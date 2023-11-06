// Copyright 2023 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package evaluator

import (
	"sync"
	"sync/atomic"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"github.com/bufbuild/protovalidate-go/internal/constraints"
	"github.com/bufbuild/protovalidate-go/internal/errors"
	"github.com/bufbuild/protovalidate-go/internal/expression"
	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Builder is a build-through cache of message evaluators keyed off the provided
// descriptor.
type Builder struct {
	mtx         sync.Mutex                   // serializes cache writes.
	cache       atomic.Pointer[MessageCache] // copy-on-write cache.
	env         *cel.Env
	constraints constraints.Cache
	resolver    StandardConstraintResolver
	Load        func(desc protoreflect.MessageDescriptor) Evaluator

	coverageEnabled bool
	coverageTracker *CoverageTracker
}

type appender interface {
	Append(eval Evaluator)
}

func (b *Builder) trackAppend(
	to appender,
	eval Evaluator,
	containingDesc protoreflect.Descriptor,
	constraint protoreflect.ProtoMessage,
) {
	if !b.coverageEnabled {
		to.Append(eval)
	}
	to.Append(b.coverageTracker.addTracking(eval, containingDesc, constraint.ProtoReflect()))
}

type CoverageTracker struct {
	mu         sync.Mutex
	evaluators []*coverageEvaluator
}

func (ct *CoverageTracker) addTracking(
	eval Evaluator,
	containingDesc protoreflect.Descriptor,
	constraint protoreflect.Message,
) Evaluator {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ce := &coverageEvaluator{
		base:           eval,
		containingDesc: containingDesc,
		constraint:     constraint,
	}
	ct.evaluators = append(ct.evaluators, ce)
	return ce
}

func (ct *CoverageTracker) GenerateCoverageReport() *CoverageReport {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	report := &CoverageReport{
		AllEvaluators:      make([]EvaluatorCoverage, 0, len(ct.evaluators)),
		ByMessageName:      make(map[protoreflect.FullName][]*EvaluatorCoverage),
		ByUniqueConstraint: make(map[protoreflect.Message][]*EvaluatorCoverage),
	}
	for _, ce := range ct.evaluators {
		if ce.Tautology() {
			continue
		}
		report.AllEvaluators = append(report.AllEvaluators, EvaluatorCoverage{
			Evaluator:      ce.base,
			ContainingDesc: ce.containingDesc,
			Constraint:     ce.constraint,
			HitCount:       int(ce.hitCount.Load()),
		})
		report.ByMessageName[ce.containingDesc.FullName()] = append(
			report.ByMessageName[ce.containingDesc.FullName()],
			&report.AllEvaluators[len(report.AllEvaluators)-1],
		)
		report.ByUniqueConstraint[ce.constraint] = append(
			report.ByUniqueConstraint[ce.constraint],
			&report.AllEvaluators[len(report.AllEvaluators)-1],
		)
	}
	return report
}

type CoverageReport struct {
	AllEvaluators []EvaluatorCoverage
	// Coverage reports that would be evaluated for each top-level message.
	// Nested messages containing evaluators will be duplicated in each
	// top-level message that contains them, whether directly or indirectly.
	ByMessageName map[protoreflect.FullName][]*EvaluatorCoverage
	// Coverage reports by constraint message instance (where the constraint was
	// used in an option).
	ByUniqueConstraint map[protoreflect.Message][]*EvaluatorCoverage
}

type EvaluatorCoverage struct {
	Evaluator      Evaluator
	ContainingDesc protoreflect.Descriptor
	Constraint     protoreflect.Message
	HitCount       int
}

type StandardConstraintResolver interface {
	ResolveMessageConstraints(desc protoreflect.MessageDescriptor) *validate.MessageConstraints
	ResolveOneofConstraints(desc protoreflect.OneofDescriptor) *validate.OneofConstraints
	ResolveFieldConstraints(desc protoreflect.FieldDescriptor) *validate.FieldConstraints
}

type builderOptions struct {
	enableCoverageTracking bool
	disableLazy            bool
	seedDescs              []protoreflect.MessageDescriptor
}

type BuilderOption func(*builderOptions)

func WithCoverageTracking(enable bool) BuilderOption {
	return func(o *builderOptions) {
		o.enableCoverageTracking = enable
	}
}

func WithDisableLazy(disable bool) BuilderOption {
	return func(o *builderOptions) {
		o.disableLazy = disable
	}
}

func WithSeedDescriptors(descs ...protoreflect.MessageDescriptor) BuilderOption {
	return func(o *builderOptions) {
		o.seedDescs = append(o.seedDescs, descs...)
	}
}

// NewBuilder initializes a new Builder.
func NewBuilder(
	env *cel.Env,
	res StandardConstraintResolver,
	opts ...BuilderOption,
) *Builder {
	var options builderOptions
	for _, opt := range opts {
		opt(&options)
	}

	bldr := &Builder{
		env:             env,
		constraints:     constraints.NewCache(),
		resolver:        res,
		coverageTracker: &CoverageTracker{},
		coverageEnabled: options.enableCoverageTracking,
	}

	if options.disableLazy {
		bldr.Load = bldr.load
	} else {
		bldr.Load = bldr.loadOrBuild
	}

	cache := make(MessageCache, len(options.seedDescs))
	for _, desc := range options.seedDescs {
		bldr.build(desc, cache)
	}
	bldr.cache.Store(&cache)
	return bldr
}

// load returns a pre-cached MessageEvaluator for the given descriptor or, if
// the descriptor is unknown, returns an evaluator that always resolves to a
// errors.CompilationError.
func (bldr *Builder) load(desc protoreflect.MessageDescriptor) Evaluator {
	if eval, ok := (*bldr.cache.Load())[desc]; ok {
		return eval
	}
	return unknownMessage{desc: desc}
}

// loadOrBuild either returns a memoized MessageEvaluator for the given
// descriptor, or lazily constructs a new one. This method is thread-safe via
// locking.
func (bldr *Builder) loadOrBuild(desc protoreflect.MessageDescriptor) Evaluator {
	if eval, ok := (*bldr.cache.Load())[desc]; ok {
		return eval
	}
	bldr.mtx.Lock()
	defer bldr.mtx.Unlock()
	cache := *bldr.cache.Load()
	if eval, ok := cache[desc]; ok {
		return eval
	}
	newCache := cache.Clone()
	msgEval := bldr.build(desc, newCache)
	bldr.cache.Store(&newCache)
	return msgEval
}

func (bldr *Builder) build(
	desc protoreflect.MessageDescriptor,
	cache MessageCache,
) *message {
	if eval, ok := cache[desc]; ok {
		return eval
	}
	msgEval := &message{}
	cache[desc] = msgEval
	bldr.buildMessage(desc, msgEval, cache)
	return msgEval
}

func (bldr *Builder) buildMessage(
	desc protoreflect.MessageDescriptor, msgEval *message,
	cache MessageCache,
) {
	msgConstraints := bldr.resolver.ResolveMessageConstraints(desc)
	if msgConstraints.GetDisabled() {
		return
	}

	steps := []func(
		desc protoreflect.MessageDescriptor,
		msgConstraints *validate.MessageConstraints,
		msg *message,
		cache MessageCache,
	){
		bldr.processMessageExpressions,
		bldr.processOneofConstraints,
		bldr.processFields,
	}

	for _, step := range steps {
		if step(desc, msgConstraints, msgEval, cache); msgEval.Err != nil {
			break
		}
	}
}

func (bldr *Builder) processMessageExpressions(
	desc protoreflect.MessageDescriptor,
	msgConstraints *validate.MessageConstraints,
	msgEval *message,
	_ MessageCache,
) {
	compiledExprs, err := expression.Compile(
		msgConstraints.GetCel(),
		bldr.env,
		cel.Types(dynamicpb.NewMessage(desc)),
		cel.Variable("this", cel.ObjectType(string(desc.FullName()))),
	)
	if err != nil {
		msgEval.Err = err
		return
	}

	bldr.trackAppend(msgEval, celPrograms(compiledExprs), desc, msgConstraints)
}

func (bldr *Builder) processOneofConstraints(
	desc protoreflect.MessageDescriptor,
	_ *validate.MessageConstraints,
	msgEval *message,
	_ MessageCache,
) {
	oneofs := desc.Oneofs()
	for i := 0; i < oneofs.Len(); i++ {
		oneofDesc := oneofs.Get(i)
		oneofConstraints := bldr.resolver.ResolveOneofConstraints(oneofDesc)
		oneofEval := oneof{
			Descriptor: oneofDesc,
			Required:   oneofConstraints.GetRequired(),
		}
		msgEval.Append(oneofEval)
		// 		bldr.trackAppend(msgEval, oneofEval, desc, oneofConstraints)
	}
}

func (bldr *Builder) processFields(
	desc protoreflect.MessageDescriptor,
	msgConstraints *validate.MessageConstraints,
	msgEval *message,
	cache MessageCache,
) {
	fields := desc.Fields()
	for i := 0; i < fields.Len(); i++ {
		fdesc := fields.Get(i)
		fieldConstraints := bldr.resolver.ResolveFieldConstraints(fdesc)
		fldEval, err := bldr.buildField(fdesc, fieldConstraints, cache)
		if err != nil {
			msgEval.Err = err
			return
		}
		if ii := fieldConstraints.GetIgnoreIf(); ii != nil {
			compiledExpr, err := expression.Compile(
				[]*validate.Constraint{ii},
				bldr.env,
				cel.Types(dynamicpb.NewMessage(desc)),
				cel.Variable("this", cel.ObjectType(string(desc.FullName()))),
			)

			if err != nil {
				msgEval.Err = err
				return
			}
			msgEval.Append(ignoreIfEvaluator{
				expr:         compiledExpr,
				ifNotIgnored: fldEval,
			})
			// bldr.trackAppend(msgEval, ignoreIfEvaluator{
			// 	expr:         compiledExpr,
			// 	ifNotIgnored: fldEval,
			// }, desc, ii)
		} else {
			msgEval.Append(fldEval)
			// bldr.trackAppend(msgEval, fldEval, fdesc, fieldConstraints)
		}
	}
}

func (bldr *Builder) buildField(
	fieldDescriptor protoreflect.FieldDescriptor,
	fieldConstraints *validate.FieldConstraints,
	cache MessageCache,
) (field, error) {
	fld := field{
		Descriptor: fieldDescriptor,
		Required:   fieldConstraints.GetRequired(),
		Optional:   fieldDescriptor.HasPresence(),
	}
	err := bldr.buildValue(fieldDescriptor, fieldConstraints, false, &fld.Value, cache)
	return fld, err
}

func (bldr *Builder) buildValue(
	fdesc protoreflect.FieldDescriptor,
	constraints *validate.FieldConstraints,
	forItems bool,
	valEval *value,
	cache MessageCache,
) (err error) {
	valEval.IgnoreEmpty = constraints.GetIgnoreEmpty()
	steps := []func(
		fdesc protoreflect.FieldDescriptor,
		fieldConstraints *validate.FieldConstraints,
		forItems bool,
		valEval *value,
		cache MessageCache,
	) error{
		bldr.processZeroValue,
		bldr.processFieldExpressions,
		bldr.processEmbeddedMessage,
		bldr.processWrapperConstraints,
		bldr.processStandardConstraints,
		bldr.processAnyConstraints,
		bldr.processEnumConstraints,
		bldr.processMapConstraints,
		bldr.processRepeatedConstraints,
	}

	for _, step := range steps {
		if err = step(fdesc, constraints, forItems, valEval, cache); err != nil {
			return err
		}
	}
	return nil
}

func (bldr *Builder) processZeroValue(
	fdesc protoreflect.FieldDescriptor,
	_ *validate.FieldConstraints,
	forItems bool,
	val *value,
	_ MessageCache,
) error {
	switch fdesc.Kind() {
	case protoreflect.MessageKind:
		// For messages, the zero value needs to be a non-nil empty message.
		// Default() will return a nil Value, which is never equal to anything.
		val.Zero = protoreflect.ValueOfMessage(dynamicpb.NewMessage(fdesc.Message()).Type().New())
	default:
		val.Zero = fdesc.Default()
	}
	if forItems && fdesc.IsList() {
		msg := dynamicpb.NewMessage(fdesc.ContainingMessage())
		val.Zero = msg.Get(fdesc).List().NewElement()
	}
	return nil
}

func (bldr *Builder) processFieldExpressions(
	fieldDesc protoreflect.FieldDescriptor,
	fieldConstraints *validate.FieldConstraints,
	_ bool,
	eval *value,
	_ MessageCache,
) error {
	exprs := fieldConstraints.GetCel()
	if len(exprs) == 0 {
		return nil
	}
	var opts []cel.EnvOption
	if fieldDesc.Kind() == protoreflect.MessageKind {
		opts = []cel.EnvOption{
			cel.Types(dynamicpb.NewMessage(fieldDesc.ContainingMessage())),
			cel.Types(dynamicpb.NewMessage(fieldDesc.Message())),
			cel.Variable("this", cel.ObjectType(string(fieldDesc.Message().FullName()))),
		}
	} else {
		opts = []cel.EnvOption{
			cel.Variable("this", constraints.ProtoKindToCELType(fieldDesc.Kind())),
		}
	}
	compiledExpressions, err := expression.Compile(exprs, bldr.env, opts...)
	if err != nil {
		return err
	}
	if len(compiledExpressions) > 0 {
		bldr.trackAppend(eval, celPrograms(compiledExpressions), fieldDesc, fieldConstraints)
	}
	return nil
}

func (bldr *Builder) processEmbeddedMessage(
	fdesc protoreflect.FieldDescriptor,
	rules *validate.FieldConstraints,
	forItems bool,
	valEval *value,
	cache MessageCache,
) error {
	if fdesc.Kind() != protoreflect.MessageKind ||
		rules.GetSkipped() ||
		fdesc.IsMap() || (fdesc.IsList() && !forItems) {
		return nil
	}

	embedEval := bldr.build(fdesc.Message(), cache)
	if err := embedEval.Err; err != nil {
		return errors.NewCompilationErrorf(
			"failed to compile embedded type %s for %s: %w",
			fdesc.Message().FullName(), fdesc.FullName(), err)
	}
	bldr.trackAppend(valEval, embedEval, fdesc.ContainingMessage(), rules)

	return nil
}

func (bldr *Builder) processWrapperConstraints(
	fdesc protoreflect.FieldDescriptor,
	rules *validate.FieldConstraints,
	forItems bool,
	valEval *value,
	cache MessageCache,
) error {
	if fdesc.Kind() != protoreflect.MessageKind ||
		rules.GetSkipped() ||
		fdesc.IsMap() || (fdesc.IsList() && !forItems) {
		return nil
	}

	expectedWrapperDescriptor, ok := constraints.ExpectedWrapperConstraints(fdesc.Message().FullName())
	if !ok || !rules.ProtoReflect().Has(expectedWrapperDescriptor) {
		return nil
	}
	var unwrapped value
	err := bldr.buildValue(fdesc.Message().Fields().ByName("value"), rules, true, &unwrapped, cache)
	if err != nil {
		return err
	}
	bldr.trackAppend(valEval, unwrapped.Constraints, fdesc, rules)
	return nil
}

func (bldr *Builder) processStandardConstraints(
	fdesc protoreflect.FieldDescriptor,
	constraints *validate.FieldConstraints,
	forItems bool,
	valEval *value,
	_ MessageCache,
) error {
	stdConstraints, err := bldr.constraints.Build(
		bldr.env,
		fdesc,
		constraints,
		forItems,
	)
	if err != nil {
		return err
	}
	bldr.trackAppend(valEval, celPrograms(stdConstraints), fdesc, constraints)
	return nil
}

func (bldr *Builder) processAnyConstraints(
	fdesc protoreflect.FieldDescriptor,
	fieldConstraints *validate.FieldConstraints,
	forItems bool,
	valEval *value,
	_ MessageCache,
) error {
	if (fdesc.IsList() && !forItems) ||
		fdesc.Kind() != protoreflect.MessageKind ||
		fdesc.Message().FullName() != "google.protobuf.Any" {
		return nil
	}

	typeURLDesc := fdesc.Message().Fields().ByName("type_url")
	anyEval := anyPB{
		TypeURLDescriptor: typeURLDesc,
		In:                stringsToSet(fieldConstraints.GetAny().GetIn()),
		NotIn:             stringsToSet(fieldConstraints.GetAny().GetNotIn()),
	}
	bldr.trackAppend(valEval, anyEval, fdesc, fieldConstraints)
	return nil
}

func (bldr *Builder) processEnumConstraints(
	fdesc protoreflect.FieldDescriptor,
	fieldConstraints *validate.FieldConstraints,
	_ bool,
	valEval *value,
	_ MessageCache,
) error {
	if fdesc.Kind() != protoreflect.EnumKind {
		return nil
	}
	if fieldConstraints.GetEnum().GetDefinedOnly() {
		bldr.trackAppend(valEval, definedEnum{
			ValueDescriptors: fdesc.Enum().Values(),
		}, fdesc.Enum(), fieldConstraints)
	}
	return nil
}

func (bldr *Builder) processMapConstraints(
	fieldDesc protoreflect.FieldDescriptor,
	constraints *validate.FieldConstraints,
	_ bool,
	valEval *value,
	cache MessageCache,
) error {
	if !fieldDesc.IsMap() {
		return nil
	}

	var mapEval kvPairs

	err := bldr.buildValue(
		fieldDesc.MapKey(),
		constraints.GetMap().GetKeys(),
		true,
		&mapEval.KeyConstraints,
		cache)
	if err != nil {
		return errors.NewCompilationErrorf(
			"failed to compile key constraints for map %s: %w",
			fieldDesc.FullName(), err)
	}

	err = bldr.buildValue(
		fieldDesc.MapValue(),
		constraints.GetMap().GetValues(),
		true,
		&mapEval.ValueConstraints,
		cache)
	if err != nil {
		return errors.NewCompilationErrorf(
			"failed to compile value constraints for map %s: %w",
			fieldDesc.FullName(), err)
	}

	bldr.trackAppend(valEval, mapEval, fieldDesc, constraints)
	return nil
}

func (bldr *Builder) processRepeatedConstraints(
	fdesc protoreflect.FieldDescriptor,
	fieldConstraints *validate.FieldConstraints,
	forItems bool,
	valEval *value,
	cache MessageCache,
) error {
	if !fdesc.IsList() || forItems {
		return nil
	}

	var listEval listItems
	err := bldr.buildValue(fdesc, fieldConstraints.GetRepeated().GetItems(), true, &listEval.ItemConstraints, cache)
	if err != nil {
		return errors.NewCompilationErrorf(
			"failed to compile items constraints for repeated %v: %w", fdesc.FullName(), err)
	}

	bldr.trackAppend(valEval, listEval, fdesc, fieldConstraints)
	return nil
}

func (bldr *Builder) GenerateCoverageReport() (*CoverageReport, error) {
	if !bldr.coverageEnabled {
		return nil, errors.NewRuntimeErrorf("coverage tracking not enabled")
	}
	return bldr.coverageTracker.GenerateCoverageReport(), nil
}

type MessageCache map[protoreflect.MessageDescriptor]*message

func (c MessageCache) Clone() MessageCache {
	newCache := make(MessageCache, len(c)+1)
	c.SyncTo(newCache)
	return newCache
}
func (c MessageCache) SyncTo(other MessageCache) {
	for k, v := range c {
		other[k] = v
	}
}
