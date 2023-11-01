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
	"github.com/bufbuild/protovalidate-go/internal/errors"
	"github.com/bufbuild/protovalidate-go/internal/expression"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// evaluator defines a validation evaluator. evaluator implementations may elide
// type checking of the passed in value, as the types have been guaranteed
// during the build phase.
type evaluator interface {
	// Tautology returns true if the evaluator always succeeds.
	Tautology() bool

	// Evaluate checks that the provided val is valid. Unless failFast is true,
	// evaluation attempts to find all violations present in val instead of
	// returning an error on the first violation. The returned error will be one
	// of the following expected types:
	//
	//   - errors.ValidationError: val is invalid.
	//   - errors.RuntimeError: error evaluating val determined at runtime.
	//   - errors.CompilationError: this evaluator (or child evaluator) failed to
	//       build. This error is not recoverable.
	//
	Evaluate(val protoreflect.Value, failFast bool) error
}

// MessageEvaluator is essentially the same as evaluator, but specialized for
// messages as an optimization. See evaluator for behavior.
type MessageEvaluator interface {
	evaluator

	// EvaluateMessage checks that the provided msg is valid. See
	// evaluator.Evaluate for behavior
	EvaluateMessage(msg protoreflect.Message, failFast bool) error
}

// evaluators are a set of evaluator applied together to a value. Evaluation
// merges all errors.ValidationError violations or short-circuits if failFast is
// true or a different error is returned.
type evaluators []evaluator

func (e evaluators) Evaluate(val protoreflect.Value, failFast bool) (err error) {
	var ok bool
	for _, eval := range e {
		evalErr := eval.Evaluate(val, failFast)
		if ok, err = errors.Merge(err, evalErr, failFast); !ok {
			return err
		}
	}
	return err
}

func (e evaluators) Tautology() bool {
	for _, eval := range e {
		if !eval.Tautology() {
			return false
		}
	}
	return true
}

// messageEvaluators are a specialization of evaluators. See evaluators for
// behavior details.
type messageEvaluators []MessageEvaluator

func (m messageEvaluators) Evaluate(val protoreflect.Value, failFast bool) error {
	return m.EvaluateMessage(val.Message(), failFast)
}

func (m messageEvaluators) EvaluateMessage(msg protoreflect.Message, failFast bool) (err error) {
	var ok bool
	for _, eval := range m {
		evalErr := eval.EvaluateMessage(msg, failFast)
		if ok, err = errors.Merge(err, evalErr, failFast); !ok {
			return err
		}
	}
	return err
}

func (m messageEvaluators) Tautology() bool {
	for _, eval := range m {
		if !eval.Tautology() {
			return false
		}
	}
	return true
}

type ignoreIfEvaluator struct {
	expr expression.ProgramSet

	ifNotIgnored evaluator
}

func (i ignoreIfEvaluator) Tautology() bool {
	return false
}

func (i ignoreIfEvaluator) EvaluateMessage(msg protoreflect.Message, failFast bool) error {
	return i.Evaluate(protoreflect.ValueOfMessage(msg), failFast)
}

func (i ignoreIfEvaluator) Evaluate(val protoreflect.Value, failFast bool) error {
	return expression.BindThis(val.Message(), func(binding *expression.Variable) error {
		ignore, _, err := i.expr[0].Program.Eval(binding)
		if err != nil {
			return err
		}
		if b, ok := ignore.Value().(bool); ok {
			if !b {
				return i.ifNotIgnored.Evaluate(val, failFast)
			}
			return nil // ignore
		} else {
			return errors.NewRuntimeErrorf(
				"ignore_if expression must evaluate to a boolean, got %T",
				ignore.Value(),
			)
		}
	})
}

var (
	_ evaluator        = evaluators(nil)
	_ MessageEvaluator = messageEvaluators(nil)
)
