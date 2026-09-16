// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extproc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// guardrailViolation describes a trigger that should block the request/response.
type guardrailViolation struct {
	Name    string
	Message string
}

type guardrailFailOpenError struct {
	errors []error
}

func (e *guardrailFailOpenError) Error() string {
	return fmt.Sprintf("%d guardrail provider evaluation(s) failed open: %v", len(e.errors), errors.Join(e.errors...))
}

func isGuardrailFailOpenError(err error) bool {
	var failOpenError *guardrailFailOpenError
	return errors.As(err, &failOpenError)
}

func guardrailsConfiguredForPhase(guardrails []filterapi.RuntimeGuardrail, phase filterapi.GuardrailPhase, backendName string, includeGlobal bool) bool {
	for i := range guardrails {
		if guardrails[i].Phase == phase && guardrailAppliesToBackend(&guardrails[i], backendName, includeGlobal) {
			return true
		}
	}
	return false
}

func evaluateGuardrailsForPhase(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, phase filterapi.GuardrailPhase, body []byte, backendName string, includeGlobal bool) (*guardrailViolation, error) {
	var failOpenErrors []error
	for i := range guardrails {
		g := &guardrails[i]
		if g.Phase != phase || !guardrailAppliesToBackend(g, backendName, includeGlobal) {
			continue
		}
		var blocked bool
		if g.Provider.Type == filterapi.GuardrailProviderTypeRegex {
			if g.Matcher == nil {
				return nil, fmt.Errorf("guardrail %q uses regex provider without a compiled matcher", g.Name)
			}
			blocked = g.Matcher.Match(body)
		} else {
			if g.Evaluator == nil {
				return nil, fmt.Errorf("guardrail %q uses provider %q without an evaluator", g.Name, g.Provider.Type)
			}
			var err error
			blocked, err = g.Evaluator.Evaluate(ctx, body, phase)
			if err != nil {
				if g.Provider.FailureMode == filterapi.GuardrailFailureModeFailOpen {
					failOpenErrors = append(failOpenErrors, fmt.Errorf("guardrail %q evaluation failed: %w", g.Name, err))
					continue
				}
				return nil, fmt.Errorf("guardrail %q evaluation failed: %w", g.Name, err)
			}
		}
		if blocked {
			msg := g.Provider.Message
			if msg == "" {
				msg = fmt.Sprintf("request blocked by guardrail %q", g.Name)
			}
			return &guardrailViolation{Name: g.Name, Message: msg}, nil
		}
	}
	if len(failOpenErrors) > 0 {
		return nil, &guardrailFailOpenError{errors: failOpenErrors}
	}
	return nil, nil
}

func guardrailAppliesToBackend(guardrail *filterapi.RuntimeGuardrail, backendName string, includeGlobal bool) bool {
	if len(guardrail.Backends) == 0 {
		return includeGlobal
	}
	return backendName != "" && slices.Contains(guardrail.Backends, backendName)
}

func evaluateRequestGuardrails(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, body []byte) (*guardrailViolation, error) {
	return evaluateGuardrailsForPhase(ctx, guardrails, filterapi.GuardrailPhaseRequest, body, "", true)
}

func evaluateBackendRequestGuardrails(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, body []byte, backendName string) (*guardrailViolation, error) {
	return evaluateGuardrailsForPhase(ctx, guardrails, filterapi.GuardrailPhaseRequest, body, backendName, false)
}

func evaluateResponseGuardrails(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, body []byte, backendName string) (*guardrailViolation, error) {
	return evaluateGuardrailsForPhase(ctx, guardrails, filterapi.GuardrailPhaseResponse, body, backendName, true)
}
