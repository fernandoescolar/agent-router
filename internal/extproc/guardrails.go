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
	"sync"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// guardrailEvaluationBudget bounds the time all the guardrails of one phase may take together. Envoy waits 10s for
// each ext_proc message and then answers 504 on its own, before a FailOpen guardrail gets to let the request
// through, so the guardrails have to give up first and leave time for the rest of the processing.
var guardrailEvaluationBudget = 8 * time.Second

// maxConcurrentGuardrailEvaluations bounds the provider calls a guardrail makes at once: one per extracted text,
// which on a long conversation is one per message.
const maxConcurrentGuardrailEvaluations = 8

// guardrailViolation describes a trigger that should block the request/response.
type guardrailViolation struct {
	Name    string
	Message string
}

type guardrailOutcome struct {
	Violation *guardrailViolation
	Body      []byte
	Masked    bool
	Monitored bool
	RuleName  string
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

func guardrailsRequireBufferedResponse(guardrails []filterapi.RuntimeGuardrail, backendName string) bool {
	for i := range guardrails {
		guardrail := &guardrails[i]
		if guardrail.Phase == filterapi.GuardrailPhaseResponse &&
			guardrailAppliesToBackend(guardrail, backendName, true) {
			return true
		}
	}
	return false
}

func evaluateGuardrailsForPhase(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, phase filterapi.GuardrailPhase, body []byte, backendName string, includeGlobal bool) (guardrailOutcome, error) {
	ctx, cancel := context.WithTimeout(ctx, guardrailEvaluationBudget)
	defer cancel()
	outcome := guardrailOutcome{Body: body}
	var failOpenErrors []error
	for i := range guardrails {
		g := &guardrails[i]
		if g.Phase != phase || !guardrailAppliesToBackend(g, backendName, includeGlobal) {
			continue
		}
		maxPayloadBytes := g.MaxPayloadBytes
		if maxPayloadBytes <= 0 {
			maxPayloadBytes = 10 * 1024 * 1024
		}
		if int64(len(outcome.Body)) > maxPayloadBytes {
			err := fmt.Errorf("guardrail %q payload is %d bytes, exceeding the %d-byte limit", g.Name, len(outcome.Body), maxPayloadBytes)
			if g.Provider.FailureMode == filterapi.GuardrailFailureModeFailOpen || guardrailAction(g.Provider.Action) == filterapi.GuardrailActionMonitor {
				failOpenErrors = append(failOpenErrors, err)
				continue
			}
			return outcome, err
		}

		action := guardrailAction(g.Provider.Action)
		if g.Provider.Type == filterapi.GuardrailProviderTypeRegex && action != filterapi.GuardrailActionMask {
			if g.Matcher == nil {
				return outcome, fmt.Errorf("guardrail %q uses regex provider without a compiled matcher", g.Name)
			}
			if !g.Matcher.Match(outcome.Body) {
				continue
			}
			if action == filterapi.GuardrailActionMonitor {
				outcome.Monitored = true
				outcome.RuleName = g.Name
				continue
			}
			outcome.Violation = newGuardrailViolation(g)
			return outcome, nil
		}

		contents, err := extractGuardrailContents(outcome.Body)
		if err != nil {
			if g.Provider.FailureMode == filterapi.GuardrailFailureModeFailOpen || action == filterapi.GuardrailActionMonitor {
				failOpenErrors = append(failOpenErrors, fmt.Errorf("guardrail %q text extraction failed: %w", g.Name, err))
				continue
			}
			return outcome, fmt.Errorf("guardrail %q text extraction failed: %w", g.Name, err)
		}
		var evaluations []filterapi.GuardrailEvaluationResult
		var evaluationErrors []error
		if g.Provider.Type != filterapi.GuardrailProviderTypeRegex {
			if g.Evaluator == nil {
				return outcome, fmt.Errorf("guardrail %q uses provider %q without an evaluator", g.Name, g.Provider.Type)
			}
			evaluations, evaluationErrors = evaluateGuardrailContents(ctx, g.Evaluator, contents, phase)
		}
		for j, content := range contents {
			var evaluation filterapi.GuardrailEvaluationResult
			if g.Provider.Type == filterapi.GuardrailProviderTypeRegex {
				if g.Matcher == nil {
					return outcome, fmt.Errorf("guardrail %q uses regex provider without a compiled matcher", g.Name)
				}
				evaluation.Matched = g.Matcher.Match(content.text)
				if evaluation.Matched {
					replacement := g.Provider.MaskReplacement
					if replacement == "" {
						replacement = "[REDACTED]"
					}
					evaluation.Replacement = g.Matcher.ReplaceAll(content.text, []byte(replacement))
				}
			} else {
				evaluation, err = evaluations[j], evaluationErrors[j]
				if err != nil {
					if g.Provider.FailureMode == filterapi.GuardrailFailureModeFailOpen || action == filterapi.GuardrailActionMonitor {
						failOpenErrors = append(failOpenErrors, fmt.Errorf("guardrail %q evaluation failed: %w", g.Name, err))
						continue
					}
					return outcome, fmt.Errorf("guardrail %q evaluation failed: %w", g.Name, err)
				}
			}
			if !evaluation.Matched {
				continue
			}
			switch action {
			case filterapi.GuardrailActionMonitor:
				outcome.Monitored = true
				outcome.RuleName = g.Name
			case filterapi.GuardrailActionMask:
				if len(evaluation.Replacement) == 0 {
					return outcome, fmt.Errorf("guardrail %q matched but provider %q returned no masked content", g.Name, g.Provider.Type)
				}
				outcome.Body, err = replaceGuardrailContent(outcome.Body, content, evaluation.Replacement)
				if err != nil {
					return outcome, fmt.Errorf("guardrail %q failed to mask content: %w", g.Name, err)
				}
				outcome.Masked = true
				outcome.RuleName = g.Name
			default:
				outcome.Violation = newGuardrailViolation(g)
				return outcome, nil
			}
		}
	}
	if len(failOpenErrors) > 0 {
		return outcome, &guardrailFailOpenError{errors: failOpenErrors}
	}
	return outcome, nil
}

// evaluateGuardrailContents sends every extracted text to the provider, a few at a time, and returns the results
// in the order of contents, so a mask or a violation applies exactly as when they were evaluated one by one.
func evaluateGuardrailContents(ctx context.Context, evaluator filterapi.GuardrailEvaluator, contents []guardrailContent, phase filterapi.GuardrailPhase) ([]filterapi.GuardrailEvaluationResult, []error) {
	evaluations := make([]filterapi.GuardrailEvaluationResult, len(contents))
	errs := make([]error, len(contents))
	slots := make(chan struct{}, maxConcurrentGuardrailEvaluations)
	var wg sync.WaitGroup
	for i := range contents {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			evaluations[i], errs[i] = evaluator.Evaluate(ctx, contents[i].text, phase)
		})
	}
	wg.Wait()
	return evaluations, errs
}

func guardrailAction(action filterapi.GuardrailAction) filterapi.GuardrailAction {
	if action == "" {
		return filterapi.GuardrailActionBlock
	}
	return action
}

func newGuardrailViolation(guardrail *filterapi.RuntimeGuardrail) *guardrailViolation {
	message := guardrail.Provider.Message
	if message == "" {
		message = fmt.Sprintf("request blocked by guardrail %q", guardrail.Name)
	}
	return &guardrailViolation{Name: guardrail.Name, Message: message}
}

func guardrailAppliesToBackend(guardrail *filterapi.RuntimeGuardrail, backendName string, includeGlobal bool) bool {
	if len(guardrail.Backends) == 0 {
		return includeGlobal
	}
	return backendName != "" && slices.Contains(guardrail.Backends, backendName)
}

func evaluateRequestGuardrails(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, body []byte) (guardrailOutcome, error) {
	return evaluateGuardrailsForPhase(ctx, guardrails, filterapi.GuardrailPhaseRequest, body, "", true)
}

func evaluateBackendRequestGuardrails(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, body []byte, backendName string) (guardrailOutcome, error) {
	return evaluateGuardrailsForPhase(ctx, guardrails, filterapi.GuardrailPhaseRequest, body, backendName, false)
}

func evaluateResponseGuardrails(ctx context.Context, guardrails []filterapi.RuntimeGuardrail, body []byte, backendName string) (guardrailOutcome, error) {
	return evaluateGuardrailsForPhase(ctx, guardrails, filterapi.GuardrailPhaseResponse, body, backendName, true)
}
