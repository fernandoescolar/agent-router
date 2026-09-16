// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extproc

import (
	"fmt"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// guardrailViolation describes a trigger that should block the request/response.
type guardrailViolation struct {
	Name    string
	Message string
}

func evaluateGuardrailsForPhase(guardrails []filterapi.RuntimeGuardrail, phase filterapi.GuardrailPhase, body []byte) (*guardrailViolation, error) {
	for i := range guardrails {
		g := &guardrails[i]
		if g.Phase != phase {
			continue
		}
		if g.Provider.Type == filterapi.GuardrailProviderTypeRegex {
			if g.Matcher == nil {
				return nil, fmt.Errorf("guardrail %q uses regex provider without a compiled matcher", g.Name)
			}
			if g.Matcher.Match(body) {
				msg := g.Provider.Message
				if msg == "" {
					msg = fmt.Sprintf("request blocked by guardrail %q", g.Name)
				}
				return &guardrailViolation{Name: g.Name, Message: msg}, nil
			}
		}
	}
	return nil, nil
}

func evaluateRequestGuardrails(guardrails []filterapi.RuntimeGuardrail, body []byte) (*guardrailViolation, error) {
	return evaluateGuardrailsForPhase(guardrails, filterapi.GuardrailPhaseRequest, body)
}

func evaluateResponseGuardrails(guardrails []filterapi.RuntimeGuardrail, body []byte) (*guardrailViolation, error) {
	return evaluateGuardrailsForPhase(guardrails, filterapi.GuardrailPhaseResponse, body)
}
