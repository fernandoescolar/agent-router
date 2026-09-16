// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extproc

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

func TestEvaluateGuardrailsForPhase(t *testing.T) {
	t.Run("request guardrail matches and returns violation", func(t *testing.T) {
		guardrails := []filterapi.RuntimeGuardrail{{
			Name:  "deny-pii",
			Phase: filterapi.GuardrailPhaseRequest,
			Provider: filterapi.GuardrailProvider{
				Type:    filterapi.GuardrailProviderTypeRegex,
				Message: "PII detected in request",
			},
			Matcher: regexp.MustCompile(`\bSSN\b`),
		}}

		violation, err := evaluateRequestGuardrails(guardrails, []byte("customer SSN is present"))
		require.NoError(t, err)
		require.NotNil(t, violation)
		require.Equal(t, "deny-pii", violation.Name)
		require.Equal(t, "PII detected in request", violation.Message)
	})

	t.Run("response guardrail ignores different phase", func(t *testing.T) {
		guardrails := []filterapi.RuntimeGuardrail{{
			Name:  "block-sensitive-response",
			Phase: filterapi.GuardrailPhaseResponse,
			Provider: filterapi.GuardrailProvider{
				Type: filterapi.GuardrailProviderTypeRegex,
			},
			Matcher: regexp.MustCompile(`forbidden`),
		}}

		violation, err := evaluateRequestGuardrails(guardrails, []byte("forbidden"))
		require.NoError(t, err)
		require.Nil(t, violation)
	})

	t.Run("regex guardrail without compiled matcher returns error on matching phase", func(t *testing.T) {
		guardrails := []filterapi.RuntimeGuardrail{{
			Name:  "missing-matcher",
			Phase: filterapi.GuardrailPhaseRequest,
			Provider: filterapi.GuardrailProvider{
				Type: filterapi.GuardrailProviderTypeRegex,
			},
		}}

		violation, err := evaluateRequestGuardrails(guardrails, []byte("forbidden"))
		require.Error(t, err)
		require.Nil(t, violation)
		require.Contains(t, err.Error(), "uses regex provider without a compiled matcher")
	})
}
