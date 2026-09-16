// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extproc

import (
	"context"
	"log/slog"
	"regexp"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/endpointspec"
	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/metrics"
	"github.com/envoyproxy/ai-gateway/internal/tracing/tracingapi"
)

type recordingGuardrailMetrics struct {
	phase  string
	result metrics.GuardrailResult
	count  int
}

func (m *recordingGuardrailMetrics) RecordEvaluation(_ context.Context, phase string, result metrics.GuardrailResult) {
	m.phase = phase
	m.result = result
	m.count++
}

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

func TestRequestGuardrailBlockRecordsMetric(t *testing.T) {
	recorder := &recordingGuardrailMetrics{}
	config := &filterapi.RuntimeConfig{
		Guardrails: []filterapi.RuntimeGuardrail{{
			Name:  "deny-pii",
			Phase: filterapi.GuardrailPhaseRequest,
			Provider: filterapi.GuardrailProvider{
				Type: filterapi.GuardrailProviderTypeRegex,
			},
			Matcher: regexp.MustCompile(`SSN`),
		}},
	}
	factory := NewFactory(nil, recorder, tracingapi.NoopChatCompletionTracer{}, endpointspec.ChatCompletionsEndpointSpec{})
	processor, err := factory(config, map[string]string{
		"content-type": "application/json",
		":path":        "/v1/chat/completions",
	}, slog.Default(), false, false)
	require.NoError(t, err)

	response, err := processor.ProcessRequestBody(t.Context(), &extprocv3.HttpBody{
		Body: []byte(`{"model":"test","messages":[{"role":"user","content":"customer SSN"}]}`),
	})
	require.NoError(t, err)
	require.NotNil(t, response.GetImmediateResponse())
	require.Equal(t, 1, recorder.count)
	require.Equal(t, string(filterapi.GuardrailPhaseRequest), recorder.phase)
	require.Equal(t, metrics.GuardrailResultBlocked, recorder.result)
}

func TestRecordGuardrailEvaluationIgnoresUnconfiguredPhase(t *testing.T) {
	recorder := &recordingGuardrailMetrics{}
	processor := &chatCompletionProcessorRouterFilter{
		config: &filterapi.RuntimeConfig{Guardrails: []filterapi.RuntimeGuardrail{{
			Phase: filterapi.GuardrailPhaseResponse,
		}}},
		guardrailMetrics: recorder,
	}

	processor.recordGuardrailEvaluation(t.Context(), filterapi.GuardrailPhaseRequest, metrics.GuardrailResultAllowed)
	require.Zero(t, recorder.count)
}
