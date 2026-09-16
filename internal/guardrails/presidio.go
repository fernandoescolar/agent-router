// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package guardrails

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

type presidioEvaluator struct {
	config *filterapi.PresidioGuardrailProvider
	client *http.Client
}

func newPresidioEvaluator(config *filterapi.PresidioGuardrailProvider, client *http.Client) (filterapi.GuardrailEvaluator, error) {
	if config == nil || config.Endpoint == "" {
		return nil, fmt.Errorf("presidio endpoint is required")
	}
	configCopy := *config
	if configCopy.Language == "" {
		configCopy.Language = "en"
	}
	return &presidioEvaluator{config: &configCopy, client: client}, nil
}

func (e *presidioEvaluator) Evaluate(ctx context.Context, body []byte, _ filterapi.GuardrailPhase) (bool, error) {
	payload := struct {
		Text           string   `json:"text"`
		Language       string   `json:"language"`
		ScoreThreshold *float64 `json:"score_threshold,omitempty"`
	}{Text: string(body), Language: e.config.Language}
	if e.config.ScoreThresholdPercent > 0 {
		threshold := float64(e.config.ScoreThresholdPercent) / 100
		payload.ScoreThreshold = &threshold
	}

	var result []struct {
		Score float64 `json:"score"`
	}
	if err := doJSON(ctx, e.client, http.MethodPost, strings.TrimRight(e.config.Endpoint, "/")+"/analyze", payload, func(req *http.Request) {
		if e.config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+e.config.APIKey)
		}
	}, &result); err != nil {
		return false, fmt.Errorf("presidio analyze request failed: %w", err)
	}
	return len(result) > 0, nil
}
