// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// GuardrailPolicy evaluates content safety checks for request and response payloads.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[-1:].type`
// +kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=direct"
// +kubebuilder:deprecatedversion:warning="aigateway.envoyproxy.io/v1alpha1 is deprecated; use aigateway.envoyproxy.io/v1beta1 instead"
type GuardrailPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GuardrailPolicySpec `json:"spec,omitempty"`
	// Status defines the status details of the GuardrailPolicy.
	Status GuardrailPolicyStatus `json:"status,omitempty"`
}

// GuardrailPolicySpec contains the configured checks attached to an AIServiceBackend.
type GuardrailPolicySpec struct {
	// TargetRefs are the names of the AIServiceBackend resources this GuardrailPolicy is attached to.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(ref, ref.group == 'aigateway.envoyproxy.io' && ref.kind == 'AIServiceBackend')", message="targetRefs must reference AIServiceBackend resources"
	TargetRefs []gwapiv1a2.LocalPolicyTargetReference `json:"targetRefs,omitempty"`
	// Rules are executed in order and can evaluate request or response payloads.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=32
	Rules []GuardrailRule `json:"rules,omitempty"`
}

// GuardrailRule defines one content-safety check to apply to a request or response.
type GuardrailRule struct {
	// Name is a stable identifier for the rule.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Phase determines whether the rule runs against the request or the response payload.
	//
	// +kubebuilder:validation:Enum=Request;Response
	Phase GuardrailPhase `json:"phase"`
	// Provider configures how the rule is evaluated.
	Provider GuardrailProvider `json:"provider"`
}

// GuardrailPhase determines when a guardrail runs.
type GuardrailPhase string

const (
	GuardrailPhaseRequest  GuardrailPhase = "Request"
	GuardrailPhaseResponse GuardrailPhase = "Response"
)

// GuardrailProvider describes the implementation used to evaluate a rule.
type GuardrailProvider struct {
	// Type identifies the guardrail implementation.
	//
	// +kubebuilder:validation:Enum=Regex;Presidio;Bedrock;AzureContentSafety
	Type GuardrailProviderType `json:"type"`
	// Pattern is used for deterministic regex-based evaluations.
	//
	// +optional
	Pattern string `json:"pattern,omitempty"`
	// Action is the action taken when the rule is matched.
	//
	// +optional
	// +kubebuilder:default=Block
	Action GuardrailAction `json:"action,omitempty"`
	// Message is returned to the caller when the rule blocks a request or response.
	//
	// +optional
	Message string `json:"message,omitempty"`
}

// GuardrailProviderType is the guardrail implementation.
type GuardrailProviderType string

const (
	GuardrailProviderTypeRegex              GuardrailProviderType = "Regex"
	GuardrailProviderTypePresidio           GuardrailProviderType = "Presidio"
	GuardrailProviderTypeBedrockGuardrails  GuardrailProviderType = "Bedrock"
	GuardrailProviderTypeAzureContentSafety GuardrailProviderType = "AzureContentSafety"
)

// GuardrailAction defines the safeguard action.
type GuardrailAction string

const (
	GuardrailActionBlock GuardrailAction = "Block"
)

// GuardrailPolicyList contains a list of GuardrailPolicy resources.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type GuardrailPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GuardrailPolicy `json:"items"`
}
