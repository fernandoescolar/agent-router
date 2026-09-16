// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	aigv1b1 "github.com/envoyproxy/ai-gateway/api/v1beta1"
)

// GuardrailPolicyController implements [reconcile.TypedReconciler] for [aigv1b1.GuardrailPolicy].
type GuardrailPolicyController struct {
	client             client.Client
	kube               kubernetes.Interface
	logger             logr.Logger
	aiGatewayRouteChan chan event.GenericEvent
}

// NewGuardrailPolicyController creates a new reconciler for GuardrailPolicy resources.
func NewGuardrailPolicyController(client client.Client, kube kubernetes.Interface, logger logr.Logger, aiGatewayRouteChan chan event.GenericEvent) *GuardrailPolicyController {
	return &GuardrailPolicyController{
		client:             client,
		kube:               kube,
		logger:             logger,
		aiGatewayRouteChan: aiGatewayRouteChan,
	}
}

// Reconcile implements [reconcile.TypedReconciler] for [aigv1b1.GuardrailPolicy].
func (c *GuardrailPolicyController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var policy aigv1b1.GuardrailPolicy
	if err := c.client.Get(ctx, req.NamespacedName, &policy); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.logger.Info("Deleting GuardrailPolicy",
				"namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	c.logger.Info("Reconciling GuardrailPolicy", "namespace", req.Namespace, "name", req.Name)
	if handleFinalizer(ctx, c.client, c.logger, &policy, nil) {
		return ctrl.Result{}, nil
	}
	if len(policy.Spec.TargetRefs) == 0 {
		c.updateGuardrailPolicyStatus(ctx, &policy, aigv1b1.ConditionTypeAccepted, "GuardrailPolicy reconciled successfully")
		return ctrl.Result{}, nil
	}
	if err := c.syncGuardrailPolicy(ctx, &policy); err != nil {
		c.logger.Error(err, "failed to sync GuardrailPolicy")
		c.updateGuardrailPolicyStatus(ctx, &policy, aigv1b1.ConditionTypeNotAccepted, err.Error())
		return ctrl.Result{}, err
	}

	c.updateGuardrailPolicyStatus(ctx, &policy, aigv1b1.ConditionTypeAccepted, "GuardrailPolicy reconciled successfully")
	c.notifyAIGatewayRoutesForGuardrailPolicy(ctx, &policy)
	return ctrl.Result{}, nil
}

func (c *GuardrailPolicyController) syncGuardrailPolicy(ctx context.Context, policy *aigv1b1.GuardrailPolicy) error {
	if len(policy.Spec.TargetRefs) == 0 {
		return nil
	}

	for _, ref := range policy.Spec.TargetRefs {
		var backend aigv1b1.AIServiceBackend
		key := client.ObjectKey{Namespace: policy.Namespace, Name: string(ref.Name)}
		if err := c.client.Get(ctx, key, &backend); err != nil {
			if apierrors.IsNotFound(err) {
				c.logger.Info("AIServiceBackend not found, skipping guardrail policy target",
					"namespace", key.Namespace, "name", key.Name,
					"guardrailPolicy", policy.Name)
				continue
			}
			return fmt.Errorf("failed to get AIServiceBackend %s: %w", key, err)
		}
	}

	return nil
}

// BackendToGuardrailPolicy maps AIServiceBackend changes to GuardrailPolicy reconcile requests.
func (c *GuardrailPolicyController) BackendToGuardrailPolicy(ctx context.Context, obj client.Object) []reconcile.Request {
	var policies aigv1b1.GuardrailPolicyList
	key := fmt.Sprintf("%s.%s", obj.GetName(), obj.GetNamespace())
	if err := c.client.List(ctx, &policies,
		client.MatchingFields{k8sClientIndexAIServiceBackendToTargetingGuardrailPolicy: key}); err != nil {
		c.logger.Error(err, "failed to list GuardrailPolicies for backend", "backend", key)
		return nil
	}

	var requests []reconcile.Request
	for i := range policies.Items {
		policy := &policies.Items[i]
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(policy),
		})
	}
	return requests
}

func (c *GuardrailPolicyController) notifyAIGatewayRoutesForGuardrailPolicy(ctx context.Context, policy *aigv1b1.GuardrailPolicy) {
	for _, ref := range policy.Spec.TargetRefs {
		key := fmt.Sprintf("%s.%s", ref.Name, policy.Namespace)
		var routes aigv1b1.AIGatewayRouteList
		if err := c.client.List(ctx, &routes,
			client.MatchingFields{k8sClientIndexBackendToReferencingAIGatewayRoute: key}); err != nil {
			c.logger.Error(err, "failed to list AIGatewayRoutes for guardrail policy", "backend", key)
			continue
		}
		for i := range routes.Items {
			route := &routes.Items[i]
			c.logger.Info("notifying AIGatewayRoute of GuardrailPolicy change",
				"route", route.Name, "namespace", route.Namespace,
				"guardrailPolicy", policy.Name)
			c.aiGatewayRouteChan <- event.GenericEvent{Object: route}
		}
	}
}

func (c *GuardrailPolicyController) updateGuardrailPolicyStatus(ctx context.Context, policy *aigv1b1.GuardrailPolicy, conditionType string, message string) {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.client.Get(ctx, client.ObjectKey{Name: policy.Name, Namespace: policy.Namespace}, policy); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		policy.Status.Conditions = newConditions(conditionType, message)
		return c.client.Status().Update(ctx, policy)
	})
	if err != nil {
		c.logger.Error(err, "failed to update GuardrailPolicy status",
			"namespace", policy.Namespace, "name", policy.Name)
	}
}
