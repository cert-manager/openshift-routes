/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package crcontroller

import (
	"testing"

	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_shouldReconcile(t *testing.T) {
	tests := []struct {
		name  string
		given *routev1.Route
		want  bool
	}{
		{
			name: "should reconcile with cert-manager.io/issuer-name annotation",
			given: &routev1.Route{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"cert-manager.io/issuer-name": "test",
				}},
			},
			want: true,
		},
		{
			name: "should sync with cert-manager.io/issuer annotation",
			given: &routev1.Route{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"cert-manager.io/issuer": "test",
				}},
			},
			want: true,
		},
		{
			name: "should not sync when Route owned by Ingress",
			given: &routev1.Route{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Ingress",
					},
				}},
			},
			want: false,
		},
		{
			name: "should not sync when Route owned by Ingress",
			given: &routev1.Route{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{
						Kind: "Ingress",
					},
				}},
			},
			want: false,
		},
		{
			name:  "should not sync when no annotation is found",
			given: &routev1.Route{ObjectMeta: metav1.ObjectMeta{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldSync(logr.Discard(), tt.given)
			assert.Equal(t, tt.want, got)
		})
	}
}
