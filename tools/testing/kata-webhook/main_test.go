// Copyright (c) 2025 Red Hat Inc.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
)

func TestAnnotatePodMutator(t *testing.T) {
	tests := []struct {
		name                    string
		nsBlacklist             map[string]bool
		nsOnlyRegexp            *regexp.Regexp
		minMemory               *string
		container               corev1.Container
		initContainer           corev1.Container
		wantMutatedRuntimeClass bool
		wantErr                 bool
		wantLimit               string
		wantInitLimit           string
	}{
		{
			name:                    "no filters",
			nsBlacklist:             nil,
			nsOnlyRegexp:            nil,
			wantMutatedRuntimeClass: true,
		},
		{
			name:                    "matching nsBlacklist",
			nsBlacklist:             map[string]bool{"testing-namespace": true},
			nsOnlyRegexp:            nil,
			wantMutatedRuntimeClass: false,
		},
		{
			name:                    "matching nsOnlyRegexp",
			nsBlacklist:             nil,
			nsOnlyRegexp:            regexp.MustCompile("^testing-.*$"),
			wantMutatedRuntimeClass: true,
		},
		{
			name:                    "nonmatching nsOnlyRegexp",
			nsBlacklist:             nil,
			nsOnlyRegexp:            regexp.MustCompile(".*nonexisting.*"),
			wantMutatedRuntimeClass: false,
		},
		{
			name:                    "limit below minimum is raised",
			minMemory:               ptr("256Mi"),
			container:               memLimitContainer("128Mi"),
			initContainer:           memLimitContainer("128Mi"),
			wantMutatedRuntimeClass: true,
			wantLimit:               "256Mi",
			wantInitLimit:           "256Mi",
		},
		{
			name:                    "limit equal to minimum is kept",
			minMemory:               ptr("256Mi"),
			container:               memLimitContainer("256Mi"),
			initContainer:           memLimitContainer("256Mi"),
			wantMutatedRuntimeClass: true,
			wantLimit:               "256Mi",
			wantInitLimit:           "256Mi",
		},
		{
			name:                    "limit above minimum is kept",
			minMemory:               ptr("256Mi"),
			container:               memLimitContainer("512Mi"),
			initContainer:           memLimitContainer("512Mi"),
			wantMutatedRuntimeClass: true,
			wantLimit:               "512Mi",
			wantInitLimit:           "512Mi",
		},
		{
			name:                    "byte notation below minimum is raised",
			minMemory:               ptr("256Mi"),
			container:               memLimitContainer("268435455"),
			wantMutatedRuntimeClass: true,
			wantLimit:               "256Mi",
		},
		{
			name:                    "byte notation equal to minimum keeps its notation",
			minMemory:               ptr("256Mi"),
			container:               memLimitContainer("268435456"),
			wantMutatedRuntimeClass: true,
			wantLimit:               "268435456",
		},
		{
			name:      "container without a memory limit stays unlimited",
			minMemory: ptr("256Mi"),
			container: corev1.Container{
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("1"),
				}},
			},
			wantMutatedRuntimeClass: true,
			wantLimit:               "",
		},
		{
			name:      "empty min memory returns error",
			minMemory: ptr(""),
			wantErr:   true,
		},
		{
			name:      "malformed min memory returns error",
			minMemory: ptr("not-a-quantity"),
			wantErr:   true,
		},
		{
			name:      "zero min memory returns error",
			minMemory: ptr("0"),
			wantErr:   true,
		},
		{
			name:      "negative min memory returns error",
			minMemory: ptr("-1Mi"),
			wantErr:   true,
		},
	}

	expectedRuntimeClass := "kata"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whPolicy = &policy{nsBlacklist: tt.nsBlacklist, nsOnlyRegexp: tt.nsOnlyRegexp}

			if tt.minMemory != nil {
				t.Setenv(minMemoryLimitEnvKey, *tt.minMemory)
			}

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "testing-namespace",
				},
				Spec: corev1.PodSpec{
					Containers:     []corev1.Container{tt.container},
					InitContainers: []corev1.Container{tt.initContainer},
				},
			}

			ar := &kwhmodel.AdmissionReview{
				Namespace: "testing-namespace",
			}

			result, err := annotatePodMutator(context.Background(), ar, pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, err)
			} else if err == nil {
				mutatedRuntimeClass := result.MutatedObject != nil && result.MutatedObject.(*corev1.Pod).Spec.RuntimeClassName != nil
				if mutatedRuntimeClass != tt.wantMutatedRuntimeClass {
					t.Errorf("expected mutation: %v, got: %v", tt.wantMutatedRuntimeClass, mutatedRuntimeClass)
				}
				if mutatedRuntimeClass && *result.MutatedObject.(*corev1.Pod).Spec.RuntimeClassName != expectedRuntimeClass {
					t.Errorf("expected runtimeclass: %v, got %v", expectedRuntimeClass, result.MutatedObject.(*corev1.Pod).Spec.RuntimeClassName)
				}
			}

			assertMemoryLimit(t, pod.Spec.Containers[0].Resources.Limits, tt.wantLimit)
			assertMemoryLimit(t, pod.Spec.InitContainers[0].Resources.Limits, tt.wantInitLimit)
		})
	}
}

func ptr[T any](v T) *T {
	return &v
}

func memLimitContainer(memory string) corev1.Container {
	return corev1.Container{
		Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse(memory),
		}},
	}
}

func assertMemoryLimit(t *testing.T, limits corev1.ResourceList, want string) {
	t.Helper()

	got, ok := limits[corev1.ResourceMemory]
	if ok {
		if want == "" {
			t.Errorf("expected no memory limit, got %s", got.String())
		} else if got.String() != want {
			t.Errorf("expected memory limit %s, got %s", want, got.String())
		}
	} else if want != "" {
		t.Errorf("expected memory limit %s, got none", want)
	}
}

func TestGenpolicyInput(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "web-"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:    "c",
			EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{}}},
			Env: []corev1.EnvVar{
				{Name: "PLAIN", Value: "v"},
				{Name: "CM", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "k"}}},
				{Name: "SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "k"}}},
				{Name: "NODE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
			},
		}}},
	}

	out, err := genpolicyInput(pod, "ns")
	if err != nil {
		t.Fatal(err)
	}
	var got corev1.Pod
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got.Kind != "Pod" || got.APIVersion != "v1" || got.Namespace != "ns" {
		t.Errorf("unexpected type/namespace: %q %q %q", got.Kind, got.APIVersion, got.Namespace)
	}
	c := got.Spec.Containers[0]
	if c.EnvFrom != nil || len(c.Env) != 2 || c.Env[0].Name != "PLAIN" || c.Env[1].Name != "NODE" {
		t.Errorf("unexpected env: %+v %+v", c.EnvFrom, c.Env)
	}
	if len(pod.Spec.Containers[0].Env) != 4 || pod.Spec.Containers[0].EnvFrom == nil {
		t.Errorf("input pod was modified")
	}
}

func fakeGenpolicy(t *testing.T, script string, timeout time.Duration) *genpolicyConfig {
	dir := t.TempDir()
	bin := filepath.Join(dir, "genpolicy")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &genpolicyConfig{binary: bin, cacheFile: filepath.Join(dir, "cache.json"), timeout: timeout}
}

func TestAddPolicy(t *testing.T) {
	tests := []struct {
		name         string
		script       string
		wantStatus   string
		wantInitdata string
	}{
		{"ok", "cat >/dev/null; echo H4sIinitdata", "ok", "H4sIinitdata"},
		{"failed", "echo boom >&2; exit 101", "failed", ""},
		{"empty output", "true", "failed", ""},
		{"timeout", "sleep 2", "timeout", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fakeGenpolicy(t, tt.script, 500*time.Millisecond)
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
			addPolicy(cfg, pod, "ns")

			if got := pod.Annotations[genpolicyStatusAnnotation]; got != tt.wantStatus {
				t.Errorf("status: want %q, got %q", tt.wantStatus, got)
			}
			if got := pod.Annotations[initdataAnnotation]; got != tt.wantInitdata {
				t.Errorf("initdata: want %q, got %q", tt.wantInitdata, got)
			}
		})
	}
	// Let the timed-out run release the slot.
	genpolicySlot <- struct{}{}
	<-genpolicySlot
}

func TestAddPolicyKeepsUserPolicy(t *testing.T) {
	cfg := fakeGenpolicy(t, "exit 1", time.Second)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{initdataAnnotation: "mine"}}}
	addPolicy(cfg, pod, "ns")
	if pod.Annotations[initdataAnnotation] != "mine" || pod.Annotations[genpolicyStatusAnnotation] != "user-provided" {
		t.Errorf("unexpected annotations: %v", pod.Annotations)
	}
}
