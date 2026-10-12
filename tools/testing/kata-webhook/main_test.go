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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
)

func TestAnnotatePodMutator(t *testing.T) {
	tests := []struct {
		name         string
		nsBlacklist  map[string]bool
		nsOnlyRegexp *regexp.Regexp
		wantMutated  bool
	}{
		{"no filters", nil, nil, true},
		{"matching nsBlacklist", map[string]bool{"testing-namespace": true}, nil, false},
		{"matching nsOnlyRegexp", nil, regexp.MustCompile("^testing-.*$"), true},
		{"nonmatching nsOnlyRegexp", nil, regexp.MustCompile(".*nonexisting.*"), false},
	}

	expectedRuntimeClass := "kata"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			whPolicy = &policy{nsBlacklist: tt.nsBlacklist, nsOnlyRegexp: tt.nsOnlyRegexp}

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "testing-namespace",
				},
			}

			ar := &kwhmodel.AdmissionReview{
				Namespace: "testing-namespace",
			}

			result, err := annotatePodMutator(context.Background(), ar, pod)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			mutated := result.MutatedObject != nil && result.MutatedObject.(*corev1.Pod).Spec.RuntimeClassName != nil
			if mutated != tt.wantMutated {
				t.Errorf("expected mutation: %v, got: %v", tt.wantMutated, mutated)
			}
			if mutated && *result.MutatedObject.(*corev1.Pod).Spec.RuntimeClassName != expectedRuntimeClass {
				t.Errorf("expected runtimeclass: %v, got %v", expectedRuntimeClass, result.MutatedObject.(*corev1.Pod).Spec.RuntimeClassName)
			}
		})
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
