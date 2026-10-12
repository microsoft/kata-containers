// Copyright (c) 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhmutating "github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
)

const minMemoryLimitEnvKey = "MIN_MEMORY_LIMIT"

const (
	initdataAnnotation        = "io.katacontainers.config.hypervisor.cc_init_data"
	genpolicyStatusAnnotation = "kata-webhook/genpolicy"
	webhookAppLabel           = "pod-annotate-webhook"
)

var errGenpolicyTimeout = errors.New("timeout")

type genpolicyConfig struct {
	binary    string
	settings  string
	rules     string
	cacheFile string
	timeout   time.Duration
}

// nil disables policy generation.
var genpolicyCfg *genpolicyConfig

// genpolicy runs one at a time: concurrent runs would race on the layers cache file.
var genpolicySlot = make(chan struct{}, 1)

func getRuntimeClass(runtimeClassKey, defaultRuntimeClass string) string {
	if runtimeClass, ok := os.LookupEnv(runtimeClassKey); ok {
		return runtimeClass
	}
	return defaultRuntimeClass
}

func getMinMemoryLimit(minMemoryLimitKey string) (*resource.Quantity, error) {
	value, ok := os.LookupEnv(minMemoryLimitKey)
	if !ok {
		return nil, nil
	}

	minMemoryLimit, err := resource.ParseQuantity(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", minMemoryLimitKey, value, err)
	}
	if minMemoryLimit.Sign() <= 0 {
		return nil, fmt.Errorf("invalid %s %q: must be greater than zero", minMemoryLimitKey, value)
	}

	return &minMemoryLimit, nil
}

func enforceMinMemoryLimit(containers []corev1.Container, minimum resource.Quantity) {
	for i := range containers {
		currentMemoryLimit, ok := containers[i].Resources.Limits[corev1.ResourceMemory]
		if !ok || currentMemoryLimit.Cmp(minimum) >= 0 {
			continue
		}

		containers[i].Resources.Limits[corev1.ResourceMemory] = minimum
		fmt.Println("memory limit too low. Updating to: ", containers[i].Resources.Limits)
	}
}

// genpolicy panics on ConfigMap/Secret references it can't resolve; the
// webhook settings allow any env var instead of looking them up.
func dropConfigEnvRefs(containers []corev1.Container) {
	for i := range containers {
		containers[i].EnvFrom = nil
		env := containers[i].Env[:0]
		for _, e := range containers[i].Env {
			if e.ValueFrom != nil && (e.ValueFrom.ConfigMapKeyRef != nil || e.ValueFrom.SecretKeyRef != nil) {
				continue
			}
			env = append(env, e)
		}
		containers[i].Env = env
	}
}

func genpolicyInput(pod *corev1.Pod, namespace string) ([]byte, error) {
	p := pod.DeepCopy()
	p.APIVersion = "v1"
	p.Kind = "Pod"
	if p.Namespace == "" {
		p.Namespace = namespace
	}
	p.ManagedFields = nil
	p.Status = corev1.PodStatus{}
	dropConfigEnvRefs(p.Spec.InitContainers)
	dropConfigEnvRefs(p.Spec.Containers)
	// genpolicy reads YAML, and JSON is valid YAML.
	return json.Marshal(p)
}

// runGenpolicy returns the cc_init_data annotation value for the pod.
func runGenpolicy(cfg *genpolicyConfig, input []byte) (string, error) {
	timer := time.NewTimer(cfg.timeout)
	defer timer.Stop()

	select {
	case genpolicySlot <- struct{}{}:
	case <-timer.C:
		return "", errGenpolicyTimeout
	}

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-genpolicySlot }()
		cmd := exec.Command(cfg.binary,
			"--base64-out",
			"--silent-unsupported-fields",
			"--json-settings-path", cfg.settings,
			"--rego-rules-path", cfg.rules,
			"--layers-cache-file-path="+cfg.cacheFile)
		// genpolicy creates temporary directories in its working directory.
		cmd.Dir = filepath.Dir(cfg.cacheFile)
		cmd.Stdin = bytes.NewReader(input)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			msg := stderr.String()
			if len(msg) > 1024 {
				msg = msg[len(msg)-1024:]
			}
			err = fmt.Errorf("%w: %s", err, msg)
		}
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return "", r.err
		}
		initdata := strings.TrimSpace(string(r.out))
		if initdata == "" {
			return "", errors.New("genpolicy printed no initdata")
		}
		return initdata, nil
	case <-timer.C:
		// Leave genpolicy running so it saves the image layers to the cache for the next pod.
		return "", errGenpolicyTimeout
	}
}

// addPolicy never rejects the pod: on failure it runs without a generated policy,
// marked by the status annotation.
func addPolicy(cfg *genpolicyConfig, pod *corev1.Pod, namespace string) {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	if _, ok := pod.Annotations[initdataAnnotation]; ok {
		pod.Annotations[genpolicyStatusAnnotation] = "user-provided"
		return
	}

	start := time.Now()
	initdata, err := func() (string, error) {
		input, err := genpolicyInput(pod, namespace)
		if err != nil {
			return "", err
		}
		return runGenpolicy(cfg, input)
	}()
	elapsed := time.Since(start).Round(time.Millisecond)

	switch {
	case errors.Is(err, errGenpolicyTimeout):
		fmt.Println("genpolicy timeout: ", namespace, pod.GetName(), pod.GetGenerateName(), elapsed)
		pod.Annotations[genpolicyStatusAnnotation] = "timeout"
	case err != nil:
		fmt.Println("genpolicy failed: ", namespace, pod.GetName(), pod.GetGenerateName(), elapsed, err)
		pod.Annotations[genpolicyStatusAnnotation] = "failed"
	default:
		fmt.Println("genpolicy ok: ", namespace, pod.GetName(), pod.GetGenerateName(), elapsed, len(initdata))
		pod.Annotations[initdataAnnotation] = initdata
		pod.Annotations[genpolicyStatusAnnotation] = "ok"
	}
}

func annotatePodMutator(_ context.Context, ar *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhmutating.MutatorResult, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// If not a pod just continue the mutation chain (if there is one) and don't do anything
		return &kwhmutating.MutatorResult{}, nil
	}

	// The Namespace is not always available in the pod Spec
	// specially when operators create the pods. Hence access
	// the Namespace in the actual request (vs the object)
	// https://godoc.org/k8s.io/api/admission/v1beta1#AdmissionRequest
	if whPolicy.nsBlacklist[ar.Namespace] {
		fmt.Println("blacklisted namespace: ", ar.Namespace)
		return &kwhmutating.MutatorResult{}, nil
	}
	// Check if we are only mutating pods in specific namespaces using the regular expression.
	if whPolicy.nsOnlyRegexp != nil && !whPolicy.nsOnlyRegexp.MatchString(ar.Namespace) {
		fmt.Println("namespace doesn't match re-only-namespaces: ", ar.Namespace)
		return &kwhmutating.MutatorResult{}, nil
	}

	// We cannot support --net=host in Kata
	// https://github.com/kata-containers/documentation/blob/master/Limitations.md#docker---nethost
	if pod.Spec.HostNetwork {
		fmt.Println("host network: ", pod.GetNamespace(), pod.GetName())
		return &kwhmutating.MutatorResult{}, nil
	}

	// With genpolicy enabled, a webhook pod created by a rollout would otherwise get a CC VM.
	if pod.Labels["app"] == webhookAppLabel {
		fmt.Println("webhook pod: ", pod.GetNamespace(), pod.GetName())
		return &kwhmutating.MutatorResult{}, nil
	}

	if pod.GetNamespace() == "sonobuoy" {
		fmt.Println("sonobuoy pods will not be changed to kata", pod.GetNamespace(), pod.GetName())
		return &kwhmutating.MutatorResult{}, nil
	}

	if pod.Spec.RuntimeClassName != nil {
		fmt.Println("explicit runtime: ", pod.GetNamespace(), pod.GetName(), pod.Spec.RuntimeClassName)
		return &kwhmutating.MutatorResult{}, nil
	}

	minMemoryLimit, err := getMinMemoryLimit(minMemoryLimitEnvKey)
	if err != nil {
		return nil, err
	}
	if minMemoryLimit != nil {
		enforceMinMemoryLimit(pod.Spec.Containers, *minMemoryLimit)
		enforceMinMemoryLimit(pod.Spec.InitContainers, *minMemoryLimit)
	}

	// Mutate the pod
	fmt.Println("setting runtime to kata: ", pod.GetNamespace(), pod.GetName())

	runtimeClassEnvKey := "RUNTIME_CLASS"
	kataRuntimeClassName := getRuntimeClass(runtimeClassEnvKey, "kata")
	pod.Spec.RuntimeClassName = &kataRuntimeClassName

	// Last step: the policy must describe the final pod spec.
	if genpolicyCfg != nil {
		addPolicy(genpolicyCfg, pod, ar.Namespace)
	}

	return &kwhmutating.MutatorResult{
		MutatedObject: pod,
	}, nil
}

type config struct {
	certFile     string
	keyFile      string
	nsBlacklist  string
	nsOnlyRegexp string
	genpolicy    genpolicyConfig
}

type policy struct {
	nsBlacklist  map[string]bool
	nsOnlyRegexp *regexp.Regexp
}

var whPolicy *policy

func initFlags() *config {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.certFile, "tls-cert-file", "", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "", "TLS key file")
	fl.StringVar(&cfg.nsBlacklist, "exclude-namespaces", "", "Comma separated namespace blacklist")
	fl.StringVar(&cfg.nsOnlyRegexp, "only-namespaces-regexp", "", "Regexp namespace filter applied after --exclude-namespaces")
	fl.StringVar(&cfg.genpolicy.binary, "genpolicy", "", "Path to genpolicy; if set, add a generated policy to every pod switched to Kata")
	fl.StringVar(&cfg.genpolicy.settings, "genpolicy-settings", "/etc/genpolicy", "genpolicy settings file or directory")
	fl.StringVar(&cfg.genpolicy.rules, "genpolicy-rules", "/etc/genpolicy/rules.rego", "genpolicy rules file")
	fl.StringVar(&cfg.genpolicy.cacheFile, "genpolicy-cache", "/cache/layers-cache.json", "genpolicy layers cache file")
	fl.DurationVar(&cfg.genpolicy.timeout, "genpolicy-timeout", 25*time.Second, "Admit the pod without a policy if genpolicy takes longer")

	fl.Parse(os.Args[1:])
	return cfg
}

func main() {
	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	cfg := initFlags()

	whPolicy = &policy{}
	whPolicy.nsBlacklist = make(map[string]bool)
	if cfg.nsBlacklist != "" {
		for _, s := range strings.Split(cfg.nsBlacklist, ",") {
			whPolicy.nsBlacklist[s] = true
		}
	}

	if cfg.nsOnlyRegexp != "" {
		var err error
		whPolicy.nsOnlyRegexp, err = regexp.Compile(cfg.nsOnlyRegexp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error compiling regular expression: %s", err)
			os.Exit(1)
		}
	}

	if cfg.genpolicy.binary != "" {
		genpolicyCfg = &cfg.genpolicy
	}

	// Create our mutator
	mt := kwhmutating.MutatorFunc(annotatePodMutator)

	mcfg := kwhmutating.WebhookConfig{
		ID:      "podAnnotate",
		Obj:     &corev1.Pod{},
		Mutator: mt,
		Logger:  logger,
	}
	wh, err := kwhmutating.NewWebhook(mcfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	// Get the handler for our webhook.
	whHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{Webhook: wh, Logger: logger})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook handler: %s", err)
		os.Exit(1)
	}

	port := ":8080"
	logger.Infof("Listening on %s", port)
	err = http.ListenAndServeTLS(port, cfg.certFile, cfg.keyFile, whHandler)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serving webhook: %s", err)
		os.Exit(1)
	}
}
