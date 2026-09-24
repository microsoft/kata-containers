// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Command warm-pool-manager maintains a pool of warm kata pod-sandbox members
// via containerd's CRI API and serves claims over a small HTTP control API.
//
// It is a non-Kubernetes control plane: every member is an ordinary kata pod
// sandbox created with RunPodSandbox, so containerd drives the normal
// shim-v2 -> cloud-hypervisor path. The manager only does the bookkeeping
// (reconcile-to-N, claim, backfill, TTL/health) — it never spawns a VMM.
//
//		Tier A: warm members are bare pod sandboxes. Claim attaches a
//		        workload container.
//		Tier B: warm members are deferred-paused restore sandboxes. Claim wakes the
//	         VM with an exec no-op.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kata-containers/kata-containers/src/tools/warm-pool-manager/cri"
	"github.com/kata-containers/kata-containers/src/tools/warm-pool-manager/pool"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// annotationFlag collects repeated -restore-annotation key=value pairs.
type annotationFlag map[string]string

func (a annotationFlag) String() string { return "" }
func (a annotationFlag) Set(v string) error {
	k, val, _ := strings.Cut(v, "=")
	a[strings.TrimSpace(k)] = strings.TrimSpace(val)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[warm-pool] ")

	var (
		endpoint = flag.String("endpoint", "/run/containerd/containerd.sock", "containerd CRI socket")
		handler  = flag.String("runtime-handler", "kata", "kata runtime handler registered in containerd")
		size     = flag.Int("size", 2, "number of free warm members to maintain")
		tier     = flag.String("tier", "B", "warm-member strategy: A (attach-on-claim) or B (deferred-restore wake-on-claim)")
		image    = flag.String("image", "", "workload image for members (ignored if -container-config sets one)")
		ns       = flag.String("namespace", "warmpool", "pod sandbox namespace")
		wakeCtr  = flag.String("wake-container", "agent", "Tier B container the wake exec targets")
		podCfg   = flag.String("pod-config", "", "CRI PodSandboxConfig YAML/JSON template for members")
		ctrCfg   = flag.String("container-config", "", "CRI ContainerConfig YAML/JSON template for member workloads (e.g. pyruntime)")
		ttl      = flag.Duration("member-ttl", 0, "recycle free members older than this (0 = never)")
		interval = flag.Duration("reconcile-interval", 5*time.Second, "maintenance loop period")
		listen   = flag.String("listen", "127.0.0.1:8080", "HTTP control API address")
	)
	restoreAnns := annotationFlag{}
	flag.Var(restoreAnns, "restore-annotation", "Tier B restore annotation key=value (repeatable)")
	memberLabels := annotationFlag{}
	flag.Var(memberLabels, "member-label", "label stamped on members for claim selectors, key=value (repeatable)")
	var command stringsFlag
	flag.Var(&command, "command", "override member container entrypoint arg (repeatable)")
	flag.Parse()

	var podTemplate *runtimeapi.PodSandboxConfig
	if *podCfg != "" {
		t, err := pool.LoadPodSandboxConfig(*podCfg)
		if err != nil {
			log.Fatalf("load pod config: %v", err)
		}
		podTemplate = t
	}
	var ctrTemplate *runtimeapi.ContainerConfig
	if *ctrCfg != "" {
		t, err := pool.LoadContainerConfig(*ctrCfg)
		if err != nil {
			log.Fatalf("load container config: %v", err)
		}
		ctrTemplate = t
	}

	client, err := cri.Dial(*endpoint)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	version, err := client.Version(pingCtx)
	pingCancel()
	if err != nil {
		log.Fatalf("CRI handshake failed: %v", err)
	}
	log.Printf("connected to CRI runtime: %s", version)

	mgr, err := pool.New(client, pool.Config{
		Endpoint:           *endpoint,
		RuntimeHandler:     *handler,
		PoolSize:           *size,
		Namespace:          *ns,
		Tier:               pool.Tier(strings.ToUpper(*tier)),
		Image:              *image,
		Command:            command,
		PodTemplate:        podTemplate,
		ContainerTemplate:  ctrTemplate,
		MemberLabels:       memberLabels,
		RestoreAnnotations: restoreAnns,
		WakeContainer:      *wakeCtr,
		MemberTTL:          *ttl,
		ReconcileInterval:  *interval,
	})
	if err != nil {
		log.Fatalf("init manager: %v", err)
	}
	log.Printf("strategy: %s, target size: %d", mgr.Strategy().Name(), *size)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := startAPI(*listen, mgr)

	runErr := make(chan error, 1)
	go func() { runErr <- mgr.Run(ctx) }()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received")
	case err := <-runErr:
		log.Printf("manager loop exited: %v", err)
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
	log.Printf("tearing down %d members...", mgr.Stats().Total)
	mgr.Shutdown(shutCtx)
	log.Printf("bye")
}

// startAPI serves /stats (GET) and /claim (POST) for demos and integration.
func startAPI(addr string, mgr *pool.Manager) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mgr.Stats())
	})

	mux.HandleFunc("/claim", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()

		selector := parseSelector(r.URL.Query().Get("selector"))

		// mode=reserve hands back only the sandbox ID (no attach/wake) so an
		// external `crictl create <id> ... && crictl start` can continue the
		// normal CRI flow on the pooled sandbox.
		var (
			mem *pool.Member
			err error
		)
		if r.URL.Query().Get("mode") == "reserve" {
			mem, err = mgr.Reserve(ctx, selector)
		} else {
			mem, err = mgr.Claim(ctx, selector)
		}
		if err == pool.ErrNoMemberAvailable {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"id":         mem.ID,
			"name":       mem.Name,
			"workloadId": mem.WorkloadID,
		})
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("control API on http://%s (GET /stats, POST /claim)", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()
	return srv
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// stringsFlag collects repeated string flags.
type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, " ") }
func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseSelector turns "k1=v1,k2=v2" into a label map (empty string => nil).
func parseSelector(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, _ := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if k != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}
