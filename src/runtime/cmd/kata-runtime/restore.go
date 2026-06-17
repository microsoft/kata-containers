// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	containerdshim "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2"
	"github.com/urfave/cli"
)

// restore boots a snapshot dir as a Mode A side-by-side CLONE: a brand-new
// cloud-hypervisor running next to the still-alive original. The clone has no shim
// or sandbox owner, so this command itself drives all the layers the shim would: it
// copies+patches the config, creates a host tap, launches clh via systemd-run, calls
// vm.restore/vm.resume over the clh api socket, then re-IPs the clone's eth0 via
// kata-agent-ctl (without which the clone collides with the original's IP). COW is
// automatic: CLH opens the snapshot's memory-ranges MAP_PRIVATE, so the clone
// diverges and the original's RAM is never written. This mirrors the proven manual
// restore runbook (nodepool0 counter/pyruntime demos) 1:1.

const (
	// restoreWorkBase holds per-clone working dirs (tmpfs). Each clone gets
	// /tmp/<clone-id>/ with the patched config + symlinked memory-ranges, the clh api
	// socket, the agent vsock, the clh log, and clone.json metadata.
	restoreWorkBase = "/tmp"

	// clone networking is auto-allocated, not user-supplied. Each clone N gets tap
	// kat<N> and the point-to-point subnet 192.168.<tapSubnetBase+N>.0/24 (host .2,
	// guest .1). tap<N> is claimed atomically by `ip tuntap add` (fails EBUSY if the
	// device exists), which is what lets N>1 clones coexist without a TOCTOU.
	tapPrefix     = "kat"
	tapSubnetBase = 240 // -> 192.168.240.x for clone 0, .241 for clone 1, ...
	maxClones     = 15  // 192.168.240..254; one tap/subnet each

	// clh + agent binaries are resolved from PATH (falling back to these), not flags.
	defaultClhBin    = "cloud-hypervisor"
	defaultAgentCtl  = "kata-agent-ctl"
	fallbackAgentCtl = "/kata-containers/src/tools/agent-ctl/target/release/kata-agent-ctl"
)

// cloneNet is the auto-allocated networking for one clone.
type cloneNet struct {
	tap     string // kat<N>
	hostIP  string // 192.168.<base+N>.2/24
	guestIP string // 192.168.<base+N>.1/24
}

// cloneMeta records exactly what a restore created so `kill` can clean it precisely.
type cloneMeta struct {
	ID      string `json:"id"`
	Tap     string `json:"tap"`
	HostIP  string `json:"host_ip"`
	GuestIP string `json:"guest_ip"`
	Unit    string `json:"unit"`
	Vsock   string `json:"vsock"`
	Sock    string `json:"sock"`
	Source  string `json:"source"`
}

var restoreCLICommand = cli.Command{
	Name:      "restore",
	Usage:     "restore a Kata Containers snapshot as a running clone",
	ArgsUsage: "--from <snapshot>",
	Flags: []cli.Flag{
		cli.StringFlag{Name: "from", Usage: "snapshot source: a name under " + containerdshim.SnapshotBaseDir + ", or a path"},
		cli.StringFlag{Name: "name", Usage: "clone id (default: clone-<hex>)"},
		// advanced/hidden: binary overrides for non-standard nodes. Networking is
		// auto-allocated and intentionally NOT exposed.
		cli.StringFlag{Name: "clh-bin", Usage: "cloud-hypervisor binary (default: from PATH)", Hidden: true},
		cli.StringFlag{Name: "agent-ctl", Usage: "kata-agent-ctl binary (default: from PATH)", Hidden: true},
	},
	// kill is a subcommand; with no matching subcommand this Action runs.
	Subcommands: []cli.Command{restoreKillCommand},
	Action:      restoreAction,
}

func restoreAction(c *cli.Context) error {
	from := c.String("from")
	if from == "" {
		return fmt.Errorf("--from is required")
	}
	src, err := resolveSource(from)
	if err != nil {
		return err
	}
	clhBin := resolveBin(c.String("clh-bin"), defaultClhBin, "")
	agentCtl := resolveBin(c.String("agent-ctl"), defaultAgentCtl, fallbackAgentCtl)

	id := genCloneID(c.String("name"))
	if err := validateCloneID(id); err != nil {
		return err
	}
	cloneDir := filepath.Join(restoreWorkBase, id)
	unit := "clh-" + id
	sock := filepath.Join(cloneDir, "clh.sock")
	vsock := filepath.Join(cloneDir, "clone-vm.vsock")

	if _, err := os.Stat(cloneDir); err == nil {
		return fmt.Errorf("clone %q already exists; run `kata-runtime restore kill %s` first", id, id)
	}

	// allocate a free tap + subnet by atomically claiming the tap (add fails EBUSY if
	// taken). this both picks the slot and reserves it -- no check-then-create race.
	net, err := allocateCloneNet()
	if err != nil {
		return err
	}

	ok := false
	defer func() {
		// roll back whatever we created if we bail out mid-flight.
		if !ok {
			killClh(sock)
			deleteTap(net.tap)
			os.RemoveAll(cloneDir)
		}
	}()

	// proven manual restore STEP 1: build the clone's private working dir at 0700
	// (config.json + state.json copied; memory-ranges symlinked, not duplicated).
	if err := prepareCopy(src, cloneDir); err != nil {
		return err
	}

	// proven manual restore STEP 2: jq-equivalent patch (5 edits, .file untouched);
	// returns the MAC to reuse for the re-IP.
	mac, err := patchConfig(cloneDir, vsock, net.tap)
	if err != nil {
		return err
	}

	// proven manual restore STEP 3: finish wiring the allocated tap (addr + route).
	if err := setupTap(net); err != nil {
		return err
	}

	// proven manual restore STEP 4: launch a fresh cloud-hypervisor.
	if err := launchCLH(cloneDir, clhBin, unit, sock); err != nil {
		return err
	}

	// proven manual restore STEP 5: restore + resume + wait for Running.
	if err := clhPut(sock, "vm.restore", map[string]interface{}{"source_url": "file://" + cloneDir, "prefault": false}); err != nil {
		return fmt.Errorf("vm.restore: %s", err)
	}
	if err := clhPut(sock, "vm.resume", nil); err != nil {
		return fmt.Errorf("vm.resume: %s", err)
	}
	if err := waitRunning(sock); err != nil {
		return err
	}

	// proven manual restore STEP 6: re-IP the clone's eth0 (verify + retry). we ALWAYS
	// assign a fresh IP -- restore never tries to preserve the original's pod IP.
	if err := reIP(agentCtl, vsock, mac, net.guestIP); err != nil {
		return err
	}

	meta := cloneMeta{ID: id, Tap: net.tap, HostIP: net.hostIP, GuestIP: net.guestIP, Unit: unit, Vsock: vsock, Sock: sock, Source: src}
	if err := writeCloneMeta(cloneDir, meta); err != nil {
		return err
	}
	ok = true

	guestAddr, _ := splitCIDR(net.guestIP)
	fmt.Fprintf(defaultOutputFile, "clone %s up\n", id)
	fmt.Fprintf(defaultOutputFile, "guest IP: %s   (inbound only - no egress/default route)\n", guestAddr)
	fmt.Fprintf(defaultOutputFile, "probe:    curl http://%s:<port>/   (counter app on :9999, pyruntime on :8888)\n", guestAddr)
	fmt.Fprintf(defaultOutputFile, "note:     %s is held MAP_PRIVATE; do not `snapshot delete` it while this clone is live\n", src)
	// loud disclosure: a side-by-side clone shares the original's kernel RNG state and
	// frozen wall/monotonic clock. unsafe for workloads that mint secrets (tokens,
	// UUIDs, TLS nonces) or depend on time post-restore. RNG reseed + SetGuestDateTime
	// are deferred future work (security review C1/H2/M2, §13).
	fmt.Fprintf(defaultOutputFile, "WARNING:  clone shares the original's RNG state and wall clock - unsafe for secret-minting or time-dependent workloads (RNG reseed + clock sync are future work, security-review §13)\n")
	return nil
}

var restoreKillCommand = cli.Command{
	Name:      "kill",
	Usage:     "tear down a restore clone (stop clh, delete tap, remove working dir)",
	ArgsUsage: "<clone-id>",
	Action:    killAction,
}

func killAction(c *cli.Context) error {
	id := c.Args().First()
	if id == "" {
		return fmt.Errorf("clone id is required: kata-runtime restore kill <clone-id>")
	}
	if err := validateCloneID(id); err != nil {
		return err
	}
	cloneDir := filepath.Join(restoreWorkBase, id)
	sock := filepath.Join(cloneDir, "clh.sock")
	tap := ""
	// recover the exact tap/sock this clone used from its clone.json (written for
	// every successful restore; the tap is auto-allocated so there is no default).
	if b, err := os.ReadFile(filepath.Join(cloneDir, "clone.json")); err == nil {
		var meta cloneMeta
		if json.Unmarshal(b, &meta) == nil {
			if meta.Sock != "" {
				sock = meta.Sock
			}
			if meta.Tap != "" {
				tap = meta.Tap
			}
		}
	}
	killClh(sock)
	if tap != "" {
		deleteTap(tap)
		if tapExists(tap) {
			fmt.Fprintf(defaultOutputFile, "warning: tap %s still present; remove with: ip tuntap del mode tap %s\n", tap, tap)
		}
	}
	os.RemoveAll(cloneDir)
	fmt.Fprintf(defaultOutputFile, "cleaned %s\n", id)
	return nil
}

// resolveSource maps --from to a snapshot dir and checks it looks like one.
func resolveSource(from string) (string, error) {
	// a bare name (no slash) must stay a direct child of SnapshotBaseDir -- reject
	// `--from ..` style traversal, mirroring the snapshot delete guard. An explicit
	// path (with a slash) is the caller's responsibility and used verbatim.
	if !strings.Contains(from, "/") {
		clean := filepath.Clean(filepath.Join(containerdshim.SnapshotBaseDir, from))
		if filepath.Dir(clean) != filepath.Clean(containerdshim.SnapshotBaseDir) {
			return "", fmt.Errorf("invalid snapshot name %q: must not contain path separators or ..", from)
		}
	}
	dir := resolvePath(from)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("snapshot not found: %s", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		return "", fmt.Errorf("not a snapshot dir (no config.json): %s", dir)
	}
	return dir, nil
}

// resolvePath is the pure name->path rule: a bare name (no slash) lives under
// SnapshotBaseDir; anything with a slash is used verbatim.
func resolvePath(from string) string {
	if strings.Contains(from, "/") {
		return from
	}
	return filepath.Join(containerdshim.SnapshotBaseDir, from)
}

// genCloneID returns name if given, else a random clone-<hex> id. If the entropy
// read fails (effectively never for crypto/rand), it falls back to a pid+nanotime
// suffix so we never silently emit a fixed all-zero id; the caller's dir-exists guard
// catches any residual collision.
func genCloneID(name string) string {
	if name != "" {
		return name
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("clone-%x%x", os.Getpid(), time.Now().UnixNano())
	}
	return "clone-" + hex.EncodeToString(b)
}

// validateCloneID rejects ids that would let the working dir escape restoreWorkBase.
// The id becomes /tmp/<id>, which restore creates (cp/symlink as root) and kill
// removes (os.RemoveAll as root) -- so a "../etc" style id is a write/delete primitive.
// Mirrors the snapshot delete guard (snapshot.go S2): the cleaned join must stay a
// direct child of restoreWorkBase.
func validateCloneID(id string) error {
	dir := filepath.Clean(filepath.Join(restoreWorkBase, id))
	if filepath.Dir(dir) != filepath.Clean(restoreWorkBase) {
		return fmt.Errorf("invalid clone id %q: must not contain path separators or ..", id)
	}
	return nil
}

// prepareCopy builds the clone's private working dir from the snapshot WITHOUT
// duplicating the ~2 GiB memory-ranges. config.json (patched next) + state.json are
// what source_url reads; the guest RAM is backed by config's .memory.zones[].file,
// which stays pointed at the ORIGINAL snapshot's memory-ranges (opened MAP_PRIVATE ->
// COW, original never written). We symlink memory-ranges into the clone dir so the
// source_url dir still contains the expected file name at zero RAM cost, while .file
// (untouched by patchConfig) resolves to the original. This is the documented H4
// source-dependency: the original snapshot must outlive the clone.
func prepareCopy(src, cloneDir string) error {
	if err := os.MkdirAll(cloneDir, 0700); err != nil {
		return err
	}
	for _, f := range []string{"config.json", "state.json"} {
		data, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			return fmt.Errorf("read %s: %s", f, err)
		}
		if err := os.WriteFile(filepath.Join(cloneDir, f), data, 0600); err != nil {
			return err
		}
	}
	// symlink, do NOT copy, the 2 GiB RAM file.
	if err := os.Symlink(filepath.Join(src, "memory-ranges"), filepath.Join(cloneDir, "memory-ranges")); err != nil {
		return fmt.Errorf("symlink memory-ranges: %s", err)
	}
	return nil
}

// patchConfig applies the proven 5 edits to the clone's config.json and returns the
// MAC to reuse for the agent re-IP. It deliberately does NOT touch
// .memory.zones[].file: COW comes from .memory.shared=false +
// .memory.zones[].shared=false, which makes CLH open the (original) memory-ranges
// MAP_PRIVATE so the source snapshot is never written.
func patchConfig(cloneDir, vsock, tap string) (string, error) {
	path := filepath.Join(cloneDir, "config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	mac, err := patchConfigMap(cfg, vsock, tap)
	if err != nil {
		return "", err
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return mac, os.WriteFile(path, out, 0600)
}

// patchConfigMap mutates cfg in place (the testable core of patchConfig).
func patchConfigMap(cfg map[string]interface{}, vsock, tap string) (string, error) {
	netArr, ok := cfg["net"].([]interface{})
	if !ok || len(netArr) == 0 {
		return "", fmt.Errorf("config.json: .net[0] missing")
	}
	net0, ok := netArr[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("config.json: .net[0] not an object")
	}
	net0["tap"] = tap // attach the clone to its own host tap
	net0["fds"] = nil // drop the original's inherited tap fds
	mac, _ := net0["mac"].(string)
	if mac == "" {
		return "", fmt.Errorf("config.json: .net[0].mac missing")
	}

	vs, ok := cfg["vsock"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("config.json: .vsock missing")
	}
	vs["socket"] = vsock // unique per-clone agent vsock (clh demuxes by this path)

	mem, ok := cfg["memory"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("config.json: .memory missing")
	}
	mem["shared"] = false // MAP_PRIVATE -> COW; do NOT touch .zones[].file
	if zones, ok := mem["zones"].([]interface{}); ok {
		for _, z := range zones {
			if zm, ok := z.(map[string]interface{}); ok {
				zm["shared"] = false
			}
		}
	}
	return mac, nil
}

// allocateCloneNet finds a free clone slot by atomically claiming a tap: `ip tuntap
// add kat<N>` fails EBUSY if the device already exists, so the first N that adds
// cleanly is ours and is now reserved -- no separate existence check, no TOCTOU. The
// matching subnet 192.168.<base+N>.0/24 is implied by N. On success the tap exists
// (DOWN); setupTap brings it up and assigns addresses.
func allocateCloneNet() (cloneNet, error) {
	for n := 0; n < maxClones; n++ {
		tap := fmt.Sprintf("%s%d", tapPrefix, n)
		if err := exec.Command("ip", "tuntap", "add", "mode", "tap", tap).Run(); err != nil {
			continue // device busy (or add failed) -> try the next slot
		}
		octet := tapSubnetBase + n
		return cloneNet{
			tap:     tap,
			hostIP:  fmt.Sprintf("192.168.%d.2/24", octet),
			guestIP: fmt.Sprintf("192.168.%d.1/24", octet),
		}, nil
	}
	return cloneNet{}, fmt.Errorf("no free clone slot (all %d taps %s0..%s%d in use); kill an existing clone", maxClones, tapPrefix, tapPrefix, maxClones-1)
}

// resolveBin picks an explicit override, else the first of (name-on-PATH, fallback)
// that exists, else the bare name (let exec surface the error at use).
func resolveBin(override, name, fallback string) string {
	if override != "" {
		return override
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if fallback != "" {
		if _, err := os.Stat(fallback); err == nil {
			return fallback
		}
	}
	return name
}

// setupTap finishes wiring an already-allocated tap: bring it up, assign the host IP,
// and add a /32 route to the guest. The tap itself was created (and thereby reserved)
// by allocateCloneNet.
func setupTap(net cloneNet) error {
	guestAddr, _ := splitCIDR(net.guestIP)
	steps := [][]string{
		{"link", "set", "dev", net.tap, "up"},
		{"a", "add", net.hostIP, "dev", net.tap},
		{"route", "add", guestAddr + "/32", "dev", net.tap},
	}
	for _, s := range steps {
		if out, err := exec.Command("ip", s...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %s (%s)", strings.Join(s, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// launchCLH starts a fresh cloud-hypervisor in its own transient systemd scope so it
// survives this process exiting. stdin is /dev/null and the child gets its own
// session (Setsid) to dodge SIGTTOU, which would otherwise stop clh and hang every
// API call. Mirrors the proven `systemd-run --scope --slice=- --collect ... </dev/null & disown`.
func launchCLH(cloneDir, clhBin, unit, sock string) error {
	logPath := filepath.Join(cloneDir, "clh-restore.log")
	logf, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logf.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()

	args := []string{
		"--unit=" + unit, "--scope", "--slice=-", "--collect", "--quiet",
		clhBin, "--api-socket", sock, "-v",
	}
	cmd := exec.Command("systemd-run", args...)
	cmd.Stdin = devnull
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("systemd-run cloud-hypervisor: %s", err)
	}

	// wait for the api socket to appear (clh is up once it's listening).
	for i := 0; i < 80; i++ {
		if isSocket(sock) {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("clh api socket never appeared: %s (see %s)", sock, logPath)
}

// clhClient builds an http client that dials a CLH api unix socket. Mirrors the
// in-tree shimclient.buildUnixSocketClient idiom, pointed at the raw clh socket.
func clhClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Dial: func(_, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}
}

// clhPut PUTs a json body to a CLH api path and expects 204/200.
func clhPut(sock, apiPath string, body interface{}) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPut, "http://localhost/api/v1/"+apiPath, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := clhClient(sock).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// waitRunning polls vm.info until the clone reports Running.
func waitRunning(sock string) error {
	for i := 0; i < 40; i++ {
		if clhState(sock) == "Running" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("clh did not reach Running state (see the clh-restore.log in the clone dir)")
}

func clhState(sock string) string {
	resp, err := clhClient(sock).Get("http://localhost/api/v1/vm.info")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var info struct {
		State string `json:"state"`
	}
	json.NewDecoder(resp.Body).Decode(&info)
	return info.State
}

// reIP reconfigures the clone's eth0 over hybrid-vsock so it stops colliding with the
// original's IP. UpdateInterface logs "FIXME not fully implemented" but still adds the
// IP; it's flaky, so we poll ListInterfaces and retry once.
func reIP(agentCtl, vsock, mac, guestIP string) error {
	addr, mask := splitCIDR(guestIP)
	ifJSON := fmt.Sprintf(`UpdateInterface json://{"interface": {"name": "eth0", "device": "", "mtu": 1500, "hwAddr": "%s", "IPAddresses": [{"family": 0, "address": "%s", "mask": "%s"}]}}`, mac, addr, mask)
	server := "unix://" + vsock
	for attempt := 0; attempt < 2; attempt++ {
		// timeout 15: kata-agent-ctl can hang after the RPC actually succeeds.
		exec.Command("timeout", "15", agentCtl, "connect", "--server-address", server, "--hybrid-vsock", "true", "-c", ifJSON).Run()
		// the IP takes a few seconds to settle (5s counter / 8s pyruntime); poll.
		for i := 0; i < 6; i++ {
			time.Sleep(2 * time.Second)
			if ipPresent(agentCtl, server, addr) {
				return nil
			}
		}
	}
	return fmt.Errorf("re-IP failed: %s not visible on eth0 after retry (check kata-agent-ctl ListInterfaces)", addr)
}

func ipPresent(agentCtl, server, addr string) bool {
	out, _ := exec.Command("timeout", "10", agentCtl, "connect", "--server-address", server, "--hybrid-vsock", "true", "-c", "ListInterfaces").CombinedOutput()
	// match addr as a whole token, not a substring: otherwise 192.168.240.1 would
	// falsely match inside 192.168.240.10 (auto-allocated subnets go up to .254).
	return hasIPToken(string(out), addr)
}

// hasIPToken reports whether addr appears in s bounded by non-IP-character runs, so
// "192.168.240.1" does not match within "192.168.240.10".
func hasIPToken(s, addr string) bool {
	isIPChar := func(b byte) bool { return (b >= '0' && b <= '9') || b == '.' }
	for i := 0; ; {
		j := strings.Index(s[i:], addr)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(addr)
		leftOK := start == 0 || !isIPChar(s[start-1])
		rightOK := end == len(s) || !isIPChar(s[end])
		if leftOK && rightOK {
			return true
		}
		i = start + 1
	}
}

func writeCloneMeta(cloneDir string, meta cloneMeta) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cloneDir, "clone.json"), b, 0600)
}

func tapExists(tap string) bool {
	return exec.Command("ip", "link", "show", tap).Run() == nil
}

// deleteTap removes the host tap, retrying because the kernel releases it from a
// dying clh asynchronously: an immediate delete races and silently no-ops, leaving
// the tap lingering DOWN.
func deleteTap(tap string) {
	for i := 0; i < 20; i++ {
		if !tapExists(tap) {
			return
		}
		exec.Command("ip", "tuntap", "del", "mode", "tap", tap).Run()
		time.Sleep(250 * time.Millisecond)
	}
}

// killClh SIGKILLs the clone's cloud-hypervisor, found by its unique api socket in
// the process table. The match key is the per-clone "--api-socket <sock>" token, NOT
// the binary name -- a custom --clh-bin path/name must still be killed. NOT systemctl
// stop (--collect reaps the dead scope) and NOT pkill -f (which would match this very
// process).
func killClh(sock string) {
	out, err := exec.Command("ps", "-eo", "pid,args").Output()
	if err != nil {
		return
	}
	needle := "--api-socket " + sock
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if pid, err := strconv.Atoi(fields[0]); err == nil {
			if p, err := os.FindProcess(pid); err == nil {
				p.Signal(syscall.SIGKILL)
			}
		}
	}
}

// splitCIDR splits "192.168.249.1/24" into ("192.168.249.1", "24"). A bare address
// returns an empty mask.
func splitCIDR(cidr string) (addr, mask string) {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i], cidr[i+1:]
	}
	return cidr, ""
}

func isSocket(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}
