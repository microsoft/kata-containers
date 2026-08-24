// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// placeholderNetns is a synthetic network namespace that satisfies the
// containment RestoreSandbox expects: it holds exactly one non-loopback
// interface carrying an IP address, so kata's endpoint scan yields exactly one
// endpoint. It is a POC stand-in for the target pod CNI netns, which does not
// exist until a real pod is scheduled.
type placeholderNetns struct {
	name string // named netns, bind-mounted at /var/run/netns/<name>
	path string // /var/run/netns/<name>
}

const (
	placeholderNetnsDir  = "/var/run/netns"
	placeholderIfaceName = "eth0"
	placeholderPeerName  = "eth0-host"
	// Link-local /30 that never routes; only presence of an addr matters.
	placeholderCIDR = "169.254.200.2/30"
	placeholderMTU  = 1500
)

// newPlaceholderNetns creates a named netns containing a single veth whose
// guest-facing end carries an IP, so the kata endpoint scan finds one endpoint.
//
// The calling OS thread is temporarily moved into the new namespace to plumb
// the interface, then restored. The named mount at /var/run/netns/<name>
// persists after this returns so RestoreSandbox can open it by path.
func newPlaceholderNetns(name string) (_ *placeholderNetns, err error) {
	if err := os.MkdirAll(placeholderNetnsDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", placeholderNetnsDir, err)
	}

	// Pin this goroutine so namespace switches do not leak to other goroutines.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("get current netns: %w", err)
	}
	defer origns.Close()

	// NewNamed creates the bind-mounted named netns and switches this thread
	// into it. Restore the original namespace on every return path.
	newns, err := netns.NewNamed(name)
	if err != nil {
		return nil, fmt.Errorf("create named netns %q: %w", name, err)
	}
	defer newns.Close()
	defer func() {
		if setErr := netns.Set(origns); setErr != nil && err == nil {
			err = fmt.Errorf("restore original netns: %w", setErr)
		}
	}()
	// If anything below fails, delete the named netns we just created.
	defer func() {
		if err != nil {
			_ = netns.DeleteNamed(name)
		}
	}()

	// Both veth ends live in this netns; only the guest-facing end gets an IP,
	// so exactly one interface is endpoint-eligible.
	la := netlink.NewLinkAttrs()
	la.Name = placeholderIfaceName
	la.MTU = placeholderMTU
	veth := &netlink.Veth{LinkAttrs: la, PeerName: placeholderPeerName}
	if err = netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("create veth in netns %q: %w", name, err)
	}

	link, err := netlink.LinkByName(placeholderIfaceName)
	if err != nil {
		return nil, fmt.Errorf("find %s in netns %q: %w", placeholderIfaceName, name, err)
	}
	addr, err := netlink.ParseAddr(placeholderCIDR)
	if err != nil {
		return nil, fmt.Errorf("parse placeholder addr: %w", err)
	}
	if err = netlink.AddrAdd(link, addr); err != nil {
		return nil, fmt.Errorf("assign addr to %s: %w", placeholderIfaceName, err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("bring up %s: %w", placeholderIfaceName, err)
	}

	return &placeholderNetns{
		name: name,
		path: filepath.Join(placeholderNetnsDir, name),
	}, nil
}

// remove unmounts and deletes the named netns. Safe to call more than once.
func (p *placeholderNetns) remove() error {
	if p == nil || p.name == "" {
		return nil
	}
	if err := netns.DeleteNamed(p.name); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete named netns %q: %w", p.name, err)
	}
	return nil
}
