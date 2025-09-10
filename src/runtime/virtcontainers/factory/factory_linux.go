// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package factory

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils/katatrace"
	pb "github.com/kata-containers/kata-containers/src/runtime/protocols/cache"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/factory/base"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/factory/cache"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/factory/direct"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/factory/grpccache"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/factory/template"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils"
)

type factory struct {
	base base.FactoryBase
}

// NewFactory returns a working factory.
func NewFactory(ctx context.Context, config Config, fetchOnly bool) (vc.Factory, error) {
	span, _ := katatrace.Trace(ctx, nil, "NewFactory", factoryTracingTags)
	defer span.End()

	factoryLogger.WithField("factoryConfig", config).Info("Cameron debug: NewFactory")

	err := config.VMConfig.Valid()
	if err != nil {
		return nil, err
	}

	if fetchOnly && config.Cache > 0 {
		return nil, fmt.Errorf("cache factory does not support fetch")
	}

	var b base.FactoryBase
	if config.VMCache && config.Cache == 0 {
		// For VMCache client
		factoryLogger.Info("Cameron debug: using VMCache factory")
		b, err = grpccache.New(ctx, config.VMCacheEndpoint)
		if err != nil {
			return nil, err
		}
	} else {
		if config.Template {
			factoryLogger.Info("Cameron debug: using Template factory (entry)")
			if fetchOnly {
				factoryLogger.WithField("fetchOnly", fetchOnly).Info("Cameron debug: before template.Fetch")
				b, err = template.Fetch(config.VMConfig, config.TemplatePath, config.UseSnapshot)
				factoryLogger.WithField("fetchOnly", fetchOnly).WithField("err", err).Info("Cameron debug: after template.Fetch")
				if err != nil {
					factoryLogger.WithError(err).Error("Cameron debug: template.Fetch failed")
					return nil, err
				}
			} else {
				factoryLogger.WithField("fetchOnly", fetchOnly).Info("Cameron debug: before template.New")
				b, err = template.New(ctx, config.VMConfig, config.TemplatePath, config.UseSnapshot)
				factoryLogger.WithField("fetchOnly", fetchOnly).WithField("err", err).Info("Cameron debug: after template.New")
				if err != nil {
					factoryLogger.WithError(err).Error("Cameron debug: template.New failed")
					return nil, err
				}
			}
			factoryLogger.Info("Cameron debug: using Template factory (exit)")
		} else {
			factoryLogger.Info("Cameron debug: using Direct factory")
			b = direct.New(ctx, config.VMConfig)
		}

		if config.Cache > 0 {
			factoryLogger.Info("Cameron debug: adding Cache layer to factory")
			b = cache.New(ctx, config.Cache, b)
		}
	}

	return &factory{b}, nil
}

func resetHypervisorConfig(config *vc.VMConfig) {
	config.HypervisorConfig.NumVCPUsF = 0
	config.HypervisorConfig.DefaultMaxVCPUs = 0
	config.HypervisorConfig.MemorySize = 0
	config.HypervisorConfig.BootToBeTemplate = false
	config.HypervisorConfig.BootFromTemplate = false
	config.HypervisorConfig.MemoryPath = ""
	config.HypervisorConfig.DevicesStatePath = ""
	config.HypervisorConfig.SharedPath = ""
	config.HypervisorConfig.VMStorePath = ""
	config.HypervisorConfig.RunStorePath = ""
	config.HypervisorConfig.SandboxName = ""
	config.HypervisorConfig.SandboxNamespace = ""
}

// It's important that baseConfig and newConfig are passed by value!
func checkVMConfig(baseConfig, newConfig vc.VMConfig) error {
	if baseConfig.HypervisorType != newConfig.HypervisorType {
		return fmt.Errorf("hypervisor type does not match: %s vs. %s", baseConfig.HypervisorType, newConfig.HypervisorType)
	}

	// check hypervisor config details
	resetHypervisorConfig(&baseConfig)
	resetHypervisorConfig(&newConfig)

	if !utils.DeepCompare(baseConfig, newConfig) {
		// Pretty print configs for comparison
		baseJSON, _ := json.MarshalIndent(baseConfig, "", "  ")
		newJSON, _ := json.MarshalIndent(newConfig, "", "  ")

		factoryLogger.WithField("baseConfig", string(baseJSON)).Info("Cameron debug: base config")
		factoryLogger.WithField("newConfig", string(newJSON)).Info("Cameron debug: new config")

		return fmt.Errorf("hypervisor config does not match")
	}

	return nil
}

func (f *factory) checkConfig(config vc.VMConfig) error {
	baseConfig := f.base.Config()

	return checkVMConfig(baseConfig, config)
}

// GetVM returns a working blank VM created by the factory.
func (f *factory) GetVM(ctx context.Context, config vc.VMConfig) (*vc.VM, error) {
	span, ctx := katatrace.Trace(ctx, f.log(), "GetVM", factoryTracingTags)
	defer span.End()

	f.log().Infof("Cameron debug: start s.factory.GetVM with config %v", config)
	hypervisorConfig := config.HypervisorConfig
	if err := config.Valid(); err != nil {
		f.log().WithError(err).Error("invalid hypervisor config")
		return nil, err
	}

	f.log().Infof("Cameron debug: before f.checkConfig with config %v", config)
	err := f.checkConfig(config)
	if err != nil {
		f.log().WithError(err).Info("fallback to direct factory vm")
		return direct.New(ctx, config).GetBaseVM(ctx, config)
	}

	f.log().Info("get base VM")
	vm, err := f.base.GetBaseVM(ctx, config)
	if err != nil {
		f.log().WithError(err).Error("failed to get base VM")
		return nil, err
	}

	f.log().Infof("Cameron debug: after GetBaseVM %v", vm)

	// cleanup upon error
	defer func() {
		if err != nil {
			f.log().WithError(err).Error("clean up vm")
			vm.Stop(ctx)
		}
	}()

	err = vm.Resume(ctx)
	if err != nil {
		return nil, err
	}

	f.log().Infof("Cameron debug: after Resume")

	// reseed RNG so that shared memory VMs do not generate same random numbers.
	err = vm.ReseedRNG(ctx)
	if err != nil {
		return nil, err
	}

	f.log().Infof("Cameron debug: after ReseedRNG")

	// sync guest time since we might have paused it for a long time.
	err = vm.SyncTime(ctx)
	if err != nil {
		return nil, err
	}

	f.log().Infof("Cameron debug: after SyncTime")

	online := false
	baseConfig := f.base.Config().HypervisorConfig
	if baseConfig.NumVCPUsF < hypervisorConfig.NumVCPUsF {
		err = vm.AddCPUs(ctx, hypervisorConfig.NumVCPUs()-baseConfig.NumVCPUs())
		if err != nil {
			return nil, err
		}
		online = true
	}

	f.log().Infof("Cameron debug: after AddCPUs")

	if baseConfig.MemorySize < hypervisorConfig.MemorySize {
		err = vm.AddMemory(ctx, hypervisorConfig.MemorySize-baseConfig.MemorySize)
		if err != nil {
			return nil, err
		}
		online = true
	}

	f.log().Infof("Cameron debug: after AddMemory")

	if online {
		err = vm.OnlineCPUMemory(ctx)
		if err != nil {
			return nil, err
		}
	}

	f.log().Infof("Cameron debug: after OnlineCPUMemory")

	return vm, nil
}

// Config returns base factory config.
func (f *factory) Config() vc.VMConfig {
	return f.base.Config()
}

// GetVMStatus returns the status of the paused VM created by the base factory.
func (f *factory) GetVMStatus() []*pb.GrpcVMStatus {
	return f.base.GetVMStatus()
}

// GetBaseVM returns a paused VM created by the base factory.
func (f *factory) GetBaseVM(ctx context.Context, config vc.VMConfig) (*vc.VM, error) {
	return f.base.GetBaseVM(ctx, config)
}

// CloseFactory closes the factory.
func (f *factory) CloseFactory(ctx context.Context) {
	f.base.CloseFactory(ctx)
}
