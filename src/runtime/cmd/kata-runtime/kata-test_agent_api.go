package main

import (
	"encoding/json"
	"fmt"
	"os"
	containerdshim "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/utils/shimclient"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/urfave/cli"
)

// Debug Agent Ttrpc Api's by communicating with shim_management server
// Create a Ttrpc API Call Request from provided inputs.
// Total No of exposed agent API's = 38

// Makes sense to make each Agent Api a subcommand
var agentApiSubCmds = []cli.Command{
	copyFileTestCommand,
	setPolicyTestCommand,
}

var kataTestAgentApiCommand = cli.Command{
	Name:		"test-agent-api",
	Usage:		"test agent Ttrpc APIs",
	Subcommands:	agentApiSubCmds,
	Action:		func(context *cli.Context) {
			cli.ShowSubcommandHelp(context)
	},
}

var copyFileTestCommand = cli.Command{
	Name:		"copyFile",
	Usage:		"copyFile <sandbox-id> <src path> <dest path>",
	Description:	"Test CopyFileRequest Api",
	Action:		func(c *cli.Context) error {
			if !c.Args().Present() {
				return fmt.Errorf("copyFile: excepts 3 arguments, see usage")
			}

			sandboxId := c.Args().Get(0)
			source := c.Args().Get(1)
			destination := c.Args().Get(2)

			if err := katautils.VerifyContainerID(sandboxId); err != nil {
				return err
			}

			req := vc.TtrpcTestReq{
				Api: "CopyFileRequest",
				SandboxID: sandboxId,
				Params: vc.CopyFileReq{
					Src: source,
					Dest: destination,
				},
			}

			encoded, err := json.Marshal(req)
			if err != nil {
				return err
			}

			return shimclient.DoPost(sandboxId, defaultTimeout, containerdshim.TestAgentTtrpcUrl, "application/json", encoded)
	},
}

var setPolicyTestCommand = cli.Command{
	Name:		"setPolicy",
	Usage:          "setPolicy <sandbox-id> <policy file>",
	Description:    "Test SetPolicyRequest Api",
	Action:         func(c *cli.Context) error {
			if !c.Args().Present() {
				return fmt.Errorf("setPolicy: expects 2 arguments, see usage")
			}

			sandboxId := c.Args().Get(0)
			policyFile := c.Args().Get(1)

			if err := katautils.VerifyContainerID(sandboxId); err != nil {
				return err
			}

			if policyFile == "" {
				return fmt.Errorf("setPolicy: policy file not provided")
			}

			if !katautils.FileExists(policyFile) {
				return fmt.Errorf("setPolicy: policy file does not exist: %s", policyFile)
			}

			// Read file into buffer, and make request to the appropriate shim
			buf, err := os.ReadFile(policyFile)
			if err != nil {
				return err
			}

			req := vc.TtrpcTestReq{
				Api: "SetPolicyRequest",
				SandboxID: sandboxId,
				Params: vc.SetPolicyReq{
					Buf: buf,
				},
			}

			encoded, err := json.Marshal(req)
			if err != nil {
				return err
			}

			return shimclient.DoPost(sandboxId, defaultTimeout, containerdshim.TestAgentTtrpcUrl, "application/json", encoded)
	},
}
