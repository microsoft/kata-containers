//go:build linux
// +build linux

/*
   Copyright The containerd Authors.
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

package main

import (
	"fmt"
	"os"
	"net"

	"google.golang.org/grpc"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/contrib/snapshotservice"

	"github.com/urfave/cli"

	"cc-snapshotter/snapshotter"
)

const usage = "cc-snapshotter stores image layers as ext4 filesystems with dmverity information"

func main() {
	app := cli.NewApp()
	app.Version = "v0.1"
	app.Name = "cc-snapshotter"
	app.Commands = []cli.Command {
		cli.Command {
			Name: "run",
			Usage: "run snapshotter using given config",
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "config,c",
					Usage:"Optional: Path to TOML configuration file",
					Required: false,
				},
			},
			Action: actionRunSnapshotter,
		},
		cli.Command {
			Name: "dir2tar",
			Usage: "convert directory to reproducible tar",
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "dir,d",
					Usage:"Required: Path to directory",
					Required: true,
				},
				cli.StringFlag {
					Name: "tar,t",
					Usage:"Required: Path to tar file",
					Required: true,
				},
			},
			Action: actionDirectoryToTar,
		},
		cli.Command {
			Name: "tar2disk",
			Usage: "convert tar file to ext4 file system disk with dmverity-metadata appended",
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "tar,t",
					Usage:"Required: Path to tar file",
					Required: true,
				},
				cli.StringFlag {
					Name: "disk,d",
					Usage:"Required: Path to disk file",
					Required: true,
				},
			},
			Action: actionTarToDiskImage,
		},
		cli.Command {
			Name: "pull",
			Usage: "pull image from repository",
			Flags: []cli.Flag {
				cli.StringFlag {
					Name: "image,i",
					Usage:"Required: Image reference",
					Required: true,
				},
				cli.StringFlag {
					Name: "storage-path, s",
					Usage:"Required: Image storage directory",
					Required: true,
				},
			},
			Action: actionPullImage,
		},
	}

	app.Usage = usage
	if err := app.Run(os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func actionRunSnapshotter(ctx *cli.Context) error {
	var config *snapshotter.Config

	// Fetch config path, if any.
	configPath := ctx.String("config")
	var err error
	if len(configPath) > 0 {
		config, err = snapshotter.LoadConfig(configPath)
		if err != nil {
			return err
		}
	} else {
		config = snapshotter.DefaultConfig()
	}

	rpc := grpc.NewServer()
	sn, err := snapshotter.NewSnapshotter(config)
	if err != nil {
		return fmt.Errorf("error: failed to create snapshotter: %v\n", err)
	}

	// Convert the snapshotter to a gRPC service,
	// example in github.com/containerd/containerd/contrib/snapshotservice
	service := snapshotservice.FromSnapshotter(sn)

	// Register the service with the gRPC server
	snapshotsapi.RegisterSnapshotsServer(rpc, service)

	// Listen and serve
	l, err := net.Listen("unix", config.SocketPath)
	if err != nil {
		return fmt.Errorf("error: failed to listen to socket. %w\n", err)
	}
	if err := rpc.Serve(l); err != nil {
		return fmt.Errorf("error: serving request failed. %w\n", err)
	}
	return nil
}

func actionDirectoryToTar(ctx *cli.Context) error {
	dirPath := ctx.String("dir")
	tarPath := ctx.String("tar")
	return snapshotter.DirectoryToTar(dirPath, tarPath)
}

func actionTarToDiskImage(ctx *cli.Context) error {
	tarPath := ctx.String("tar")
	diskImagePath := ctx.String("disk")
	rootHash, err := snapshotter.TarToDiskImage(tarPath, diskImagePath)
	if err != nil {
		return err
	}
	fmt.Printf("RootHash = %s\n", rootHash)
	return nil
}

func actionPullImage(ctx *cli.Context) error {
	imageRef := ctx.String("image")
	storagePath := ctx.String("storage-path")
	err := snapshotter.PullImage(imageRef, storagePath)
	if err != nil {
		return err
	}
	return nil
}
