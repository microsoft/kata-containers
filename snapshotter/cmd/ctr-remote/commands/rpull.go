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

package commands

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/cmd/ctr/commands/content"
	containerdimages "github.com/containerd/containerd/images"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/log"

	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	
	"github.com/urfave/cli"
)

var RpullCommand = cli.Command{
	Name:      "rpull",
	Usage:     "pull an image from a registry leveraging cc-snapshotter",
	ArgsUsage: "[flags] <ref>",
	Description: "Fetch an image using cc-snapshotter",
	Flags: append(commands.RegistryFlags, commands.LabelFlag),
	Action: func(context *cli.Context) error {
		ref := context.Args().First()
		if ref == "" {
			return fmt.Errorf("please provide an image reference to pull")
		}

		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		ctx, done, err := client.WithLease(ctx)
		if err != nil {
			return err
		}
		defer done(ctx)

		fc, err := content.NewFetchConfig(ctx, context)
		if err != nil {
			return err
		}

		return pull(ctx, client, ref, fc)
	},
}

func pull(ctx context.Context, client *containerd.Client, ref string, config *content.FetchConfig) error {
	pCtx := ctx
	h := containerdimages.HandlerFunc(func(ctx context.Context, desc imagespec.Descriptor) ([]imagespec.Descriptor, error) {
		if desc.MediaType != containerdimages.MediaTypeDockerSchema1Manifest {
			fmt.Printf("fetching %v... %v\n", desc.Digest.String()[:15], desc.MediaType)
		}
		return nil, nil
	})

	log.G(pCtx).WithField("image", ref).Debug("fetching")
	labels := commands.LabelArgs(config.Labels)
	if _, err := client.Pull(pCtx, ref, []containerd.RemoteOpt{
		containerd.WithPullLabels(labels),
		containerd.WithResolver(config.Resolver),
		containerd.WithImageHandler(h),
		containerd.WithSchema1Conversion,
		containerd.WithPullUnpack,
		containerd.WithPullSnapshotter("cc-snapshotter"),
		containerd.WithImageHandlerWrapper(appendInfoHandlerWrapper(ref)),
	}...); err != nil {
		return err
	}

	return nil
}

const (
	// targetRefLabel is a label which contains image reference and will be passed
	// to snapshotters.
	targetRefLabel = "containerd.io/snapshot/cri.image-ref"
	// targetManifestDigestLabel is a label which contains manifest digest and will be passed
	// to snapshotters.
	targetManifestDigestLabel = "containerd.io/snapshot/cri.manifest-digest"
	// targetLayerDigestLabel is a label which contains layer digest and will be passed
	// to snapshotters.
	targetLayerDigestLabel = "containerd.io/snapshot/cri.layer-digest"
	// targetImageLayersLabel is a label which contains layer digests contained in
	// the target image and will be passed to snapshotters for preparing layers in
	// parallel. Skipping some layers is allowed and only affects performance.
	targetImageLayersLabel = "containerd.io/snapshot/cri.image-layers"
)

// appendInfoHandlerWrapper makes a handler which appends some basic information
// of images like digests for manifest and their child layers as annotations during unpack.
// These annotations will be passed to snapshotters as labels. These labels will be
// used mainly by stargz-based snapshotters for querying image contents from the
// registry.
func appendInfoHandlerWrapper(ref string) func(f containerdimages.Handler) containerdimages.Handler {
	return func(f containerdimages.Handler) containerdimages.Handler {
		return containerdimages.HandlerFunc(func(ctx context.Context, desc imagespec.Descriptor) ([]imagespec.Descriptor, error) {
			children, err := f.Handle(ctx, desc)
			if err != nil {
				return nil, err
			}
			switch desc.MediaType {
			case imagespec.MediaTypeImageManifest, containerdimages.MediaTypeDockerSchema2Manifest:
				for i := range children {
					c := &children[i]
					if containerdimages.IsLayerType(c.MediaType) {
						if c.Annotations == nil {
							c.Annotations = make(map[string]string)
						}
						c.Annotations[targetRefLabel] = ref
						c.Annotations[targetLayerDigestLabel] = c.Digest.String()
						c.Annotations[targetImageLayersLabel] = getLayers(ctx, targetImageLayersLabel, children[i:], labels.Validate)
						c.Annotations[targetManifestDigestLabel] = desc.Digest.String()
					}
				}
			}
			return children, nil
		})
	}
}

// getLayers returns comma-separated digests based on the passed list of
// descriptors. The returned list contains as many digests as possible as well
// as meets the label validation.
func getLayers(ctx context.Context, key string, descs []imagespec.Descriptor, validate func(k, v string) error) (layers string) {
	var item string
	for _, l := range descs {
		if containerdimages.IsLayerType(l.MediaType) {
			item = l.Digest.String()
			if layers != "" {
				item = "," + item
			}
			// This avoids the label hits the size limitation.
			if err := validate(key, layers+item); err != nil {
				log.G(ctx).WithError(err).WithField("label", key).Debugf("%q is omitted in the layers list", l.Digest.String())
				break
			}
			layers += item
		}
	}
	return
}
