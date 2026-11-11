// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import "context"

func (s *service) teardownSandbox(ctx context.Context) {
	if s.sandbox == nil {
		return
	}

	s.teardownOnce.Do(func() {
		ctx = context.WithoutCancel(ctx)
		if err := s.sandbox.Stop(ctx, true); err != nil {
			shimLog.WithError(err).WithField("sandbox", s.sandbox.ID()).Error("failed to stop sandbox")
		}
		if err := s.sandbox.Delete(ctx); err != nil {
			shimLog.WithError(err).WithField("sandbox", s.sandbox.ID()).Error("failed to delete sandbox")
		}
	})
}
