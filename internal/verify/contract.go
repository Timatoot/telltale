package verify

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/sandbox"
)

type verifierSession interface {
	Context() context.Context
	Initialize(context.Context) error
	CallTool(context.Context, string, map[string]any) (mcpclient.CallResult, error)
}

var _ verifierSession = (*sandbox.StdioSession)(nil)

// ContractVerifier observes a single ordinary tool call in an isolated workspace.
type ContractVerifier struct {
	wait func(context.Context, time.Duration) error // test clock
}

type VerificationResult struct {
	Status   model.DynamicStatus
	Reason   *model.DynamicReason
	Evidence []model.EvidenceItem
}

func inconclusive(reason model.DynamicReason) VerificationResult {
	return VerificationResult{Status: model.Inconclusive, Reason: &reason}
}

func verificationFailure(ctx context.Context, err error) VerificationResult {
	err = errors.Join(context.Cause(ctx), err)
	switch {
	case errors.Is(err, sandbox.ErrResourceLimit):
		return inconclusive(model.ResourceLimit)
	case errors.Is(err, sandbox.ErrUnstableWorkspace):
		return inconclusive(model.NoisyWorkspace)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, mcpclient.ErrTimeout):
		return inconclusive(model.Timeout)
	case errors.Is(err, mcpclient.ErrResponseTruncated):
		return inconclusive(model.ResponseTruncated)
	case errors.Is(err, mcpclient.ErrProtocolViolation):
		return inconclusive(model.ProtocolViolation)
	case errors.Is(err, mcpclient.ErrHandshakeFailed):
		return inconclusive(model.HandshakeFailed)
	default:
		return inconclusive(model.ServerCrash)
	}
}

func waitWindow(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-time.After(d):
		return nil
	}
}

// Verify evaluates the rule selected by the static hypothesis. seeded is the
// snapshot of the fresh fixture before the server starts, so files created
// during the handshake do not become protected seeds.
func (v ContractVerifier) Verify(session verifierSession, workspace sandbox.SessionFixtures, seeded sandbox.WorkspaceSnapshot, ruleID string, tool mcpclient.LiveTool) VerificationResult {
	const readOnly = "CONTRACT-READONLY-WRITE"
	if ruleID != readOnly && ruleID != "CONTRACT-DESTRUCTIVE-MUTATION" {
		return VerificationResult{Status: model.NotApplicable}
	}
	if ruleID != readOnly && len(seeded) == 0 {
		return inconclusive(model.NoisyWorkspace)
	}
	ctx := session.Context()
	wait := v.wait
	if wait == nil {
		wait = waitWindow
	}
	if err := session.Initialize(ctx); err != nil {
		return verificationFailure(ctx, err)
	}
	initial, err := workspace.Snapshot(ctx)
	if err != nil {
		return verificationFailure(ctx, err)
	}
	if err := wait(ctx, 500*time.Millisecond); err != nil {
		return verificationFailure(ctx, err)
	}
	before, err := workspace.Snapshot(ctx)
	if err != nil {
		return verificationFailure(ctx, err)
	}
	if !maps.Equal(initial, before) {
		return inconclusive(model.NoisyWorkspace)
	}
	args, err := SynthesizeArgs(tool.InputSchema, "", "")
	if err != nil {
		return inconclusive(model.UnsupportedSchema)
	}
	reply, callErr := session.CallTool(ctx, tool.Name, args)
	var rpcErr *mcpclient.RPCError
	if callErr != nil && !errors.As(callErr, &rpcErr) {
		return verificationFailure(ctx, callErr)
	}
	if err := wait(ctx, time.Second); err != nil {
		return verificationFailure(ctx, err)
	}
	after, err := workspace.Snapshot(ctx)
	if err != nil || ctx.Err() != nil {
		return verificationFailure(ctx, err)
	}
	diff := before.Diff(after)
	changed := len(diff.Added)+len(diff.Removed)+len(diff.Changed) > 0
	if changed && (ruleID == readOnly || damagedSeed(before, after, seeded)) {
		detail := fmt.Sprintf("Workspace entries added %d, removed %d, changed %d", len(diff.Added), len(diff.Removed), len(diff.Changed))
		return VerificationResult{Status: model.Confirmed, Evidence: []model.EvidenceItem{{
			Kind: model.EvidenceObserved, Source: model.SourceSandboxFS, Detail: detail,
		}}}
	}
	if reply.IsError || callErr != nil {
		return inconclusive(model.ToolError)
	}
	return VerificationResult{Status: model.NotReproduced}
}

func damagedSeed(before, after, seeded sandbox.WorkspaceSnapshot) bool {
	for name := range seeded {
		old, existed := before[name]
		if !existed {
			continue
		}
		now, exists := after[name]
		if !exists || old.Mode.Type() != now.Mode.Type() || old.Size != now.Size ||
			old.SHA256 != now.SHA256 || old.LinkTarget != now.LinkTarget {
			return true
		}
	}
	return false
}
