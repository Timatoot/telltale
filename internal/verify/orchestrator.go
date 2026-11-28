package verify

import (
	"context"
	"errors"
	"slices"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/rules"
	"github.com/Timatoot/telltale/internal/sandbox"
)

// Session is the bounded transport shared by inventory and hypothesis sessions.
type Session interface {
	verifierSession
	ListTools(context.Context) ([]mcpclient.LiveTool, error)
	Close() error
}

type Runtime interface {
	Preflight(context.Context) (sandbox.RuntimeInfo, error)
	StartSession(context.Context, sandbox.SessionSpec) (Session, error)
	ForceCleanup(context.Context, string) error
}

// Podman adapts the existing create-inspect-start boundary without exposing a
// way for the orchestrator to start an uninspected container.
type Podman struct{ sandbox.ContainerRuntime }

func (p Podman) StartSession(ctx context.Context, spec sandbox.SessionSpec) (Session, error) {
	s, err := p.CreateSession(ctx, spec)
	if err != nil {
		// CreateSession wraps command cancellation in FatalError. The outer
		// session deadline or user cancellation is an ordinary run outcome.
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return s.Start(ctx)
}

type Orchestrator struct {
	Runtime       Runtime
	Info          sandbox.RuntimeInfo
	RunID, RunDir string
	// Abort releases session-close waits on the second signal. Run cleanup
	// still removes containers before releasing their fixture directories.
	Abort <-chan struct{}
}

func terminal(f *model.Finding, result VerificationResult) {
	if f.DynamicStatus != model.NotRun {
		return
	}
	f.DynamicStatus, f.DynamicReason = result.Status, result.Reason
	f.Evidence = slices.Concat(f.Evidence, result.Evidence)
}

func skipped(reason model.DynamicReason) VerificationResult {
	return VerificationResult{Status: model.Skipped, Reason: &reason}
}

// Run returns the canary only for the reporting redaction guard. Fixtures
// are released after container removal, and pending findings receive one outcome.
func (o Orchestrator) Run(ctx context.Context, cfg config.Config, scan *model.ScanReport, hypotheses []rules.VerificationHypothesis) (token string, err error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.VerifyBudget)
	defer cancel()
	scan.Coverage.RuntimeCoverage = &model.RuntimeCoverage{}
	var fixtures *sandbox.FixtureManager
	defer func() {
		fallback := verificationFailure(ctx, err)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fallback = skipped(model.BudgetExhausted)
		}
		for i := range scan.Findings {
			terminal(&scan.Findings[i], fallback)
		}
		cleanupErr := o.Runtime.ForceCleanup(context.WithoutCancel(ctx), o.RunID)
		err = errors.Join(err, cleanupErr)
		// Keep mounts intact if the runtime could not remove its containers.
		// The independent guard retries and owns the enclosing directory.
		if fixtures != nil && cleanupErr == nil {
			err = errors.Join(err, fixtures.Cleanup())
		}
	}()
	for i := range scan.Findings {
		if scan.Findings[i].ID == "CONTRACT-OPENWORLD-NETWORK" {
			terminal(&scan.Findings[i], VerificationResult{Status: model.NotApplicable})
		}
	}
	fixtures, err = sandbox.NewFixtureManager(o.RunDir)
	if err != nil {
		return "", err
	}
	token, err = fixtures.ContentToken()
	if err != nil {
		return "", err
	}
	live, inventoryErr := o.inventory(ctx, cfg, fixtures)
	if inventoryErr == nil {
		inventoryErr = (InventoryReconciler{}).Reconcile(ctx, scan, live)
	}
	if inventoryErr != nil {
		var fatal *sandbox.FatalError
		var local *fixtureError
		if errors.As(inventoryErr, &fatal) || errors.As(inventoryErr, &local) {
			return token, inventoryErr
		}
		outcome := verificationFailure(ctx, inventoryErr)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			outcome = skipped(model.BudgetExhausted)
		}
		for i := range scan.Findings {
			terminal(&scan.Findings[i], outcome)
		}
		// Even an empty static report must retain failed inventory coverage.
		scan.Coverage.ParseErrors = append(scan.Coverage.ParseErrors, model.ParseError{Engine: "mcp", Reason: string(*outcome.Reason)})
		return token, nil
	}
	byName := make(map[string]mcpclient.LiveTool, len(live))
	names := make(map[string]string, len(scan.Inventory))
	counts := make(map[string]int)
	for _, t := range live {
		byName[t.Name] = t
	}
	for _, t := range scan.Inventory {
		if t.SourceLocation != nil {
			names[t.ToolID] = t.Name
			counts[t.Name]++
		}
	}
	type key struct{ rule, tool, fingerprint string }
	findings := make(map[key][]int)
	for i, f := range scan.Findings {
		findings[key{f.ID, f.ToolID, f.Fingerprint}] = append(findings[key{f.ID, f.ToolID, f.Fingerprint}], i)
	}
	for _, h := range hypotheses {
		indices := findings[key{h.RuleID, h.ToolID, h.Fingerprint}]
		pending := false
		for _, i := range indices {
			pending = pending || scan.Findings[i].DynamicStatus == model.NotRun
		}
		if !pending {
			continue
		}
		var outcome VerificationResult
		name := names[h.ToolID]
		tool, found := byName[name]
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			outcome = skipped(model.BudgetExhausted)
		case ctx.Err() != nil:
			outcome = verificationFailure(ctx, ctx.Err())
		case counts[name] > 1:
			outcome = inconclusive(model.AmbiguousJoin)
		case !found:
			outcome = skipped(model.ToolNotLive)
		case h.RuleID == "FS-PATH-TRAVERSAL" && !cfg.HasWorkspaceClaim:
			outcome = skipped(model.NoWorkspaceClaim)
		default:
			outcome, err = o.hypothesis(ctx, cfg, fixtures, h, tool)
			if err != nil {
				return token, err
			}
		}
		for _, i := range indices {
			terminal(&scan.Findings[i], outcome)
		}
	}
	return token, nil
}

func (o Orchestrator) closeSession(s Session) error {
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		return err
	case <-o.Abort:
		return context.Canceled
	}
}

type fixtureError struct{ error }

func (o Orchestrator) inventory(ctx context.Context, cfg config.Config, fixtures *sandbox.FixtureManager) (live []mcpclient.LiveTool, err error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	workspace, err := fixtures.NewWorkspace()
	if err != nil {
		return nil, &fixtureError{err}
	}
	s, err := o.Runtime.StartSession(ctx, workspace.SessionSpec(o.Info, o.RunID, cfg.Timeout, cfg.RunCmdArgv))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, o.closeSession(s)) }()
	if err = s.Initialize(ctx); err == nil {
		live, err = s.ListTools(ctx)
	}
	return live, err
}

func (o Orchestrator) hypothesis(ctx context.Context, cfg config.Config, fixtures *sandbox.FixtureManager, h rules.VerificationHypothesis, tool mcpclient.LiveTool) (result VerificationResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	workspace, err := fixtures.NewWorkspace()
	if err != nil {
		return result, err
	}
	seeded, err := workspace.Snapshot(ctx)
	if err != nil {
		return verificationFailure(ctx, err), nil
	}
	s, err := o.Runtime.StartSession(ctx, workspace.SessionSpec(o.Info, o.RunID, cfg.Timeout, cfg.RunCmdArgv))
	if err != nil {
		var fatal *sandbox.FatalError
		if errors.As(err, &fatal) {
			return result, err
		}
		return verificationFailure(ctx, err), nil
	}
	defer func() {
		closeErr := o.closeSession(s)
		var fatal *sandbox.FatalError
		if errors.As(closeErr, &fatal) {
			err = errors.Join(err, closeErr)
		}
	}()
	switch h.RuleID {
	case "FS-PATH-TRAVERSAL":
		return (FSVerifier{}).Verify(s, cfg, fixtures, tool, h.TaintedParameter)
	default:
		return (ContractVerifier{}).Verify(s, workspace, seeded, h.RuleID, tool), nil
	}
}
