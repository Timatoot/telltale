package verify

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/rules"
	"github.com/Timatoot/telltale/internal/sandbox"
)

type orchestrationRuntime struct {
	start   func(context.Context, sandbox.SessionSpec) (Session, error)
	cleanup func(context.Context, string) error
}

func (r orchestrationRuntime) Preflight(context.Context) (sandbox.RuntimeInfo, error) {
	return sandbox.RuntimeInfo{}, nil
}
func (r orchestrationRuntime) StartSession(ctx context.Context, spec sandbox.SessionSpec) (Session, error) {
	return r.start(ctx, spec)
}
func (r orchestrationRuntime) ForceCleanup(ctx context.Context, id string) error {
	return r.cleanup(ctx, id)
}

type orchestrationSession struct {
	ctx     context.Context
	tools   []mcpclient.LiveTool
	initErr error
	call    func(string, map[string]any) (mcpclient.CallResult, error)
	close   func() error
}

func (s orchestrationSession) Context() context.Context         { return s.ctx }
func (s orchestrationSession) Initialize(context.Context) error { return s.initErr }
func (s orchestrationSession) ListTools(context.Context) ([]mcpclient.LiveTool, error) {
	return s.tools, nil
}
func (s orchestrationSession) CallTool(_ context.Context, name string, args map[string]any) (mcpclient.CallResult, error) {
	return s.call(name, args)
}
func (s orchestrationSession) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}

func orchestrationReport(ids ...string) (model.ScanReport, []rules.VerificationHypothesis) {
	scan := model.ScanReport{Inventory: []model.ToolFact{{ToolID: "tool", Name: "read", Parameters: []model.Parameter{{Name: "path", DescriptionResolved: true}}, SourceLocation: &model.Location{Path: "s.py", StartLine: 1}, DescriptionResolved: true}}}
	var hypotheses []rules.VerificationHypothesis
	for _, id := range ids {
		f, _ := rules.FindingMetadata(id)
		f.ToolID, f.Fingerprint, f.Origin = "tool", id, model.OriginStatic
		f.StaticStatus, f.DynamicStatus = model.Suspected, model.NotRun
		scan.Findings = append(scan.Findings, f)
		if id != "CONTRACT-OPENWORLD-NETWORK" {
			hypotheses = append(hypotheses, rules.VerificationHypothesis{RuleID: id, ToolID: "tool", Fingerprint: id, TaintedParameter: "path"})
		}
	}
	return scan, hypotheses
}
func orchestrationTool() mcpclient.LiveTool {
	return mcpclient.LiveTool{Name: "read", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)}
}
func orchestrationConfig() config.Config {
	return config.Config{Verify: true, HasWorkspaceClaim: true, Timeout: time.Second, VerifyBudget: 5 * time.Second}
}

func TestOrchestratorOutcomesAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status model.DynamicStatus
		reason model.DynamicReason
	}{
		{"negative", model.NotReproduced, ""},
		{"not live", model.Skipped, model.ToolNotLive},
		{"no claim", model.Skipped, model.NoWorkspaceClaim},
		{"budget", model.Skipped, model.BudgetExhausted},
		{"crash", model.Inconclusive, model.ServerCrash},
		{"cancel", model.Inconclusive, model.ServerCrash},
		{"timeout", model.Inconclusive, model.Timeout},
		{"inventory crash", model.Inconclusive, model.ServerCrash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			scan, hypotheses := orchestrationReport("FS-PATH-TRAVERSAL", "CONTRACT-OPENWORLD-NETWORK")
			// Duplicate hypotheses must never call or transition a terminal finding again.
			hypotheses = append(hypotheses, hypotheses...)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := orchestrationConfig()
			if tc.name == "no claim" {
				cfg.HasWorkspaceClaim = false
			}
			if tc.name == "budget" {
				cfg.VerifyBudget = time.Nanosecond
			}
			var starts, calls, closes, cleanups int
			runtime := orchestrationRuntime{
				start: func(ctx context.Context, _ sandbox.SessionSpec) (Session, error) {
					starts++
					if tc.name == "inventory crash" {
						return nil, mcpclient.ErrServerCrash
					}
					tools := []mcpclient.LiveTool{orchestrationTool()}
					if tc.name == "not live" {
						tools = nil
					}
					return orchestrationSession{ctx: ctx, tools: tools, call: func(_ string, args map[string]any) (mcpclient.CallResult, error) {
						calls++
						switch tc.name {
						case "crash":
							return mcpclient.CallResult{}, mcpclient.ErrServerCrash
						case "cancel":
							cancel()
							return mcpclient.CallResult{}, ctx.Err()
						case "timeout":
							return mcpclient.CallResult{}, mcpclient.ErrTimeout
						}
						return mcpclient.CallResult{}, nil
					}, close: func() error { closes++; return nil }}, nil
				},
				cleanup: func(ctx context.Context, id string) error {
					cleanups++
					if ctx.Err() != nil || id != "run" {
						t.Fatal("cleanup canceled or wrong run")
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 1 {
						t.Fatalf("fixtures removed before containers: %v %v", entries, err)
					}
					return nil
				},
			}
			token, err := (Orchestrator{Runtime: runtime, RunID: "run", RunDir: dir}).Run(ctx, cfg, &scan, hypotheses)
			if err != nil || len(token) != 64 || cleanups != 1 || closes != starts && tc.name != "inventory crash" {
				t.Fatalf("run: %v, starts=%d closes=%d cleanups=%d", err, starts, closes, cleanups)
			}
			for _, f := range scan.Findings {
				if f.StaticStatus != model.Suspected {
					t.Fatal("static status changed")
				}
				want := tc.status
				if f.ID == "CONTRACT-OPENWORLD-NETWORK" {
					want = model.NotApplicable
				}
				if f.DynamicStatus != want {
					t.Fatalf("%s: %+v", tc.name, f)
				}
				if f.ID == "FS-PATH-TRAVERSAL" && tc.reason != "" && (f.DynamicReason == nil || *f.DynamicReason != tc.reason) {
					t.Fatalf("reason: %+v", f)
				}
			}
			if tc.name == "negative" && (calls != 10 || starts != 2) {
				t.Fatalf("duplicate execution: calls=%d starts=%d", calls, starts)
			}
			scan.ApplyPolicy(model.Policy{Verify: true, Strict: true})
			if scan.Summary.AnalysisExitCode != 1 {
				t.Fatal("verification downgraded policy")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("fixture leak %v %v", entries, err)
			}
		})
	}
}

func TestOrchestratorFreshSessionsAndPositiveOracle(t *testing.T) {
	dir := t.TempDir()
	scan, h := orchestrationReport("CONTRACT-READONLY-WRITE", "FS-PATH-TRAVERSAL")
	cfg := orchestrationConfig()
	cfg.Timeout = 3 * time.Second
	var workspaces []string
	var active bool
	runtime := orchestrationRuntime{
		start: func(ctx context.Context, _ sandbox.SessionSpec) (Session, error) {
			if active {
				t.Fatal("sessions overlap")
			}
			active = true
			fixtures, err := filepath.Glob(filepath.Join(dir, "fixtures-*"))
			if err != nil || len(fixtures) != 1 {
				t.Fatal(fixtures, err)
			}
			dirs, err := filepath.Glob(filepath.Join(fixtures[0], "workspace-*"))
			if err != nil {
				t.Fatal(err)
			}
			var workspace string
			for _, d := range dirs {
				if !slices.Contains(workspaces, d) {
					workspace = d
				}
			}
			if workspace == "" {
				t.Fatal("workspace reused")
			}
			workspaces = append(workspaces, workspace)
			return orchestrationSession{ctx: ctx, tools: []mcpclient.LiveTool{orchestrationTool()}, close: func() error { active = false; return nil }, call: func(_ string, args map[string]any) (mcpclient.CallResult, error) {
				if len(workspaces) == 2 {
					return mcpclient.CallResult{}, os.WriteFile(filepath.Join(workspace, "changed"), []byte("mutation"), 0o600)
				}
				canaries, err := filepath.Glob(filepath.Join(fixtures[0], "restricted", "*"))
				if err != nil || len(canaries) != 1 {
					t.Fatal(canaries, err)
				}
				token, err := os.ReadFile(canaries[0])
				return mcpclient.CallResult{RawFrame: token}, err
			}}, nil
		},
		cleanup: func(context.Context, string) error {
			if active {
				t.Fatal("session still active")
			}
			return nil
		},
	}
	token, err := (Orchestrator{Runtime: runtime, RunDir: dir, RunID: "run"}).Run(t.Context(), cfg, &scan, h)
	if err != nil || len(workspaces) != 3 {
		t.Fatalf("run: %v, workspaces=%v", err, workspaces)
	}
	for _, f := range scan.Findings {
		if f.DynamicStatus != model.Confirmed || len(f.Evidence) == 0 {
			t.Fatalf("missing oracle: %+v", f)
		}
		raw, _ := json.Marshal(f)
		if strings.Contains(string(raw), token) {
			t.Fatal("canary in evidence")
		}
	}
}

func TestOrchestratorCleanupFailurePreservesMounts(t *testing.T) {
	dir := t.TempDir()
	scan, h := orchestrationReport("FS-PATH-TRAVERSAL")
	failure := errors.New("runtime removal failed")
	runtime := orchestrationRuntime{start: func(context.Context, sandbox.SessionSpec) (Session, error) { return nil, mcpclient.ErrServerCrash }, cleanup: func(context.Context, string) error { return failure }}
	_, err := (Orchestrator{Runtime: runtime, RunDir: dir, RunID: "run"}).Run(t.Context(), orchestrationConfig(), &scan, h)
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	dirs, err := os.ReadDir(dir)
	if err != nil || len(dirs) != 1 {
		t.Fatal("mounts removed after failed cleanup", err)
	}
	// Test-owned cleanup of the intentionally retained sealed directory.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.Chmod(dirs[0].Name()+"/restricted", 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestOrchestratorBudgetAfterInventory(t *testing.T) {
	scan, h := orchestrationReport("FS-PATH-TRAVERSAL")
	cfg := orchestrationConfig()
	cfg.VerifyBudget = 20 * time.Millisecond
	starts := 0
	runtime := orchestrationRuntime{
		start: func(ctx context.Context, _ sandbox.SessionSpec) (Session, error) {
			starts++
			return orchestrationSession{ctx: ctx, tools: []mcpclient.LiveTool{orchestrationTool()}, close: func() error { <-ctx.Done(); return nil }}, nil
		},
		cleanup: func(context.Context, string) error { return nil },
	}
	_, err := (Orchestrator{Runtime: runtime, RunID: "run", RunDir: t.TempDir()}).Run(t.Context(), cfg, &scan, h)
	if err != nil || starts != 1 || scan.Findings[0].DynamicStatus != model.Skipped || *scan.Findings[0].DynamicReason != model.BudgetExhausted {
		t.Fatalf("budget: %v %+v starts=%d", err, scan.Findings, starts)
	}
}

func TestOrchestratorAbortCloseAndFatalIsolation(t *testing.T) {
	t.Run("abort", func(t *testing.T) {
		scan, h := orchestrationReport("FS-PATH-TRAVERSAL")
		abort := make(chan struct{})
		release := make(chan struct{})
		closed := make(chan struct{})
		cleaned := false
		runtime := orchestrationRuntime{
			start: func(ctx context.Context, _ sandbox.SessionSpec) (Session, error) {
				return orchestrationSession{ctx: ctx, tools: []mcpclient.LiveTool{orchestrationTool()}, close: func() error { close(abort); <-release; close(closed); return nil }}, nil
			},
			cleanup: func(ctx context.Context, _ string) error { cleaned = true; close(release); return ctx.Err() },
		}
		_, err := (Orchestrator{Runtime: runtime, RunID: "run", RunDir: t.TempDir(), Abort: abort}).Run(t.Context(), orchestrationConfig(), &scan, h)
		if err != nil || !cleaned {
			t.Fatal(err, cleaned)
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("close leaked")
		}
	})
	t.Run("isolation", func(t *testing.T) {
		_, fatal := (sandbox.ContainerRuntime{}).Preflight(t.Context())
		scan, h := orchestrationReport("FS-PATH-TRAVERSAL")
		cleaned := false
		runtime := orchestrationRuntime{
			start:   func(context.Context, sandbox.SessionSpec) (Session, error) { return nil, fatal },
			cleanup: func(context.Context, string) error { cleaned = true; return nil },
		}
		_, err := (Orchestrator{Runtime: runtime, RunID: "run", RunDir: t.TempDir()}).Run(t.Context(), orchestrationConfig(), &scan, h)
		if !errors.Is(err, fatal) || !cleaned {
			t.Fatal(err, cleaned)
		}
	})
}

func TestOrchestratorFailedEmptyInventoryCoverage(t *testing.T) {
	scan := model.ScanReport{}
	runtime := orchestrationRuntime{
		start:   func(context.Context, sandbox.SessionSpec) (Session, error) { return nil, mcpclient.ErrHandshakeFailed },
		cleanup: func(context.Context, string) error { return nil },
	}
	_, err := (Orchestrator{Runtime: runtime, RunID: "run", RunDir: t.TempDir()}).Run(t.Context(), orchestrationConfig(), &scan, nil)
	scan.ApplyPolicy(model.Policy{Verify: true, Strict: true})
	if err != nil || len(scan.Findings) != 0 || scan.Summary.AnalysisExitCode != 3 || len(scan.Coverage.ParseErrors) != 1 || scan.Coverage.ParseErrors[0].Engine != "mcp" {
		t.Fatalf("empty failed inventory: %v %+v", err, scan)
	}
}

func TestOrchestratorPreservesConfirmationWhenBudgetExpires(t *testing.T) {
	dir := t.TempDir()
	scan, h := orchestrationReport("FS-PATH-TRAVERSAL", "FS-PATH-TRAVERSAL")
	scan.Findings[1].Fingerprint = "second"
	h[1].Fingerprint = "second"
	cfg := orchestrationConfig()
	cfg.VerifyBudget = 50 * time.Millisecond
	starts := 0
	runtime := orchestrationRuntime{
		start: func(ctx context.Context, _ sandbox.SessionSpec) (Session, error) {
			starts++
			inventory := starts == 1
			return orchestrationSession{ctx: ctx, tools: []mcpclient.LiveTool{orchestrationTool()}, call: func(string, map[string]any) (mcpclient.CallResult, error) {
				files, err := filepath.Glob(filepath.Join(dir, "fixtures-*", "restricted", "*"))
				if err != nil || len(files) != 1 {
					t.Fatal(files, err)
				}
				token, err := os.ReadFile(files[0]) //nolint:gosec // Private fixture canary under the test directory.
				return mcpclient.CallResult{RawFrame: token}, err
			}, close: func() error {
				if !inventory {
					<-ctx.Done()
				}
				return nil
			}}, nil
		},
		cleanup: func(context.Context, string) error { return nil },
	}
	_, err := (Orchestrator{Runtime: runtime, RunID: "run", RunDir: dir}).Run(t.Context(), cfg, &scan, h)
	if err != nil || starts != 2 {
		t.Fatalf("run: %v, starts=%d", err, starts)
	}
	for _, f := range scan.Findings {
		if f.Fingerprint == "second" {
			if f.DynamicStatus != model.Skipped || f.DynamicReason == nil || *f.DynamicReason != model.BudgetExhausted {
				t.Fatalf("remaining finding: %+v", f)
			}
		} else if f.DynamicStatus != model.Confirmed || f.StaticStatus != model.Suspected {
			t.Fatalf("confirmation lost: %+v", f)
		}
	}
}
