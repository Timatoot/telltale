package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/sandbox"
)

type contractPeer struct {
	ctx  context.Context
	init func() error
	call func(string, map[string]any) (mcpclient.CallResult, error)
}

func (p contractPeer) Context() context.Context         { return p.ctx }
func (p contractPeer) Initialize(context.Context) error { return p.init() }
func (p contractPeer) CallTool(_ context.Context, name string, args map[string]any) (mcpclient.CallResult, error) {
	return p.call(name, args)
}

func TestContractVerifier(t *testing.T) {
	const readOnly = "CONTRACT-READONLY-WRITE"
	const destructive = "CONTRACT-DESTRUCTIVE-MUTATION"
	type mutation func(workspace, seed string) error
	add := func(dir, _ string) error { return os.WriteFile(filepath.Join(dir, "output"), []byte("ok"), 0o600) }
	overwrite := func(_, seed string) error { return os.WriteFile(seed, []byte("new"), 0o600) }
	remove := func(_, seed string) error { return os.Remove(seed) }
	chmod := func(_, seed string) error { return os.Chmod(seed, 0o400) }
	touch := func(_, seed string) error { return os.Chtimes(seed, time.Unix(42, 0), time.Unix(42, 0)) }
	replace := func(_, seed string) error {
		if err := os.Remove(seed); err != nil {
			return err
		}
		return os.Mkdir(seed, 0o700)
	}
	for _, tc := range []struct {
		name, rule string
		mutate     mutation
		isError    bool
		callErr    error
		status     model.DynamicStatus
		reason     model.DynamicReason
	}{
		{"write", readOnly, add, false, nil, model.Confirmed, ""},
		{"delete", destructive, remove, false, nil, model.Confirmed, ""},
		{"overwrite", destructive, overwrite, false, nil, model.Confirmed, ""},
		{"replace type", destructive, replace, false, nil, model.Confirmed, ""},
		{"add only", destructive, add, false, nil, model.NotReproduced, ""},
		{"timestamps", readOnly, touch, false, nil, model.NotReproduced, ""},
		{"permissions", readOnly, chmod, false, nil, model.Confirmed, ""},
		{"preserve content", destructive, chmod, false, nil, model.NotReproduced, ""},
		{"error without diff", readOnly, nil, true, nil, model.Inconclusive, model.ToolError},
		{"rpc error without diff", readOnly, nil, false, &mcpclient.RPCError{}, model.Inconclusive, model.ToolError},
		{"rpc error after overwrite", destructive, overwrite, false, &mcpclient.RPCError{}, model.Confirmed, ""},
		{"noisy baseline", readOnly, nil, false, nil, model.Inconclusive, model.NoisyWorkspace},
		{"watchdog during settle", readOnly, add, false, nil, model.Inconclusive, model.ResourceLimit},
		{"server crash", readOnly, nil, false, mcpclient.ErrServerCrash, model.Inconclusive, model.ServerCrash},
		{"timeout", readOnly, nil, false, mcpclient.ErrTimeout, model.Inconclusive, model.Timeout},
		{"protocol error", readOnly, nil, false, mcpclient.ErrProtocolViolation, model.Inconclusive, model.ProtocolViolation},
		{"handshake failure", readOnly, nil, false, nil, model.Inconclusive, model.HandshakeFailed},
		{"unsupported schema", readOnly, nil, false, nil, model.Inconclusive, model.UnsupportedSchema},
		{"remove startup file", destructive, func(dir, _ string) error { return os.Remove(filepath.Join(dir, "output")) }, false, nil, model.NotReproduced, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixtures, err := sandbox.NewFixtureManager(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixtures.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			workspace, err := fixtures.NewWorkspace()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			seeded, err := workspace.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			dir := workspace.Workspace()
			var events []string
			peer := contractPeer{ctx: ctx, init: func() error {
				events = append(events, "initialize")
				switch tc.name {
				case "handshake failure":
					return mcpclient.ErrHandshakeFailed
				case "remove startup file":
					return add(dir, "")
				}
				return nil
			}, call: func(name string, args map[string]any) (mcpclient.CallResult, error) {
				events = append(events, "call")
				if name != "preview" || args["path"] != "/workspace/seed/notes.txt" {
					t.Fatalf("unexpected call %q %v", name, args)
				}
				if tc.mutate != nil {
					if err := tc.mutate(dir, filepath.Join(dir, "seed", "notes.txt")); err != nil {
						t.Fatal(err)
					}
				}
				return mcpclient.CallResult{IsError: tc.isError}, tc.callErr
			}}
			v := ContractVerifier{wait: func(ctx context.Context, d time.Duration) error {
				events = append(events, d.String())
				if tc.name == "noisy baseline" && d == 500*time.Millisecond {
					return add(dir, "")
				}
				if tc.name == "watchdog during settle" && d == time.Second {
					cancel(sandbox.ErrResourceLimit)
				}
				return ctx.Err()
			}}
			tool := mcpclient.LiveTool{Name: "preview", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)}
			if tc.name == "unsupported schema" {
				tool.InputSchema = json.RawMessage(`{"oneOf":[]}`)
			}
			out := v.Verify(peer, workspace, seeded, tc.rule, tool)
			if out.Status != tc.status || (tc.reason == "") != (out.Reason == nil) || (out.Reason != nil && *out.Reason != tc.reason) {
				t.Fatalf("unexpected outcome %+v, want %s %s", out, tc.status, tc.reason)
			}
			if out.Status == model.Confirmed && (len(out.Evidence) != 1 || out.Evidence[0].Source != model.SourceSandboxFS) {
				t.Fatalf("missing observation %+v", out)
			}
			want := []string{"initialize", "500ms", "call", "1s"}
			switch tc.reason {
			case model.HandshakeFailed:
				want = want[:1]
			case model.NoisyWorkspace, model.UnsupportedSchema:
				want = want[:2]
			case model.ServerCrash, model.Timeout, model.ProtocolViolation:
				want = want[:3]
			}
			if !slices.Equal(events, want) {
				t.Fatalf("events %v, want %v", events, want)
			}
		})
	}
}
