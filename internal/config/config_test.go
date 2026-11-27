package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseValidCombinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, cfg Config)
	}{
		{
			name: "minimal static audit",
			args: []string{"audit", "./repo"},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.RepoPath != "./repo" {
					t.Fatalf("RepoPath = %q, want %q", cfg.RepoPath, "./repo")
				}
				if cfg.FailOn != DefaultFailOn {
					t.Fatalf("FailOn = %q, want %q", cfg.FailOn, DefaultFailOn)
				}
				if cfg.Timeout != DefaultTimeout {
					t.Fatalf("Timeout = %s, want %s", cfg.Timeout, DefaultTimeout)
				}
				if cfg.VerifyBudget != DefaultVerifyBudget {
					t.Fatalf("VerifyBudget = %s, want %s", cfg.VerifyBudget, DefaultVerifyBudget)
				}
				if cfg.Verify || cfg.Strict || cfg.VerifiedOnly || cfg.NoColor || cfg.HasWorkspaceClaim {
					t.Fatalf("unexpected boolean defaults: %+v", cfg)
				}
			},
		},
		{
			name: "flags after repo path",
			args: []string{
				"audit", "/tmp/my-mcp",
				"--json", "out.json",
				"--sarif", "out.sarif",
				"--html", "out.html",
				"--no-color",
				"--fail-on", "medium",
				"--verified-only",
				"--strict",
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.RepoPath != "/tmp/my-mcp" {
					t.Fatalf("RepoPath = %q, want /tmp/my-mcp", cfg.RepoPath)
				}
				if cfg.JSONPath != "out.json" || cfg.SARIFPath != "out.sarif" || cfg.HTMLPath != "out.html" {
					t.Fatalf("unexpected report paths: %+v", cfg)
				}
				if !cfg.NoColor || !cfg.VerifiedOnly || !cfg.Strict {
					t.Fatalf("expected boolean flags true: %+v", cfg)
				}
				if cfg.FailOn != "medium" {
					t.Fatalf("FailOn = %q, want medium", cfg.FailOn)
				}
			},
		},
		{
			name: "flags before repo path with verify and run-cmd workspace claim",
			args: []string{
				"audit",
				"--verify",
				"--image=localhost/mcp-test:v1",
				"--run-cmd", `python3 server.py --root={workspace} --extra "{workspace}/sub"`,
				"--timeout", "45s",
				"--verify-budget", "5m",
				"--fail-on=critical",
				"./target-repo",
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if !cfg.Verify || cfg.Image != "localhost/mcp-test:v1" {
					t.Fatalf("unexpected verify config: %+v", cfg)
				}
				if cfg.Timeout != 45*time.Second || cfg.VerifyBudget != 5*time.Minute {
					t.Fatalf("unexpected durations: timeout=%s budget=%s", cfg.Timeout, cfg.VerifyBudget)
				}
				if !cfg.HasWorkspaceClaim {
					t.Fatal("expected HasWorkspaceClaim = true")
				}
				wantArgv := []string{"python3", "server.py", "--root=/workspace", "--extra", "/workspace/sub"}
				if !slices.Equal(cfg.RunCmdArgv, wantArgv) {
					t.Fatalf("RunCmdArgv = %#v, want %#v", cfg.RunCmdArgv, wantArgv)
				}
				if cfg.FailOn != "critical" {
					t.Fatalf("FailOn = %q, want critical", cfg.FailOn)
				}
			},
		},
		{
			name: "repo path starting with dash after double dash",
			args: []string{"audit", "--fail-on", "low", "--", "-weird-repo"},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.RepoPath != "-weird-repo" {
					t.Fatalf("RepoPath = %q, want -weird-repo", cfg.RepoPath)
				}
				if cfg.FailOn != "low" {
					t.Fatalf("FailOn = %q, want low", cfg.FailOn)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse(tc.args)
			if err != nil {
				t.Fatalf("Parse(%v) returned unexpected error: %v", tc.args, err)
			}
			tc.check(t, cfg)
		})
	}
}

func TestParseValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "no arguments",
			args:        nil,
			errContains: "missing subcommand",
		},
		{
			name:        "unknown subcommand",
			args:        []string{"scan", "./repo"},
			errContains: "unknown subcommand",
		},
		{
			name:        "missing repo path",
			args:        []string{"audit"},
			errContains: "missing required <repo-path>",
		},
		{
			name:        "extra positional argument",
			args:        []string{"audit", "./repo1", "./repo2"},
			errContains: "extra positional",
		},
		{
			name:        "unknown flag after repo path",
			args:        []string{"audit", "./repo", "--does-not-exist"},
			errContains: "flag provided but not defined",
		},
		{
			name:        "verify without image",
			args:        []string{"audit", "./repo", "--verify"},
			errContains: "--verify requires --image",
		},
		{
			name:        "verify with blank image",
			args:        []string{"audit", "./repo", "--verify", "--image", "   "},
			errContains: "--verify requires --image",
		},
		{
			name:        "invalid fail-on severity",
			args:        []string{"audit", "./repo", "--fail-on", "info"},
			errContains: "invalid --fail-on",
		},
		{
			name:        "zero timeout",
			args:        []string{"audit", "./repo", "--timeout", "0s"},
			errContains: "--timeout must be positive",
		},
		{
			name:        "negative timeout",
			args:        []string{"audit", "./repo", "--timeout", "-5s"},
			errContains: "--timeout must be positive",
		},
		{
			name:        "non-positive verify budget",
			args:        []string{"audit", "./repo", "--verify-budget", "0s"},
			errContains: "--verify-budget must be positive",
		},
		{
			name:        "explicit empty json path",
			args:        []string{"audit", "./repo", "--json", ""},
			errContains: "--json path must not be empty",
		},
		{
			name:        "explicit empty run-cmd",
			args:        []string{"audit", "./repo", "--run-cmd", ""},
			errContains: "empty argv",
		},
		{
			name:        "rejected run-cmd shell metachar",
			args:        []string{"audit", "./repo", "--run-cmd", "python3 server.py | cat"},
			errContains: "shell metacharacter",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.args)
			if err == nil {
				t.Fatalf("Parse(%v) succeeded, want error containing %q", tc.args, tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("Parse(%v) error = %q, want substring %q", tc.args, err.Error(), tc.errContains)
			}
		})
	}
}

func TestTokenizeRunCmdValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		raw           string
		wantArgv      []string
		wantWorkspace bool
	}{
		{
			name:          "simple ASCII whitespace split",
			raw:           "  python3\t-m\nserver\r\n--stdio  ",
			wantArgv:      []string{"python3", "-m", "server", "--stdio"},
			wantWorkspace: false,
		},
		{
			name:          "single quotes are completely literal",
			raw:           `python3 'a\"b\\c' '$HOME' 'x | y'`,
			wantArgv:      []string{"python3", `a\"b\\c`, "$HOME", "x | y"},
			wantWorkspace: false,
		},
		{
			name:          "double quotes escape only quote and backslash",
			raw:           `python3 "hello \"world\" \\ \n \$VAR"`,
			wantArgv:      []string{"python3", `hello "world" \ \n \$VAR`},
			wantWorkspace: false,
		},
		{
			name:          "outside quotes backslash escapes next char",
			raw:           `python3 my\ dir/server.py \$NOT_EXPANDED \|literal`,
			wantArgv:      []string{"python3", "my dir/server.py", "$NOT_EXPANDED", "|literal"},
			wantWorkspace: false,
		},
		{
			name:          "no expansion of variables globs or tilde",
			raw:           `python3 "$HOME" '$USER' ~/workspace *.py [a-z]?.py`,
			wantArgv:      []string{"python3", "$HOME", "$USER", "~/workspace", "*.py", "[a-z]?.py"},
			wantWorkspace: false,
		},
		{
			name:          "workspace substitution standalone and embedded in tokens",
			raw:           `python3 server.py {workspace} --root={workspace} "{workspace}/nested/{workspace}"`,
			wantArgv:      []string{"python3", "server.py", "/workspace", "--root=/workspace", "/workspace/nested//workspace"},
			wantWorkspace: true,
		},
		{
			name:          "empty quoted non-first argument preserved",
			raw:           `python3 -c "" ''`,
			wantArgv:      []string{"python3", "-c", "", ""},
			wantWorkspace: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			argv, hasWorkspace, err := TokenizeRunCmd(tc.raw)
			if err != nil {
				t.Fatalf("TokenizeRunCmd(%q) unexpected error: %v", tc.raw, err)
			}
			if !slices.Equal(argv, tc.wantArgv) {
				t.Fatalf("argv = %#v, want %#v", argv, tc.wantArgv)
			}
			if hasWorkspace != tc.wantWorkspace {
				t.Fatalf("hasWorkspace = %v, want %v", hasWorkspace, tc.wantWorkspace)
			}
		})
	}
}

func TestTokenizeRunCmdRejected(t *testing.T) {
	t.Parallel()

	metachars := []string{"|", "&", ";", "<", ">", "(", ")", "$", "`"}
	for _, mc := range metachars {
		t.Run("unquoted_metachar_"+mc, func(t *testing.T) {
			t.Parallel()
			raw := "python3 server.py " + mc + " arg"
			if _, _, err := TokenizeRunCmd(raw); err == nil {
				t.Fatalf("TokenizeRunCmd(%q) succeeded, expected rejection for metachar %q", raw, mc)
			}
		})
	}

	otherBad := []struct {
		name string
		raw  string
	}{
		{name: "empty string", raw: ""},
		{name: "whitespace only", raw: "   \t\n  "},
		{name: "empty first token", raw: `"" --arg`},
		{name: "unterminated single quote", raw: "python3 'server.py"},
		{name: "unterminated double quote", raw: `python3 "server.py`},
		{name: "unterminated double quote after escaped quote", raw: `python3 "server.py\"`},
		{name: "trailing backslash outside quotes", raw: `python3 server.py\`},
		{name: "unquoted variable syntax", raw: "python3 $HOME/server.py"},
		{name: "unquoted command substitution", raw: "python3 $(pwd)/server.py"},
		{name: "unquoted backtick substitution", raw: "python3 `pwd`/server.py"},
		{name: "NUL byte", raw: "python3\x00server.py"},
	}

	for _, tc := range otherBad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := TokenizeRunCmd(tc.raw); err == nil {
				t.Fatalf("TokenizeRunCmd(%q) succeeded, expected error", tc.raw)
			}
		})
	}
}
