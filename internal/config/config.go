package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// DefaultFailOn is the default minimum severity threshold that gates a scan.
	DefaultFailOn = "high"
	// DefaultTimeout is the default per-verification-session timeout.
	DefaultTimeout = 30 * time.Second
	// DefaultVerifyBudget is the default total wall-clock budget for dynamic verification.
	DefaultVerifyBudget = 10 * time.Minute

	workspacePlaceholder = "{workspace}"
	workspaceMountPath   = "/workspace"
)

// Config holds the validated runtime configuration parsed strictly from CLI flags.
type Config struct {
	RepoPath          string
	JSONPath          string
	SARIFPath         string
	HTMLPath          string
	NoColor           bool
	FailOn            string
	VerifiedOnly      bool
	Strict            bool
	Verify            bool
	Image             string
	RunCmd            string
	RunCmdArgv        []string
	HasWorkspaceClaim bool
	Timeout           time.Duration
	VerifyBudget      time.Duration
}

// Parse validates CLI arguments for the `audit` subcommand and returns a validated Config.
func Parse(args []string) (Config, error) {
	if len(args) == 0 {
		return Config{}, errors.New(`missing subcommand: expected "audit <repo-path> [flags]"`)
	}
	if args[0] != "audit" {
		return Config{}, fmt.Errorf(`unknown subcommand %q: expected "audit"`, args[0])
	}

	var cfg Config
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.JSONPath, "json", "", "Write Canonical JSON 1.0 report to path")
	fs.StringVar(&cfg.SARIFPath, "sarif", "", "Write SARIF 2.1.0 report to path")
	fs.StringVar(&cfg.HTMLPath, "html", "", "Write standalone HTML report to path")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI color in terminal output")
	fs.StringVar(&cfg.FailOn, "fail-on", DefaultFailOn, "Minimum gating severity (critical|high|medium|low)")
	fs.BoolVar(&cfg.VerifiedOnly, "verified-only", false, "Gate only on proven static or confirmed dynamic findings")
	fs.BoolVar(&cfg.Strict, "strict", false, "Exit 3 on incomplete coverage or inconclusive/skipped dynamic outcomes")
	fs.BoolVar(&cfg.Verify, "verify", false, "Enable hardened Rootless Podman dynamic verification (requires --image)")
	fs.StringVar(&cfg.Image, "image", "", "Pre-existing local OCI image ref for --verify")
	fs.StringVar(&cfg.RunCmd, "run-cmd", "", "Override container ENTRYPOINT/CMD (shell-free; {workspace} claims FS boundary)")
	fs.DurationVar(&cfg.Timeout, "timeout", DefaultTimeout, "Per-verification-session timeout")
	fs.DurationVar(&cfg.VerifyBudget, "verify-budget", DefaultVerifyBudget, "Total dynamic verification wall-clock budget")

	flagArgs, positionals := splitAuditArgs(fs, args[1:])
	if err := fs.Parse(flagArgs); err != nil {
		return Config{}, fmt.Errorf("parse audit flags: %w", err)
	}
	if fs.NArg() > 0 {
		positionals = append(positionals, fs.Args()...)
	}

	if len(positionals) == 0 {
		return Config{}, errors.New("missing required <repo-path> argument")
	}
	if len(positionals) > 1 {
		return Config{}, fmt.Errorf("unexpected extra positional arguments: %v", positionals[1:])
	}
	if strings.TrimSpace(positionals[0]) == "" {
		return Config{}, errors.New("repository path must not be empty")
	}
	cfg.RepoPath = positionals[0]

	seen := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})

	if err := validateConfig(&cfg, seen); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validateConfig(cfg *Config, seen map[string]bool) error {
	if seen["json"] && strings.TrimSpace(cfg.JSONPath) == "" {
		return errors.New("--json path must not be empty")
	}
	if seen["sarif"] && strings.TrimSpace(cfg.SARIFPath) == "" {
		return errors.New("--sarif path must not be empty")
	}
	if seen["html"] && strings.TrimSpace(cfg.HTMLPath) == "" {
		return errors.New("--html path must not be empty")
	}

	if !isValidFailOn(cfg.FailOn) {
		return fmt.Errorf("invalid --fail-on value %q: must be one of critical, high, medium, low", cfg.FailOn)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("--timeout must be positive, got %s", cfg.Timeout)
	}
	if cfg.VerifyBudget <= 0 {
		return fmt.Errorf("--verify-budget must be positive, got %s", cfg.VerifyBudget)
	}
	if cfg.Verify && strings.TrimSpace(cfg.Image) == "" {
		return errors.New("--verify requires --image")
	}
	if seen["image"] && strings.TrimSpace(cfg.Image) == "" {
		return errors.New("--image must not be empty")
	}

	if seen["run-cmd"] {
		argv, hasWorkspace, err := TokenizeRunCmd(cfg.RunCmd)
		if err != nil {
			return fmt.Errorf("invalid --run-cmd: %w", err)
		}
		cfg.RunCmdArgv = argv
		cfg.HasWorkspaceClaim = hasWorkspace
	}

	return nil
}

// TokenizeRunCmd splits a --run-cmd string into an explicit argv slice without invoking a shell.
//
// Rules (ARCHITECTURE.md §4.2):
//   - Split on unquoted ASCII whitespace.
//   - Single quotes ('...') are completely literal.
//   - Inside double quotes ("..."), only \" and \\ are escapes.
//   - Outside quotes, \ escapes the next character.
//   - No variable, glob, tilde, or command expansion is ever performed.
//   - Rejects unquoted shell metacharacters (| & ; < > ( ) $ `), unterminated quotes/escapes,
//     NUL bytes, or empty argv.
//   - Replaces every literal {workspace} in any resulting token with /workspace and reports
//     whether at least one replacement occurred.
func TokenizeRunCmd(raw string) ([]string, bool, error) {
	if strings.ContainsRune(raw, 0) {
		return nil, false, errors.New("NUL byte is forbidden")
	}

	const (
		stateUnquoted = iota
		stateSingleQuote
		stateDoubleQuote
	)

	runes := []rune(raw)
	state := stateUnquoted
	var tokens []string
	var cur strings.Builder
	inToken := false

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch state {
		case stateUnquoted:
			switch {
			case isASCIIWhitespace(r):
				if inToken {
					tokens = append(tokens, cur.String())
					cur.Reset()
					inToken = false
				}
			case r == '\'':
				state = stateSingleQuote
				inToken = true
			case r == '"':
				state = stateDoubleQuote
				inToken = true
			case r == '\\':
				if i+1 >= len(runes) {
					return nil, false, errors.New("unterminated escape sequence")
				}
				i++
				cur.WriteRune(runes[i])
				inToken = true
			case isForbiddenMetachar(r):
				return nil, false, fmt.Errorf("unquoted shell metacharacter %q is forbidden", r)
			default:
				cur.WriteRune(r)
				inToken = true
			}
		case stateSingleQuote:
			if r == '\'' {
				state = stateUnquoted
			} else {
				cur.WriteRune(r)
			}
		case stateDoubleQuote:
			switch r {
			case '"':
				state = stateUnquoted
			case '\\':
				if i+1 >= len(runes) {
					return nil, false, errors.New("unterminated double quote")
				}
				next := runes[i+1]
				if next == '"' || next == '\\' {
					cur.WriteRune(next)
					i++
				} else {
					cur.WriteRune('\\')
				}
			default:
				cur.WriteRune(r)
			}
		}
	}

	switch state {
	case stateSingleQuote:
		return nil, false, errors.New("unterminated single quote")
	case stateDoubleQuote:
		return nil, false, errors.New("unterminated double quote")
	}

	if inToken {
		tokens = append(tokens, cur.String())
	}
	if len(tokens) == 0 {
		return nil, false, errors.New("empty argv")
	}
	if tokens[0] == "" {
		return nil, false, errors.New("empty executable in argv")
	}

	hasWorkspace := false
	for i, tok := range tokens {
		if strings.Contains(tok, workspacePlaceholder) {
			hasWorkspace = true
			tokens[i] = strings.ReplaceAll(tok, workspacePlaceholder, workspaceMountPath)
		}
	}

	return tokens, hasWorkspace, nil
}

// splitAuditArgs separates flags from positional arguments so both
// `telltale audit <repo> [flags]` and `telltale audit [flags] <repo>` work
// while respecting `--` as the end-of-flags separator.
func splitAuditArgs(fs *flag.FlagSet, args []string) (flagArgs, positionals []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if len(arg) > 1 && arg[0] == '-' {
			flagArgs = append(flagArgs, arg)
			name, hasEq := parseFlagTokenName(arg)
			if !hasEq {
				if f := fs.Lookup(name); f != nil && !isBoolFlag(f) && i+1 < len(args) {
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return flagArgs, positionals
}

func parseFlagTokenName(arg string) (name string, hasEq bool) {
	trimmed := strings.TrimPrefix(arg, "--")
	if len(trimmed) == len(arg) {
		trimmed = strings.TrimPrefix(arg, "-")
	}
	if idx := strings.IndexByte(trimmed, '='); idx >= 0 {
		return trimmed[:idx], true
	}
	return trimmed, false
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface {
		IsBoolFlag() bool
	}
	bf, ok := f.Value.(boolFlag)
	return ok && bf.IsBoolFlag()
}

func isValidFailOn(v string) bool {
	switch v {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func isASCIIWhitespace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

func isForbiddenMetachar(r rune) bool {
	switch r {
	case '|', '&', ';', '<', '>', '(', ')', '$', '`':
		return true
	default:
		return false
	}
}
