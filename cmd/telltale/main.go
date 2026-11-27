package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/extract/python"
	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/opengrep"
	"github.com/Timatoot/telltale/internal/report"
	"github.com/Timatoot/telltale/internal/rules"
)

const (
	exitPass       = 0
	exitFatalError = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runAudit(args, stdout, stderr, opengrep.SinkAnalyzer{})
}

type sinkAnalyzer interface {
	Preflight(context.Context) (string, error)
	Analyze(context.Context, *ingest.Snapshot) (opengrep.Result, error)
}

func runAudit(args []string, stdout, stderr io.Writer, analyzer sinkAnalyzer) int {
	cfg, err := config.Parse(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}

	if err := rejectUnfinishedModes(cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}

	repoName, err := repositoryName(cfg.RepoPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}

	scan, err := scanPython(context.Background(), cfg.RepoPath, analyzer)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}

	scan.Target = model.Target{RepoName: repoName, Mode: "static"}
	scan.ApplyPolicy(model.Policy{FailOn: model.Severity(cfg.FailOn), VerifiedOnly: cfg.VerifiedOnly, Strict: cfg.Strict})
	if cfg.JSONPath != "" {
		payload, err := report.RenderJSON(&scan, "")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "telltale: render json report: %s\n", report.Sanitize(err.Error(), "", 4096))
			return exitFatalError
		}

		if err := writeFileAtomic(cfg.JSONPath, payload); err != nil {
			_, _ = fmt.Fprintf(stderr, "telltale: write json report: %s\n", report.Sanitize(err.Error(), "", 4096))
			return exitFatalError
		}
	}

	status := "pass"
	switch scan.Summary.AnalysisExitCode {
	case 1:
		status = "policy_violation"
	case 3:
		status = "incomplete"
	}
	_, _ = fmt.Fprintf(stdout, "telltale audit: repo=%s mode=static findings=%d status=%s\n", report.SanitizeIdentifier(repoName, "", 4096), len(scan.Findings), status)
	return scan.Summary.AnalysisExitCode
}

func rejectUnfinishedModes(cfg config.Config) error {
	if cfg.Verify {
		return errors.New("--verify mode is not yet implemented")
	}
	if cfg.SARIFPath != "" {
		return errors.New("--sarif output is not yet implemented")
	}
	if cfg.HTMLPath != "" {
		return errors.New("--html output is not yet implemented")
	}
	return nil
}

func scanPython(ctx context.Context, repoPath string, analyzer sinkAnalyzer) (_ model.ScanReport, err error) {
	version, err := analyzer.Preflight(ctx)
	if err != nil {
		return model.ScanReport{}, err
	}
	snap, err := ingest.CreateSnapshot(ctx, repoPath, "")
	if err != nil {
		return model.ScanReport{}, err
	}
	defer func() { err = errors.Join(err, snap.Close()) }()
	sinks, err := analyzer.Analyze(ctx, snap)
	if err != nil {
		return model.ScanReport{}, err
	}
	result, err := python.ExtractWithMatches(ctx, snap, sinks.Matches)
	if err != nil {
		return model.ScanReport{}, err
	}
	eval := rules.Evaluate(result.Tools, result.Matches, false)
	return model.ScanReport{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.Tool{Name: "telltale", Version: "dev", RuntimeBackend: "none", OpengrepVersion: version},
		Inventory:     eval.Inventory, Findings: eval.Findings,
		Coverage: model.Coverage{
			FilesScanned: len(snap.Files) - len(sinks.FilesSkipped), FilesSkipped: append(snap.FilesSkipped, sinks.FilesSkipped...),
			ToolsDiscovered: len(result.Tools), ParseErrors: append(result.ParseErrors, sinks.ParseErrors...),
			UnresolvedDescriptions:  result.UnresolvedDescriptions,
			UnresolvedRegistrations: result.UnresolvedRegistrations,
			AnalysisLimits:          model.AnalysisLimits{CrossFileHelperCalls: result.CrossFileHelperCalls},
		},
	}, nil
}

func repositoryName(repoPath string) (string, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("resolve repository directory: %w", err)
	}
	name := filepath.Base(absPath)
	if name == string(filepath.Separator) {
		// A filesystem root has no directory name to expose in a report.
		name = "."
	}
	return name, nil
}

func writeFileAtomic(destPath string, data []byte) error {
	dir := filepath.Dir(destPath)
	tmp, err := os.CreateTemp(dir, ".telltale-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in destination directory: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename temp file to destination: %w", err)
	}

	cleanup = false
	return nil
}
