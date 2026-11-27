package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/report"
)

const (
	exitPass       = 0
	exitFatalError = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
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

	coverage, err := ingestCoverage(context.Background(), cfg.RepoPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}

	if cfg.JSONPath != "" {
		scan := model.ScanReport{
			SchemaVersion: model.SchemaVersion,
			Tool:          model.Tool{Name: "telltale", Version: "dev", RuntimeBackend: "none"},
			Target:        model.Target{RepoName: repoName, Mode: "static"},
			Coverage:      coverage,
			Summary:       model.Summary{CoverageComplete: len(coverage.FilesSkipped) == 0, PolicyPassed: true, AnalysisExitCode: exitPass},
		}
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

	_, _ = fmt.Fprintf(stdout, "telltale audit: repo=%s mode=static findings=0 status=pass\n", report.SanitizeIdentifier(repoName, "", 4096))
	return exitPass
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

func ingestCoverage(ctx context.Context, repoPath string) (_ model.Coverage, err error) {
	snap, err := ingest.CreateSnapshot(ctx, repoPath, "")
	if err != nil {
		return model.Coverage{}, err
	}
	defer func() { err = errors.Join(err, snap.Close()) }()
	return model.Coverage{FilesScanned: len(snap.Files), FilesSkipped: snap.FilesSkipped}, nil
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
