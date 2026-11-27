package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Timatoot/telltale/internal/config"
)

const (
	exitPass       = 0
	exitFatalError = 2
)

// skeletonReport is a temporary Slice 1 JSON placeholder.
// Slice 2 replaces this with the Canonical JSON 1.0 schema in internal/model and internal/report.
type skeletonReport struct {
	SchemaVersion string         `json:"schema_version"`
	Target        skeletonTarget `json:"target"`
	FindingsCount int            `json:"findings_count"`
}

type skeletonTarget struct {
	RepoName string `json:"repo_name"`
	Mode     string `json:"mode"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := config.Parse(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %v\n", err)
		return exitFatalError
	}

	if err := rejectUnfinishedModes(cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %v\n", err)
		return exitFatalError
	}

	repoName, err := validateRepoDir(cfg.RepoPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %v\n", err)
		return exitFatalError
	}

	if cfg.JSONPath != "" {
		payload, err := json.MarshalIndent(skeletonReport{
			SchemaVersion: "1.0",
			Target: skeletonTarget{
				RepoName: repoName,
				Mode:     "static",
			},
			FindingsCount: 0,
		}, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "telltale: marshal json report: %v\n", err)
			return exitFatalError
		}
		payload = append(payload, '\n')

		if err := writeFileAtomic(cfg.JSONPath, payload); err != nil {
			_, _ = fmt.Fprintf(stderr, "telltale: write json report: %v\n", err)
			return exitFatalError
		}
	}

	_, _ = fmt.Fprintf(stdout, "telltale audit: repo=%s mode=static findings=0 status=pass\n", repoName)
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

func validateRepoDir(repoPath string) (string, error) {
	info, err := os.Stat(repoPath)
	if err != nil {
		return "", fmt.Errorf("stat repository path: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("repository path is not a directory")
	}

	// Verify directory readability via os.Root without traversing its contents.
	root, err := os.OpenRoot(repoPath)
	if err != nil {
		return "", fmt.Errorf("open repository directory: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	f, err := root.Open(".")
	if err != nil {
		return "", fmt.Errorf("open repository root: %w", err)
	}
	_, readErr := f.Readdirnames(1)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("read repository directory: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close repository directory: %w", closeErr)
	}

	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("resolve repository directory: %w", err)
	}
	return filepath.Base(absPath), nil
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
