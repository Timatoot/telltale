// Package opengrep runs the embedded static analysis rules on an ingest snapshot.
package opengrep

import "embed"

//go:embed rules/*.yaml selftest_fixture.py
var assets embed.FS
