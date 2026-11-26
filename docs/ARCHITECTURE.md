# `telltale` — v1 Architecture & Contracts

## 1. Architectural Overview

`telltale` (`github.com/Timatoot/telltale`) is a stateless, pure-Go CLI engine executing a deterministic six-stage pipeline:

1. **Target Ingestion & Validation** — Validates the local repository path, walks `.py` files safely without following symlinks outside the repository root, enforces file size/count budgets, and detects an optional root `Dockerfile`.
2. **Static Metadata Extraction (`go-tree-sitter`)** — Parses Python concrete syntax trees via CGo without executing Python; extracts supported MCP tool registrations (`FastMCP` / `MCPServer` decorators and supported low-level patterns), docstrings, parameter schemas, `ToolAnnotations`, line/column spans, and unresolved-pattern coverage gaps.
3. **Static Sink & Taint Analysis (`opengrep` 2.0.0)** — Runs embedded Semgrep-compatible YAML rules via the native `opengrep` CLI (`opengrep scan --json`), handling single-file sink and taint correlation without requiring a host Python runtime [2][4].
4. **Fact Model & Static Rule Engine** — Normalizes declared metadata and inferred sink/taint signals into a language-agnostic fact structure, runs deterministic `POISON-*`, `CONTRACT-*`, and `FS-*` evaluators, and emits initial findings plus verification hypotheses.
5. **Dynamic Verification Orchestrator (Optional, `--verify`)** — Resolves or builds the target OCI image (when `--allow-build` is set), provisions disposable `/workspace` and `/restricted/<canary>` host directories, starts the server inside a hardened container via a CLI-backed `ContainerRuntime`, speaks MCP JSON-RPC 2.0 over stdio natively in Go, records independent host-side observations, and reconciles finding statuses.
6. **Reporting Layer** — Renders Terminal output, Canonical JSON, SARIF 2.1.0, and Standalone HTML from a single immutable `ScanReport`.

---

## 2. Technology Stack Choices

| Component | Choice | Rationale & Constraints |
| :--- | :--- | :--- |
| **Core & Verifiers** | Go 1.26.11 (`linux/amd64`), pure Go | Single strongly typed binary with native `os.Root` symlink confinement, context cancellation, JSON-RPC, and zero Python IPC layer. |
| **Static Metadata Extraction** | `go-tree-sitter` (CGo via `gcc` 16.2.1) + Python grammar | Accurate Python CST extraction for decorators, docstrings, schemas, annotations, and spans without running Python. |
| **Static Sink & Taint Engine** | Native `opengrep` 2.0.0 CLI + embedded YAML rules (`go:embed`) | Self-contained native binary (no host Python dependency in v2.0.0) [1][2], Semgrep-compatible rule format [7], fast single-file sink/taint analysis. Cross-file `--enable-interfile` stays disabled in v1. |
| **Container Isolation** | CLI-backed `ContainerRuntime` targeting Rootless Podman 5.8.9 (`crun`) on Fedora Linux 44 primary, with Docker compatibility | Invoked via `exec.CommandContext` with explicit argument slices (no shell). Avoids Docker SDK dependency bloat and daemon socket requirements under rootless Podman; natively attaches to MCP stdio. |
| **MCP Protocol Client** | Pure-Go JSON-RPC 2.0 over stdio | Covers `initialize`, `notifications/initialized`, paginated `tools/list`, and bounded `tools/call` with strict frame size and timeout limits. |
| **HTML Reporting** | Go `html/template` + embedded static CSS | Context-aware automatic HTML escaping, single offline standalone file, zero external asset requests. |
| **Persistence / HTTP API** | None (Stateless) | No SQLite, no DB schema, no HTTP API server in v1. All run data stays in memory and serializes to output files on completion. |

---

## 3. Proposed Package Layout

* `cmd/telltale/` — CLI entrypoint, flag parsing, signal handling, and exit-code mapping.
* `internal/config/` — Validated runtime configuration derived strictly from CLI flags.
* `internal/ingest/` — Symlink-safe repository traversal (`os.Root`), size/count caps, root `Dockerfile` detection.
* `internal/extract/python/` — Tree-sitter Python MCP metadata extractor and unresolved-pattern coverage tracker.
* `internal/opengrep/` — Embedded custom YAML rules, `opengrep` 2.0.0 subprocess runner, version/capability checks, and JSON result parser.
* `internal/model/` — Canonical fact model, findings, evidence items, coverage accounting, and `ScanReport` schema structs.
* `internal/rules/` — Deterministic static evaluators (`poison`, `contract`, `fs`) and verification hypothesis generator.
* `internal/sandbox/` — `ContainerRuntime` interface (`podman` / `docker` CLI drivers), image builder (root `Dockerfile` and Option B generated `Containerfile`), Fedora SELinux mount option handling, fixture/canary lifecycle, and guaranteed teardown.
* `internal/mcpclient/` — Bounded MCP JSON-RPC 2.0 stdio client.
* `internal/verify/` — Pure-Go dynamic verifiers (live `tools/list` poisoning diff, `readOnlyHint` workspace mutation verifier, Path Traversal canary verifier).
* `internal/report/` — Terminal, Canonical JSON, SARIF 2.1.0, and Standalone HTML reporters.
* `testdata/fixtures/` — Positive (vulnerable) and negative (safe/benign) Python MCP fixtures, `Dockerfile`s, and Option B fallback test cases.

---

## 4. Stateless Data & Interface Contracts

Because v1 has no database and no HTTP API, the system contracts are the Canonical JSON Report Schema, CLI Surface, Internal Go Interfaces, and External Process/Wire Boundaries.

### 4.1 Canonical `ScanReport` JSON Contract (`schema_version: "1.0"`)

Top-level object fields:

* **`schema_version`** (`string`): SemVer contract version (`"1.0"`).
* **`tool`** (`object`): `name` (`"telltale"`), `version`, `opengrep_version`, `runtime_backend` (`"none"` | `"podman"` | `"docker"`), `runtime_rootless` (`bool`).
* **`target`** (`object`): `repo_path` (normalized), `git_commit` (nullable string), `mode` (`"static"` | `"verify"`).
* **`coverage`** (`object`): `files_scanned`, `files_skipped`, `parse_errors` (array of file/reason), `tools_discovered`, `unresolved_registrations` (array of file/line/reason), `verification_summary` (counts by status).
* **`inventory`** (`array` of `ToolFact`):
  * `tool_id` (deterministic repo-scoped identifier), `name`, `source_location` (file, start/end line & column; nullable for runtime-only tools), `declared_description`, `live_description` (nullable, populated during `--verify`), `parameters` (name, declared type, description), `annotations` (`read_only_hint`, `destructive_hint`, `open_world_hint`, each tri-state `true` | `false` | `null`), `inferred_sinks` (sink category, rule ID, span).
* **`findings`** (`array` of `Finding`):
  * `id` (stable rule ID: `POISON-*`, `CONTRACT-*`, `FS-*`)
  * `fingerprint` (deterministic SHA-256 of rule ID + normalized file path + tool name + primary anchor)
  * `family` (`"poisoning"` | `"contract_mismatch"` | `"filesystem_escape"`)
  * `title`, `summary`, `remediation`
  * `severity` (`"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`)
  * `confidence` (`"high"` | `"medium"` | `"low"`)
  * `verification_status` (`"confirmed"` | `"suspected"` | `"not_reproduced"` | `"inconclusive"` | `"skipped"`)
  * `tool_id`, `location` (file, start/end line & column; nullable for purely runtime-discovered tools)
  * `evidence` (`array` of `EvidenceItem`): `kind` (`"declared"` | `"inferred"` | `"observed"` | `"unknown"`), `source` (`"tree-sitter"` | `"opengrep"` | `"mcp-stdio"` | `"sandbox-fs"`), `detail`, `redacted_excerpt`
  * `mappings` (`object`): `owasp_mcp` (array of strings), `cwe` (array of strings)
* **`summary`** (`object`): counts by severity, counts by verification status, `coverage_complete` (`bool`), `policy_passed` (`bool`), `exit_code` (`int`).

### 4.2 CLI Surface Contract (CLI Flags Only in v1)

* **Primary command:** `telltale audit <repo-path> [flags]`
* **Output flags:**
  * `--json <path>`
  * `--sarif <path>`
  * `--html <path>`
  * `--no-color`
* **Policy flags:**
  * `--fail-on <critical|high|medium|low>` (default `high`)
  * `--verified-only` (policy gate only fails on `confirmed` findings)
  * `--strict` (exit `3` on incomplete coverage or `inconclusive`/`skipped` verifications)
* **Verification flags:**
  * `--verify` (opt into hardened container verification)
  * `--runtime <auto|podman|docker>` (default `auto`: prefers `podman` if installed, else `docker`)
  * `--image <oci-ref>` (use prebuilt container image without building)
  * `--dockerfile <path>` (explicit Dockerfile path; requires `--allow-build`)
  * `--allow-build` (explicit consent to build root `Dockerfile` or Option B fallback `Containerfile`)
  * `--run-cmd <command>` (explicit target launch command; supports `{workspace}` placeholder for Path Traversal boundary injection; required for Option B no-Dockerfile fallback)
  * `--workspace-env <ENV_NAME>` (injects `/workspace` via the named environment variable inside the container)
  * `--timeout <duration>` (per-verification timeout, default `30s`; build timeout separate, default `180s`)

### 4.3 Internal Go Interface Contracts

* **`StaticExtractor`**: Takes `repo *os.Root` and candidate `.py` paths; returns `[]ToolFact`, `[]CoverageGap`, and non-fatal diagnostics. Never executes target code.
* **`SinkAnalyzer`**: Materializes embedded YAML rules into a secure temp directory, runs `opengrep scan`, validates exit status, and returns normalized `[]SinkMatch`, parse-error coverage records, and engine version metadata.
* **`RuleEvaluator`**: Pure deterministic function mapping `[]ToolFact` + `[]SinkMatch` into initial `[]Finding` (`suspected`) and `[]VerificationHypothesis`.
* **`ContainerRuntime`**: CLI-backed interface (`podman` / `docker`) exposing `CheckCapabilities(ctx)`, `BuildImage(ctx, BuildSpec)`, `StartStdioSession(ctx, RunSpec)`, and `ForceCleanup(ctx, runID)`.
* **`Verifier`**: Consumes a `VerificationHypothesis`, bounded `StdioSession`, and host-side `FixtureManager`; returns `VerificationOutcome` (`status`, `[]EvidenceItem`, diagnostic error).
* **`Reporter`**: Stateless formatter converting immutable `*ScanReport` to Terminal, Canonical JSON, SARIF 2.1.0, or Standalone HTML.

### 4.4 External Process & Security Boundary Contracts

#### Opengrep 2.0.0 Boundary
* Invoked via `exec.CommandContext` with explicit argument slice: `opengrep scan --config <temp-rules-dir> --json --quiet --timeout <sec> <repo-path>` (keeping `--enable-interfile` off in v1) [2][4].
* **Exit code handling** [4]:
  * `0` = scan succeeded (parse JSON results)
  * `3` = one or more target files could not be parsed (record in `coverage.parse_errors`, retain parsed findings)
  * `2`, `4`, `5`, `7`, `8`, or unexpected codes = fatal execution error (exit `2`)
* Output stream size capped; temporary extracted rule directory cleaned up via deferred teardown.

#### Container Build Boundary (`--allow-build` only)
* Supports either the repository's `Dockerfile` or the Option B narrow generated `Containerfile` (pinned `python:3.12-slim` base image, non-root `USER`, installs `requirements.txt` or `.` via `pip install --no-cache-dir`).
* Tagged deterministically per run (`telltale-tmp:<run-id>`) and deleted during teardown.
* Option B build failures never crash static scanning; affected dynamic checks record `inconclusive` (`build_failed`).

#### Container Runtime Isolation Boundary (Rootless Podman 5.8.9 / `crun` & Docker)
* `CheckCapabilities` verifies runtime availability (and under Podman checks `Host.Security.Rootless` / `crun` compatibility) before launching any workload; fails closed with exit `2`.
* **Mandatory run flags:** `--interactive`, `--rm`, `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit=64`, `--memory=512m`, `--cpus=1`, explicit non-root user (`--userns=keep-id` on rootless Podman when needed so the container user can write only to the disposable `/workspace` fixture), `--tmpfs /tmp:rw,noexec,nosuid,size=64m`, `--label telltale.run=<run-id>`, zero inherited host environment variables.
* **Disposable mounts:** per-run host temp dir -> `/workspace:rw,Z` (seeded benign fixtures) and read-only per-run canary dir -> `/restricted:ro,Z` (unique random canary file). SELinux `:Z` relabeling is applied strictly to fresh per-run disposable temp directories created by `telltale`—never to the user's repository or shared host directories.
* Host-side `/workspace` pre/post diffing uses `os.Root` and non-following `Lstat` so symlinks written inside `/workspace` by a hostile container cannot redirect host reads outside the temp directory.
* Cleanup runs under `context.WithoutCancel` with a bounded teardown timeout to force-remove labeled containers (`rm -f`), temporary images (`rmi -f`), and temp directories on completion, timeout, or signal.

#### MCP stdio Wire Boundary
* Line-delimited JSON-RPC 2.0 over container stdin/stdout; stderr captured in a bounded diagnostic ring buffer.
* Strict maximum frame size (e.g., `2 MiB`) and per-RPC deadlines to defeat response-bomb or hang attacks.
* **Protocol lifecycle:** `initialize` -> `notifications/initialized` -> paginated `tools/list` (bounded page cap) -> targeted `tools/call` probes.