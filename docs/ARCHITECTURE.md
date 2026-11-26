# `telltale` — v1 Architecture & Contracts

## 1. Architectural Overview

`telltale` (`github.com/Timatoot/telltale`) is a stateless, pure-Go CLI engine executing a deterministic pipeline:

0. **Preflight** — Validates CLI flags (including `--run-cmd` tokenization), Opengrep version/capability, and, with `--verify`, Rootless Podman capability and local image presence. Every fatal condition is detected here, before analysis begins, and exits `2`.
1. **Target Ingestion & Snapshot** — Walks the repository via `os.Root` without following symlinks. Enforces file type/size/count budgets and copies in-budget regular `.py` files into a private per-run snapshot directory. All later static stages read only this snapshot, so Tree-sitter and Opengrep see the identical file set and bytes.
2. **Static Metadata Extraction (`go-tree-sitter`)** — Parses the snapshot via CGo without executing Python. Extracts supported MCP tool registrations (`FastMCP` / `MCPServer` decorators and supported low-level patterns), docstrings, parameter schemas, `ToolAnnotations`, line/column spans, unresolved registrations/descriptions, and cross-file helper calls.
3. **Static Sink & Taint Analysis (`opengrep`)** — Runs embedded Semgrep-compatible YAML rules via the native `opengrep` CLI against the snapshot (single-file only).
4. **Fact Model & Static Rule Engine** — Normalizes declared metadata and inferred sink/taint signals into a fact structure. Runs deterministic `POISON-*`, `CONTRACT-*`, and `FS-*` evaluators and emits static findings plus verification hypotheses.
5. **Dynamic Verification Orchestrator (Optional, `--verify`)** — Runs one inventory session (live `tools/list` reconciliation), then one fresh hardened container per hypothesis using a pre-existing local image. Speaks MCP JSON-RPC 2.0 over stdio natively in Go, records independent host-side observations, and sets `dynamic_status` per the state model (§4.5).
6. **Reporting Layer** — Renders Terminal output, Canonical JSON, SARIF 2.1.0, and Standalone HTML from a single immutable `ScanReport`; writes artifacts atomically.

---

## 2. Technology Stack Choices

| Component | Choice | Rationale & Constraints |
| :--- | :--- | :--- |
| **Core & Verifiers** | Go (≥ the `go.mod` `go` directive), `linux/amd64`, pure Go | Single strongly typed binary with native `os.Root` symlink confinement, context cancellation, JSON-RPC, and zero Python IPC layer. |
| **Static Metadata Extraction** | `go-tree-sitter` (CGo) + Python grammar | Accurate Python CST extraction for decorators, docstrings, schemas, annotations, and spans without running Python. |
| **Static Sink & Taint Engine** | Native `opengrep` CLI `>= 2.0.0, < 3.0.0` + embedded YAML rules (`go:embed`) | Self-contained native binary, Semgrep-compatible rule format, fast single-file sink/taint analysis. Cross-file `--enable-interfile` stays disabled in v1. Version range and required flags are verified at preflight. |
| **Container Isolation** | CLI-backed `ContainerRuntime` for local **Rootless Podman ≥ 5.0** with `crun` on cgroup v2 (reference platform: Fedora 44) | Invoked via `exec.CommandContext` with explicit argument slices (no shell) and a scrubbed environment. No Docker, no rootful or remote Podman, no Go container SDKs. |
| **MCP Protocol Client** | Pure-Go JSON-RPC 2.0 over stdio | Covers `initialize`, `notifications/initialized`, paginated `tools/list`, and bounded `tools/call` with strict frame size and timeout limits. Advertises no client capabilities. |
| **HTML Reporting** | Go `html/template` + embedded static CSS | Visual review of results. Context-aware automatic HTML escaping, single offline standalone file, zero external asset requests, no JavaScript required. |
| **Persistence / HTTP API** | None (Stateless) | No SQLite, no DB schema, no HTTP API server in v1. All run data stays in memory and serializes to output files on completion. |

---

## 3. Proposed Package Layout

* `cmd/telltale/` — CLI entrypoint, flag parsing, signal handling, atomic artifact writing, and exit-code mapping.
* `internal/config/` — Validated runtime configuration derived strictly from CLI flags, including the `--run-cmd` tokenizer and `{workspace}` substitution.
* `internal/ingest/` — Symlink-safe repository traversal (`os.Root`), type/size/count caps, and per-run snapshot creation.
* `internal/extract/python/` — Tree-sitter Python MCP metadata extractor; unresolved-registration/description and cross-file-helper tracking.
* `internal/opengrep/` — Embedded custom YAML rules, `opengrep` subprocess runner, version/capability self-test, and JSON result parser.
* `internal/model/` — Canonical fact model, findings, evidence items, coverage accounting, identity/fingerprint functions, and `ScanReport` schema structs.
* `internal/rules/` — Deterministic static evaluators (`poison`, `contract`, `fs`) and verification hypothesis generator.
* `internal/sandbox/` — `ContainerRuntime` (Rootless Podman CLI driver): preflight, create → inspect-assert → start, SELinux mount options, fixture/canary lifecycle, workspace watchdog, and guaranteed teardown.
* `internal/mcpclient/` — Bounded MCP JSON-RPC 2.0 stdio client.
* `internal/verify/` — Live inventory reconciler and pure-Go dynamic verifiers (`readOnlyHint`/`destructiveHint` workspace mutation verifier, Path Traversal canary verifier), argument synthesis.
* `internal/report/` — Terminal, Canonical JSON, SARIF 2.1.0, and Standalone HTML reporters; shared untrusted-text sanitizer.
* `testdata/fixtures/` — Positive (vulnerable) and negative (benign) Python MCP fixtures plus `Containerfile`s used **only by the test harness** to build fixture images.
* `testdata/corpus/` — Vendored, pinned, permissively licensed real-world Python MCP servers with checked-in triage expectations.

---

## 4. Stateless Data & Interface Contracts

Because v1 has no database and no HTTP API, the system contracts are the Canonical JSON Report Schema, CLI Surface, Internal Go Interfaces, External Process/Wire Boundaries, and the Verification State Model.

### 4.1 Canonical `ScanReport` JSON Contract (`schema_version: "1.0"`)

All paths are repo-relative POSIX paths. No absolute host paths, usernames, hostnames, or timestamps. Every array is sorted deterministically: inventory by `tool_id`; findings by severity (desc), then `id`, then `fingerprint`; coverage records by path, then line.

Top-level object fields:

* **`schema_version`** (`string`): SemVer contract version (`"1.0"`).
* **`tool`** (`object`): `name` (`"telltale"`), `version`, `opengrep_version`, `runtime_backend` (`"none"` | `"podman"`), `runtime_version` (nullable string).
* **`target`** (`object`): `repo_name` (base name of the repo directory), `mode` (`"static"` | `"verify"`), `image` (nullable object: `ref`, `image_id`).
* **`coverage`** (`object`):
  * `files_scanned` (int)
  * `files_skipped` (array of `path`/`reason`; reason ∈ `symlink` | `non_regular` | `size_cap` | `count_cap` | `total_cap` | `engine_skipped`)
  * `parse_errors` (array of `path`/`engine`/`reason`)
  * `tools_discovered` (int)
  * `unresolved_registrations` (array of `path`/`line`/`reason`)
  * `unresolved_descriptions` (array of `tool_id`/`field`)
  * `static_only_tools`, `runtime_only_tools`, `ambiguous_joins` (arrays of tool names; verify mode only)
  * `analysis_limits` (`object`): `cross_file_helper_calls` (array of `tool_id`/`callee_module`). Informational; does not affect `coverage_complete`.
* **`inventory`** (`array` of `ToolFact`):
  * `tool_id` (§4.6), `name`, `source_location` (path, start/end line & column; null for runtime-only tools)
  * `declared_description` (string or null), `description_resolved` (`bool`), `live_description` (nullable, populated during `--verify`)
  * `parameters` (name, declared type, description, `description_resolved`)
  * `annotations` (`read_only_hint`, `destructive_hint`, `open_world_hint`, each tri-state `true` | `false` | `null`; unresolvable expressions are `null`)
  * `inferred_sinks` (sink category, rule ID, span, normalized callee)
* **`findings`** (`array` of `Finding`):
  * `id` (stable rule ID: `POISON-*`, `CONTRACT-*`, `FS-*`)
  * `fingerprint` (§4.6)
  * `origin` (`"static"` | `"runtime"`)
  * `family` (`"poisoning"` | `"contract_mismatch"` | `"filesystem_escape"`)
  * `title`, `summary`, `remediation`
  * `severity` (`"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`)
  * `confidence` (`"high"` | `"medium"` | `"low"`)
  * `static_status` (`"proven"` | `"suspected"` | `"none"`), immutable after rule evaluation
  * `dynamic_status` (`"not_run"` | `"confirmed"` | `"not_reproduced"` | `"inconclusive"` | `"skipped"` | `"not_applicable"`)
  * `dynamic_reason` (nullable enum: `no_workspace_claim`, `server_crash`, `handshake_failed`, `protocol_violation`, `timeout`, `resource_limit`, `unsupported_schema`, `tool_error`, `response_truncated`, `ambiguous_join`, `noisy_workspace`, `budget_exhausted`, `tool_not_live`, `description_unresolved`)
  * `gating` (`bool`, per SPEC §5)
  * `tool_id`, `location` (path, start/end line & column; null for runtime findings)
  * `evidence` (`array` of `EvidenceItem`): `kind` (`"declared"` | `"inferred"` | `"observed"` | `"unknown"`), `source` (`"tree-sitter"` | `"opengrep"` | `"mcp-stdio"` | `"sandbox-fs"` | `"cli"`), `detail`, `redacted_excerpt`
  * `mappings` (`object`): `cwe` (array of strings)
* **`summary`** (`object`): `counts_by_severity`, `counts_by_static_status`, `counts_by_dynamic_status`, `gating_count`, `coverage_complete` (`bool`), `policy_passed` (`bool`), `analysis_exit_code` (`0` | `1` | `3`; never `2`).

### 4.2 CLI Surface Contract (CLI Flags Only in v1)

* **Primary command:** `telltale audit <repo-path> [flags]`
* **Output flags:**
  * `--json <path>`
  * `--sarif <path>`
  * `--html <path>`
  * `--no-color`
* **Policy flags:**
  * `--fail-on <critical|high|medium|low>` (default `high`)
  * `--verified-only` (gate only on `static_status: proven` or `dynamic_status: confirmed`)
  * `--strict` (exit `3` on incomplete coverage or `inconclusive`/`skipped` dynamic outcomes)
* **Verification flags:**
  * `--verify` (opt into hardened container verification; requires `--image`)
  * `--image <local-oci-ref>` (pre-existing image in local Rootless Podman storage; never pulled or built)
  * `--run-cmd <command>` (replaces image `ENTRYPOINT`/`CMD`; `{workspace}` placeholder is the FS boundary claim)
  * `--timeout <duration>` (per verification session, default `30s`)
  * `--verify-budget <duration>` (total dynamic verification wall-clock budget, default `10m`; remaining hypotheses become `skipped`/`budget_exhausted`)

**`--run-cmd` tokenization (no shell, ever):**
* Split on unquoted ASCII whitespace.
* `'…'` is literal. Inside `"…"`, only `\"` and `\\` are escapes. Outside quotes, `\` escapes the next character.
* No expansion of any kind: variables, globs, tilde, or command substitution.
* Exit `2` on any unquoted shell metacharacter (`` | & ; < > ( ) $ ` ``), an unterminated quote, or an empty argv.
* After splitting, every literal `{workspace}` in any token is replaced by `/workspace`.
* The resulting argv fully replaces the image `ENTRYPOINT` and `CMD`, and the post-create inspection asserts the effective argv equals it.
* Without `--run-cmd`, the image's own `ENTRYPOINT`/`CMD` runs unchanged and FS hypotheses are `skipped` (`no_workspace_claim`).

### 4.3 Internal Go Interface Contracts

* **`Ingester`**: Takes the repo path; returns a `Snapshot` (private temp dir opened as `*os.Root`, sorted repo-relative file list, skip records). Never follows symlinks; copies only regular files.
* **`StaticExtractor`**: Takes a `Snapshot`; returns `[]ToolFact`, coverage gaps (parse errors, unresolved registrations/descriptions, cross-file helper calls), and non-fatal diagnostics. Never executes target code. CST traversal is iterative or depth-capped (512); exceeding the cap records a `depth_exceeded` parse error.
* **`SinkAnalyzer`**: Materializes embedded YAML rules into a secure temp directory, runs `opengrep scan` on the snapshot, and returns normalized `[]SinkMatch`, parse/skip coverage records derived from the JSON output, and engine version metadata.
* **`RuleEvaluator`**: Pure deterministic function mapping `[]ToolFact` + `[]SinkMatch` into static `[]Finding` (with `static_status` `proven` or `suspected`, `dynamic_status` `not_run`) and `[]VerificationHypothesis`.
* **`ContainerRuntime`**: CLI-backed Rootless Podman driver exposing `Preflight(ctx) (RuntimeInfo, error)`, `CreateSession(ctx, SessionSpec) (Session, error)` (performs `create` + inspection assertions), `Session.Start(ctx) (StdioSession, error)`, and `ForceCleanup(ctx, runID)`.
* **`InventoryReconciler`**: Consumes static `[]ToolFact` and live `[]LiveTool`. Returns the merged inventory, runtime `[]Finding` (`origin: runtime`, `static_status: none`, `dynamic_status: confirmed`), POISON dynamic outcomes for static findings, and coverage records (`static_only_tools`, `runtime_only_tools`, `ambiguous_joins`).
* **`Verifier`**: Consumes a `VerificationHypothesis`, a fresh bounded `StdioSession`, and a host-side `FixtureManager`; returns `VerificationOutcome` (`dynamic_status`, `dynamic_reason`, `[]EvidenceItem`, diagnostic error). Verifiers never create findings.
* **`Reporter`**: Stateless formatter converting immutable `*ScanReport` to Terminal, Canonical JSON, SARIF 2.1.0, or Standalone HTML via a shared untrusted-text sanitizer.

### 4.4 External Process & Security Boundary Contracts

#### Repository Snapshot Boundary
* Ingest budgets: ≤ 10,000 candidate files, ≤ 1 MiB per file, ≤ 64 MiB total. Symlinks, FIFOs, sockets, and devices are never opened and are recorded in `files_skipped`.
* The snapshot is a fresh `0700` temp dir. It contains only copied `.py` files at their repo-relative paths plus one empty `.semgrepignore` at its root, which neutralizes Opengrep's built-in default ignore list. It contains no `.git`, no ignore files from the target, and no other target files.
* Tree-sitter and Opengrep both read only the snapshot, which eliminates file-set divergence and TOCTOU between engines. Snapshot paths are mapped back to repo-relative paths in all output. The snapshot is removed on exit.

#### Opengrep Boundary
* Invoked via `exec.CommandContext` with an explicit argument slice: `opengrep scan --config <temp-rules-dir> --json --quiet --disable-nosem --max-target-bytes <per-file cap> --timeout <sec> <snapshot-dir>` (`--enable-interfile` stays off in v1). `--disable-nosem` prevents target-authored `# nosemgrep` comments from suppressing matches.
* **Preflight self-test:** `opengrep --version` must fall within the supported range, and one scan of an embedded micro-fixture must succeed with the exact flag set and list the fixture in `paths.scanned`. Otherwise exit `2`.
* **Exit code handling:**
  * `0`, and the documented partial-failure code for target parse errors (`3`), mean the JSON is parsed.
  * Any other code means a fatal execution error (exit `2`).
* **Coverage is derived from the JSON, not the exit code:**
  * Every per-file entry in `errors[]` (syntax, timeout, size) becomes a `parse_errors` record.
  * Any snapshot file absent from `paths.scanned` becomes `files_skipped` with reason `engine_skipped`.
* Stdout capped at 64 MiB (exceeding it is fatal, exit `2`); stderr is kept in a bounded ring buffer. The temporary rule directory is cleaned up via deferred teardown.

#### Container Runtime Isolation Boundary (local Rootless Podman)
* **Podman CLI environment:** the CLI runs with an explicit allowlisted environment (`PATH`, `HOME`, `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `LANG=C.UTF-8`). `CONTAINER_HOST`, `CONTAINER_CONNECTION`, `DOCKER_*`, and all other host variables are never passed through. The child runs in its own process group with `Pdeathsig=SIGKILL`, and context cancellation sends `SIGTERM` followed by a bounded `WaitDelay`.
* **Preflight (`podman info --format json`), any failure exits `2`:**
  * `host.security.rootless == true`
  * `host.serviceIsRemote == false`
  * `host.cgroupVersion == "v2"`
  * `host.cgroupControllers` ⊇ {`cpu`, `memory`, `pids`}
  * OCI runtime is `crun`
  * `podman image exists <ref>` succeeds
* **Mandatory `podman create` flags:**
  * Lifecycle and attach: `--interactive`, `--rm`, `--pull=never`, `--log-driver=none` (target output is never persisted to the journal or log files).
  * Isolation: `--network=none`, `--no-hosts`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--image-volume=ignore` (image `VOLUME`s cannot create writable unobserved mounts).
  * Resource limits: `--pids-limit=64`, `--memory=512m`, `--memory-swap=512m`, `--cpus=1`.
  * User: `--userns=keep-id`, `--user=<host-uid>:<host-gid>` (always set, overriding any image `USER`).
  * Scratch space: `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m`.
  * Environment: only explicit literal `--env KEY=VALUE` pairs (`HOME=/tmp`, `PYTHONDONTWRITEBYTECODE=1`). A bare `--env NAME` is never used.
  * Labels and lifetime: `--label telltale.run=<run-id>`, and `--timeout=<session timeout + 10s>` so conmon kills and removes the container even if `telltale` is `SIGKILL`ed.
  * Entrypoint: `--entrypoint` set to the JSON argv when `--run-cmd` is given.
* **Post-create inspection (`podman container inspect`) before `start`.** Any mismatch removes the container and exits `2`:
  * network mode `none`; read-only rootfs; empty effective capability sets; `no-new-privileges`; non-root UID equal to the host UID mapping
  * memory, PIDs, and CPU limits equal to the requested values
  * user-specified mounts exactly {`/workspace` rw, `/restricted` ro, `/tmp` tmpfs}; no devices
  * env keys/values ⊆ image `Config.Env` ∪ the explicit `--env` set (this catches `containers.conf` `env_host` or injected env)
  * effective argv as expected
* **Post-start enforcement check:** read the container's cgroup `memory.max`, `pids.max`, and `cpu.max`. Any mismatch kills the session and exits `2`.
* **Disposable mounts:**
  * A per-session host temp dir (`0700`, seeded benign fixtures) is mounted as `/workspace:rw,Z`.
  * A per-run canary dir (`0500`; one `0400` file named `<file-id>` containing the content token) is mounted as `/restricted:ro,Z`.
  * SELinux `:Z` relabeling applies strictly to these fresh per-run temp directories created by `telltale`, never to the user's repository or shared host directories.
* **Host-side reads:** `/workspace` snapshotting and watchdog sampling use `os.Root` and non-following `Lstat`, so symlinks written by a hostile container cannot redirect host reads outside the temp directory.
* **Cleanup:** runs under `context.WithoutCancel` with a bounded teardown timeout (10s). It force-removes containers labeled with this run's `run-id` only (concurrent `telltale` runs are never touched) and removes temp directories on completion, timeout, or signal. A second `SIGINT`/`SIGTERM` skips waiting for the session but still runs bounded teardown.

#### MCP stdio Wire Boundary
* Line-delimited JSON-RPC 2.0 over container stdin/stdout; stderr captured in a bounded 64 KiB ring buffer and redacted before any use as evidence.
* **Handshake:** `initialize` with `capabilities: {}` (no `roots`, `sampling`, or `elicitation`). An unsupported server `protocolVersion` gives `handshake_failed`.
* **Server-to-client traffic:**
  * Server-to-client requests are answered with JSON-RPC error `-32601`.
  * `notifications/tools/list_changed` is recorded as `observed` evidence. Other notifications are ignored.
* **Limits:**
  * Maximum frame 2 MiB. An oversize frame or a line with no newline at the cap ends the session with `response_truncated`.
  * Per-RPC deadlines are bounded by the session timeout.
  * Non-JSON stdout lines are skipped and counted, up to a 64 KiB budget, then the session ends with `protocol_violation`.
  * Responses with unknown or duplicate IDs are discarded and counted; more than 16 discards is a `protocol_violation`.
  * Pagination stops at 50 pages or 1,000 tools, and a repeated cursor is a `protocol_violation`.
* **Lifecycle:** `initialize` → `notifications/initialized` → paginated `tools/list` → targeted `tools/call` probes → close stdin → bounded wait → force removal.

### 4.5 Verification State Model

**Status transitions (per finding):**
* `static_status` is set once by `RuleEvaluator` and never changes.
  * `proven` is used only for directly observed literal facts, e.g. invisible, bidi, or control codepoints in a resolved literal.
  * Heuristic and correlation results are `suspected`.
* `dynamic_status` starts at `not_run`:
  * In static mode it stays `not_run`.
  * In verify mode, findings whose rule has no verifier become `not_applicable`.
  * Each verifiable finding moves exactly once to one terminal value (`confirmed`, `not_reproduced`, `inconclusive`, `skipped`) and never changes again.
* Runtime findings are created by the `InventoryReconciler` already at `static_status: none`, `dynamic_status: confirmed`.
* Hypotheses targeting a tool absent from the live inventory end `skipped` (`tool_not_live`).

**Sessions:**
* **Inventory session:** one container, handshake, full `tools/list`, teardown.
* **Hypothesis sessions:** one fresh container and one fresh seeded `/workspace` per hypothesis. A tool with several hypotheses (e.g., CONTRACT + FS) gets separate sessions. FS payloads for one hypothesis may share that session.
* Sessions run sequentially, with `--timeout` per session and `--verify-budget` for the whole run.

**Argument synthesis (from the live `inputSchema`):**
* Only required properties are filled.
* Fill values by type:
  * `string`: the FS payload for the tainted parameter; `/workspace/seed/notes.txt` for path-like names (`path`, `file`, `dir`, `name` suffixes); otherwise `"telltale"`.
  * `integer`/`number`: `0`.
  * `boolean`: `false`.
  * `enum`: the first value.
  * `array`: `[]`.
  * `object`: recurse, up to depth 3.
* `oneOf`/`anyOf`/`allOf`, unresolved `$ref`, or depth overflow gives `inconclusive` (`unsupported_schema`).

**Workspace mutation oracle (CONTRACT):**
* **Snapshot entries:** keyed by relative path. Each records type, mode, size, SHA-256 of content (files ≤ 8 MiB; larger files hash the first and last 1 MiB and are flagged), and symlink target text, never followed.
* **Ignored attributes:** atime, ctime, and mtime-only changes.
* **Walk caps:** 10,000 entries and depth 32. Exceeding either gives `inconclusive` (`resource_limit`).
* **Procedure:**
  1. Handshake.
  2. Take snapshot S0, wait 500 ms, take S1. If S0 ≠ S1, the result is `inconclusive` (`noisy_workspace`).
  3. One `tools/call`.
  4. Wait a 1 s settle window, then take S2.
  5. Diff S1→S2.
* **Outcomes:**
  * `readOnlyHint=true`: any added, removed, or changed entry is `confirmed`.
  * `destructiveHint=false`: removal, or a content/type change, of a seeded entry is `confirmed`; additive-only writes are `not_reproduced`.
  * No diff after a successful call is `not_reproduced`. A JSON-RPC error or `isError: true` with no diff is `inconclusive` (`tool_error`).
* **Watchdog:** samples `/workspace` every 250 ms. More than 256 MiB or more than 10,000 entries kills the container and gives `inconclusive` (`resource_limit`). Residual risk: one burst between samples is bounded only by write throughput × 250 ms.

**Canary oracle (FS):**
* Payloads come from a fixed list of at most 16 entries defined in code (relative `../` depths 1–8, absolute `/restricted/<file-id>`, `/workspace/../restricted/<file-id>`). Each references only `<file-id>`.
* **Search scope:**
  * Where: raw response frame bytes, each `content[].text`, base64-decoded `content[].data` / `resource.blob` (decoded size capped at 2 MiB), and serialized `structuredContent`.
  * What: the token plus precomputed variants (standard and URL-safe base64 at all 3 alignments, lower and upper hex).
* **Outcomes:**
  * A match in any response, including error responses, is `confirmed`.
  * No match after all payloads returned successful, untruncated responses is `not_reproduced`.
  * Otherwise `inconclusive`, with the most specific reason.
* Evidence records the payload, the matched variant, and the content path. It never records the token.

### 4.6 Identity & Fingerprints

* **`tool_id`:**
  * `py:<repo-relative path>:<registered name>`. When the same name is registered again in the same file, append `#<n>` (n ≥ 2, ordered by byte offset).
  * Registrations whose name cannot be resolved get `py:<path>:?<n>`, ordered among the unresolved registrations in that file.
  * Runtime-only tools get `live:<name>`.
* **`fingerprint`:** SHA-256 over `rule_id \x00 repo-relative path \x00 tool name \x00 anchor` (NUL-separated). Runtime findings use the literal path `<runtime>`. Anchors are content-based and never include line or column numbers:
  * `POISON` static: field path (`name` | `description` | `param:<p>.description` | `annotation:<k>`) + the rule's matched content (codepoint list or normalized matched phrase).
  * `POISON` runtime: `live:` + field path + SHA-256 of the normalized live field text.
  * `CONTRACT`: annotation key + sink category + normalized callee (e.g., `os.remove`) + ordinal among identical callees in the handler.
  * `FS`: tainted parameter name + normalized callee + ordinal.
* **SARIF:** the fingerprint is emitted as `partialFingerprints["telltale/v1"]`.

---

## 5. Required Edge-Case Test Matrix

Each row needs explicit unit tests (hermetic) or `integration`-tagged tests (container).

| Area | Required cases |
| :--- | :--- |
| Ingest/snapshot | symlink loops, symlink to `/etc/passwd`, FIFO/socket/device files, count/size/total caps, NUL bytes, non-UTF-8, BOM, CRLF, a 1 MiB single-line file, a 10k-deep nested expression (`depth_exceeded`), target-supplied `.semgrepignore`/`.gitignore`/`# nosemgrep` with no effect |
| Extraction | `ToolAnnotations` via variable, dict literal, `**kwargs`, imported constant (all `null` + coverage); aliased `FastMCP` import; `add_tool(fn)`; low-level `list_tools`/`call_tool`; f-string/variable descriptions (`unresolved`); duplicate tool names in one file and across files; cross-file helper detection |
| Opengrep | parse errors reported in `errors[]` with exit `0`; engine-skipped file; unsupported version; missing binary; stdout cap; rejected flag (self-test fails → `2`) |
| MCP client | server→client `roots/list`/`sampling/createMessage` requests; stray `print()` lines; 2 MiB frame without newline; repeated pagination cursor; > 1,000 tools; mismatched/duplicate IDs; server exits mid-call; stderr flood; `tools/list_changed` after a call |
| Reconciliation | docstring reformatted by FastMCP (no finding); env-conditional tool (static-only, no finding); live-only tool (coverage only); live-only tool with bidi text (runtime finding); ambiguous duplicate name |
| FS oracle | canary in text, base64 `data`, `resource.blob`, `structuredContent`, split across content items, in an error response; truncated response (`inconclusive`); `isError` without canary (`inconclusive`); no `{workspace}` (`skipped`) |
| Mutation oracle | atime/mtime-only change (no finding); chmod; new symlink/hardlink/FIFO; symlink pointing outside; file replaced by directory; background writer (`noisy_workspace`); disk-fill and 100k-file creation (watchdog `resource_limit`) |
| Argument synthesis | required/enum/nested/no schema; `oneOf`/`$ref` (`unsupported_schema`) |
| Image hazards | image `VOLUME` (ignored), image `USER root` (overridden), missing HOME/cache on read-only rootfs (crash → `inconclusive`), image absent (`2`), pids-limit hit |
| Isolation | rootful Podman, remote service, missing cgroup controller (all `2`); `containers.conf` `env_host=true` and extra default volume (inspection → `2`); cgroup limits read back after start |
| Cleanup | normal exit, per-session timeout, `--verify-budget` exhaustion, `SIGINT`, double `SIGINT`, `SIGKILL` of `telltale` (container self-removes via `--timeout`), concurrent runs don't remove each other's containers |
| Reporting | bidi/zero-width/ANSI in descriptions escaped in terminal, HTML, SARIF; `<script>` in descriptions neutralized in HTML; SARIF has no `message.markdown`; canary token absent from all artifacts; byte-identical JSON across two checkout paths; fingerprints stable across line-shifting edits |
| Policy/exit | `not_reproduced`/`inconclusive` high finding still gates; `--verified-only` gates on `proven`; `--strict --verify` without `{workspace}` exits `3` when FS hypotheses exist; precedence `2` > `1` > `3` > `0`; artifact write failure exits `2` with no partial files |
