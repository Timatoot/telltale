# telltale — v1 Product Specification

## 1. Purpose & Primary User

**telltale** is a local-first, static-first, canary-verified security scanner for Model Context Protocol (MCP) server repositories.

* **Primary User (v1):** An AppSec engineer or security-minded MCP server author auditing a single Python MCP server repository before merging or approving it.
* **Core Value Proposition:** Correlate statically extracted MCP tool metadata with reachable code sinks, optionally verify high-risk boundary violations inside a hardened offline container, and emit honest, evidence-backed reports (terminal, Canonical JSON, SARIF, and a standalone HTML report for visual review) without claiming that absence of findings proves safety.

---

## 2. Primary User Flows

### Flow A: Default Static Audit (Safe by Default)
1. User runs `telltale audit <repo-path>` with optional CLI flags (`--json`, `--sarif`, `--html`, `--fail-on`, `--verified-only`, `--strict`).
2. `telltale` inspects the repository without importing, building, or executing any target code, and without invoking `git` or any other tool that reads repository-controlled configuration.
3. Ingestion copies the in-budget regular `.py` files into a private per-run snapshot directory; every later static stage reads only that snapshot (see ARCHITECTURE §4.4 "Repository Snapshot Boundary").
4. Opengrep uses the snapshot directory as its project root (`--project-root`), evaluates embedded v1 rules there, and returns sink spans and single-file taint evidence.
5. Static extraction parses the same snapshot for MCP registrations, docstrings, parameter schemas and annotations. It correlates sink spans with tool handlers and records unparseable files and unresolved registrations as coverage gaps.
6. `telltale` prints a terminal summary, writes any requested artifacts atomically (Canonical JSON, SARIF 2.1.0, standalone HTML), and exits according to the exit-code contract (§5).

### Flow B: Opt-In Hardened Container Verification (`--verify`)
1. User explicitly opts into dynamic verification via `telltale audit <repo-path> --verify --image <local-oci-ref>`. The image must already exist in local Rootless Podman storage; `telltale` never builds or pulls images.
2. User may supply `--run-cmd "<command>"` to replace the image's `ENTRYPOINT`/`CMD`. A literal `{workspace}` placeholder inside `--run-cmd` is the user's assertion that the substituted argument configures the server's allowed filesystem root; it is the only boundary claim v1 accepts (see §3 FS).
3. Preflight (before any analysis): validate flags, Opengrep capability, Rootless Podman capability (cgroup v2 controllers, local non-remote service), and image presence. Any failure exits `2`.
4. For each verification session `telltale` creates a hardened `--network=none` container, inspects the created container to prove every mandatory isolation setting is in effect (fail-closed), then starts it and speaks MCP over `stdio`.
5. Independent host-side observations (live `tools/list` output, pre/post `/workspace` filesystem snapshots, and synthetic canary leakage checks) set each finding's `dynamic_status` (`confirmed`, `not_reproduced`, `inconclusive`, `skipped`, `not_applicable`).
6. Containers and disposable fixture directories are unconditionally removed before exit, including on timeout or `SIGINT`/`SIGTERM`; containers are additionally self-limiting (`--rm` + runtime-enforced `--timeout`) so they cannot outlive a killed `telltale` process.

---

## 3. In-Scope v1 Detection Families (Python Targets Only)

| Family | Rule ID Prefix | Static Evidence (Default) | Dynamic Verification (`--verify`) |
| :--- | :--- | :--- | :--- |
| **Tool & Schema Poisoning** | `POISON-*` | Deterministic inspection of tool names, docstrings, descriptions, parameter descriptions, and annotations. Invisible/bidirectional/control Unicode in a resolved literal is a directly observed fact (`static_status: proven`). Prompt-override imperatives, hidden exfil/credential directives, and misleading cross-tool references are heuristics (`static_status: suspected`). Descriptions built from f-strings, variables, or concatenation are recorded as `unresolved` and never compared. | Reconciles the static inventory with the live `tools/list` response (see "Live Inventory Reconciliation" below). Runs the same POISON text rules over live text. Emits runtime findings only on a positive oracle; tools that are merely present only at runtime or only statically are coverage records, not findings. |
| **Tool Contract Mismatch** | `CONTRACT-*` | Correlates explicit MCP annotations (`readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`) with reachable single-file sinks (filesystem write/delete, subprocess execution, outbound network APIs). Missing or unresolvable annotations are `null`, never treated as assertions. | For `readOnlyHint=true` and `destructiveHint=false` tools: one fresh container + fresh seeded `/workspace` per tool; quiescence-checked pre snapshot, one `tools/call`, settle window, post snapshot (see ARCHITECTURE §4.5). Any mutation (`readOnlyHint=true`) or deletion/overwrite of seeded fixtures (`destructiveHint=false`) in that window is `confirmed`; a noisy (non-quiescent) server is `inconclusive`. `openWorldHint=false` has no dynamic verifier in v1 (`not_applicable`). |
| **Filesystem Boundary Escape (Path Traversal)** | `FS-*` | Single-file taint correlation from untrusted MCP tool parameters to filesystem read sinks. | Runs only when `--run-cmd` contains `{workspace}` (otherwise `skipped`). Places a canary file outside `/workspace` at `/restricted/<file-id>`. `<file-id>` is a random, non-secret filename, and the file holds a separate random content token. Bounded traversal payloads reference only `<file-id>`. The finding is `confirmed` only if the content token, or one of its precomputed encodings, appears in the MCP response. Evidence records the boundary claim source as `run_cmd_workspace_placeholder`. |

### Live Inventory Reconciliation (POISON dynamic)
* **Join key:** the registered tool name. When a name has several static registrations, the join is `ambiguous`: it is recorded in coverage and that tool's diff is `inconclusive`.
* **Normalization before comparison (both sides):** CRLF→LF, `inspect.cleandoc`-equivalent indentation stripping, removal of leading/trailing blank lines and of trailing whitespace on each line. Unicode is **never** normalized (no NFC/NFKC), because Unicode tricks are what the rules detect.
* **Parameters:** compare parameter names and resolved literal descriptions only. Types and JSON-schema shapes are not compared (Pydantic rewrites them).
* **Outcomes:**
  * A static resolved literal that differs from the live text after normalization produces `POISON-RUNTIME-DRIFT` (`dynamic_status: confirmed`, the drift is directly observed).
  * A POISON text rule matching live text produces the corresponding runtime finding.
  * A live-only tool is recorded in `coverage.runtime_only_tools`.
  * A static-only tool (for example, one registered only when an env var is set) is recorded in `coverage.static_only_tools`.

---

## 4. Core Product & Security Invariants

* **Zero Target Execution in Default Mode:** Without `--verify`, `telltale` never runs containers, never executes Python on repository files, never runs repository scripts or hooks, and never invokes `git` or other tools that honor repository-local configuration.
* **No Image Builds or Pulls:** `telltale` never builds images and never pulls from registries; `--verify` uses only a pre-existing local image (`--pull=never`).
* **Two Strict Security Boundaries:**
  * **Target boundary:** The MCP server's configured `/workspace` inside the container, which verifiers intentionally test.
  * **Sandbox boundary:** Host OS, host filesystem, host environment variables, credentials, container sockets, and external networks. Never relaxed to make a test pass.
* **Fail-Closed Isolation:** `--verify` requires Rootless Podman on a local (non-remote) service with cgroup v2 `cpu`, `memory`, and `pids` controllers delegated. Every container is inspected after `create` and before `start`. If any mandatory setting is not in effect, `--verify` aborts with exit `2` and never falls back to host subprocess execution. Mandatory settings: `--network=none`, non-root user, zero capabilities, `no-new-privileges`, read-only rootfs, PID/memory/CPU limits, exactly the expected mounts, no devices, no host-derived env. Rootful Podman and Docker are rejected.
* **Honest Evidence & Coverage Separation:**
  * Never collapse severity, confidence, static status, dynamic status, and coverage into a single opaque trust score.
  * A dynamic outcome can only *add* proof (`confirmed`). `not_reproduced`, `inconclusive`, and `skipped` never downgrade a finding or remove it from the policy gate.
  * Never label a legitimate dangerous capability (e.g., an unannotated delete tool, or a file reader run without a `{workspace}` boundary claim) as a confirmed vulnerability.
  * `coverage_complete` is `false` when there are parse errors, unresolved registrations, files skipped by budget/type/engine, or ambiguous inventory joins (verify mode).
  * A failed MCP inventory records a scan-wide diagnostic with an empty `path`, `engine: "mcp"`, and the dynamic failure reason in `parse_errors`. This makes coverage incomplete even when there are no findings.
  * A scan-wide Opengrep diagnostic appears in `parse_errors` with an empty `path` and counts toward incomplete coverage.
  * Cross-file helper calls from tool handlers into other repository modules are counted in `analysis_limits`. They are a documented v1 limit and do not affect `coverage_complete`.
* **Canary Hygiene:** Every verification run generates two independent `crypto/rand` values: a canary filename (`<file-id>`, ≥128 bits) and a content token (≥256 bits). The content token never appears in tool inputs. Evidence records only the matched encoding variant and location, never the token itself. All temporary fixtures are destroyed on exit.
* **Safe, Deterministic Reporting:**
  * Size-bound all untrusted tool descriptions, source excerpts, and MCP responses.
  * In terminal, HTML, and SARIF output, render control, bidi, and zero-width codepoints as visible `<U+XXXX>` escapes, and never emit raw ANSI from target data.
  * HTML is contextually escaped. SARIF uses `message.text` only, never `message.markdown`.
  * All report paths are repo-relative POSIX paths. No absolute host paths, usernames, or timestamps appear in Canonical JSON.

---

## 5. Policy & CLI Exit-Code Contract

### Policy gate
A finding **gates** when its `severity` ≥ `--fail-on` (default `high`) **and**:
* default: `static_status` ∈ {`proven`, `suspected`} **or** `dynamic_status` = `confirmed`;
* with `--verified-only`: `static_status` = `proven` **or** `dynamic_status` = `confirmed`.

`confidence` is reported but does not affect the gate. Dynamic outcomes other than `confirmed` never change gating.

### Exit codes

| Exit Code | Meaning | Conditions |
| :--- | :--- | :--- |
| `0` | **Pass** | Analysis completed, artifacts written, no gating findings, and (if `--strict`) coverage complete with no strict-failing dynamic outcomes. |
| `1` | **Policy Violation** | One or more gating findings. |
| `2` | **Fatal Execution Error** | Invalid CLI flags (including a rejected `--run-cmd`), unreadable repo path, repository traversal exceeding 1,000,000 entries, 256 directory levels or two minutes, missing/incompatible/crashed `opengrep`, invalid embedded rules, failed preflight (Podman not rootless/local, missing cgroup controllers, image not present locally), post-create isolation inspection mismatch, artifact write failure, or unhandled internal error. Never exits `0`. |
| `3` | **Strict Coverage Failure** | Only with `--strict`: `coverage_complete` is `false`, or (verify mode) any finding ended with `dynamic_status` `inconclusive` or `skipped`. `not_applicable` never triggers exit `3`. |

* **Precedence:** `2` > `1` > `3` > `0`.
* **Target misbehavior is not fatal:** server crash, handshake failure, protocol violation, per-session timeout, resource-limit kill, or exhausted verify budget map to `inconclusive`/`skipped` with a reason, never to exit `2`.
* **Artifacts on failure:** all artifacts are rendered in memory, written to temp files in the destination directory, then renamed. If any write fails, temp files are removed and the process exits `2`. On any exit-`2` condition no artifacts are left behind. `summary.analysis_exit_code` records the analysis result (`0`/`1`/`3`) and is never `2`.

---

## 6. Explicit v1 Non-Goals

The following are deliberately out of scope for v1 and must not be implemented:

* Building or pulling container images of any kind (repository `Dockerfile`, generated `Containerfile`, Poetry/Conda/Hatch/`uv` auto-containerization, automatic entrypoint guessing). Users build their own image.
* Docker, rootful Podman, remote Podman services, or any container runtime other than local Rootless Podman.
* Invoking `git` or reading VCS metadata from the target repository.
* Live web GUI server or HTTP API server (the standalone offline HTML report file is in scope).
* SQLite or any database/persistence layer or cross-run scan history (v1 is strictly stateless).
* Local YAML/TOML configuration file schemas (all v1 runtime overrides are strictly CLI flags).
* Python verifier subprocesses or third-party plugin loaders (v1 verification is pure Go).
* TypeScript, JavaScript, Go, or other non-Python target static extractors.
* Cross-file static taint tracking (Opengrep `--enable-interfile` remains disabled in v1) and runtime/symbolic resolution of dynamically registered tools.
* Serving MCP client capabilities (`roots`, `sampling`, `elicitation`) to the target server.
* Consumer client-config (`mcp.json`) inventory or `mcp-lock.json` integrity/drift tracking.
* Multi-server or intra-server cross-tool exposure capability graphs.
* Live scanning of remote third-party MCP endpoints; Streamable HTTP and legacy SSE transports (`stdio` only in v1).
* SSRF verification / mock internal test networks, Command Injection verification, Token Passthrough / OAuth / Missing-Auth probing, and dependency CVE / SCA / SBOM scanning.
* LLM-as-a-judge classification or LLM-generated test payloads.
* Taxonomy mappings other than CWE (e.g., OWASP MCP Top 10) in the `1.0` schema.

---

## 7. v1 Acceptance Criteria

* **Static Pipeline Accuracy:** `telltale audit` against the bundled positive (vulnerable) and negative (benign) Python fixture suite in `testdata/fixtures/` detects all three v1 families with zero false positives on benign controls and reports unresolved registrations, unparseable files, and engine-skipped files in coverage.
* **Held-Out Real-World Corpus:** at least 5 permissively licensed real-world Python MCP servers are vendored offline at pinned commits under `testdata/corpus/`. Every finding on them is triaged in a checked-in expectations file. `static_status: proven` rules produce zero false positives there.
* **Dynamic Verification Proof (local Rootless Podman ≥ 5.0 with `crun`, cgroup v2; reference platform Fedora 44):**
  * Confirms runtime description drift and live-text poisoning via `tools/list`. Does not raise findings for env-conditional (static-only) or docstring-reformatted tools.
  * Confirms filesystem mutation on a `readOnlyHint=true` vulnerable fixture, reports `not_reproduced` on the patched fixture, and reports `inconclusive` on a fixture that writes spontaneously in the background.
  * Confirms Path Traversal canary leakage on the vulnerable fixture when `{workspace}` is in `--run-cmd` (including a fixture that returns the canary base64-encoded). Reports `not_reproduced` on the patched fixture and `skipped` when no `{workspace}` placeholder is given.
* **Isolation & Cleanup Fidelity:** integration tests confirm:
  * `--network=none`, zero capabilities, read-only rootfs, and enforced PID/memory/CPU limits (read back from cgroup files).
  * Rejection of rootful/remote Podman and of missing cgroup controllers.
  * Zero leaked host environment variables, even with `env_host`-style injection, and proper SELinux confinement of the disposable mounts.
  * Zero orphaned containers or temp directories after normal runs, timeout cancellation, double `SIGINT`, and `SIGKILL` of `telltale` itself.
* **Output Validity:**
  * Canonical JSON conforms to schema version `1.0` and is byte-identical across two runs on the same input from different checkout paths.
  * SARIF 2.1.0 validates cleanly with accurate line/column spans for source-addressable findings and stable `partialFingerprints` across line-shifting edits.
  * Standalone HTML renders fully offline and neutralizes embedded `<script>`/HTML payloads and bidi/control characters inside malicious tool descriptions.
* **Exit-Code Fidelity:** automated CLI tests verify exact exit codes `0`, `1`, `2`, `3` and the `2` > `1` > `3` > `0` precedence across pass, policy violation, fatal error, artifact-write failure, and `--strict` incomplete-coverage scenarios.
