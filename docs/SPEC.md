# telltale — v1 Product Specification

## 1. Purpose & Primary User

**telltale** is a local-first, static-first, canary-verified security scanner for Model Context Protocol (MCP) server repositories.

* **Primary User (v1):** An AppSec engineer or security-minded MCP server author auditing a single Python MCP server repository before merging or approving it.
* **Core Value Proposition:** Correlate statically extracted MCP tool metadata with reachable code sinks, optionally verify high-risk boundary violations inside a hardened offline container, and emit honest, evidence-backed reports without claiming that absence of findings proves safety.

---

## 2. Primary User Flows

### Flow A: Default Static Audit (Safe by Default)
1. User runs `telltale audit <repo-path>` with optional CLI flags (`--json`, `--sarif`, `--html`, `--fail-on`, `--strict`).
2. `telltale` inspects the repository without importing, building, or executing any target code.
3. Static extraction parses Python files for MCP tool registrations, docstrings, parameter schemas, annotations, and source spans, explicitly recording unparseable files and unresolved dynamic registrations as incomplete coverage.
4. Opengrep evaluates embedded v1 YAML sink/taint rules against the repository and `telltale` correlates matches to extracted MCP tool handlers.
5. `telltale` prints a terminal summary, writes any requested artifacts (Canonical JSON, SARIF 2.1.0, standalone HTML), and exits according to the 4-state exit-code contract.

### Flow B: Opt-In Hardened Container Verification (`--verify`)
1. User explicitly opts into dynamic verification via `telltale audit <repo-path> --verify` plus one container source:
   * **Prebuilt image:** `--image <oci-ref>` (no build step).
   * **Repository Dockerfile:** auto-detected root `Dockerfile` or explicit `--dockerfile <path>`, requiring `--allow-build`.
   * **Option B narrow Python fallback:** when no `Dockerfile` exists, user supplies both `--allow-build` and `--run-cmd "<command>"`, triggering one narrow generated temporary `Containerfile` (`python:3.12-slim` + `pip install` of `requirements.txt` or `.`). Anything more complex (Poetry, Conda, native system packages, private indexes, custom build hooks) fails fast and records dynamic verification as `inconclusive` (`build_failed`) while preserving all static findings.
2. User may declare how the target server receives its allowed workspace directory via either a `{workspace}` placeholder inside `--run-cmd` or `--workspace-env <ENV_NAME>`.
3. `telltale` verifies container runtime isolation capabilities (fail-closed), launches the target inside a `--network=none` hardened container speaking MCP over `stdio`, and executes eligible pure-Go verifiers.
4. Independent host-side observations (live `tools/list` output, pre/post `/workspace` filesystem snapshots, and synthetic canary leakage checks) update finding statuses (`confirmed`, `not_reproduced`, `inconclusive`, `skipped`).
5. Containers, temporary images, and disposable fixture directories are unconditionally removed before exit, including on timeout or `SIGINT`/`SIGTERM`.

---

## 3. In-Scope v1 Detection Families (Python Targets Only)

| Family | Rule ID Prefix | Static Evidence (Default) | Dynamic Verification (`--verify`) |
| :--- | :--- | :--- | :--- |
| **Tool & Schema Poisoning** | `POISON-*` | Deterministic inspection of tool names, docstrings, descriptions, parameter descriptions, and annotations for invisible/bidirectional Unicode, prompt-override imperatives, hidden exfil/credential directives, and misleading cross-tool references. | Compares statically extracted tool inventory and descriptions against live `tools/list` responses to detect runtime description injection or hidden/altered tools. |
| **Tool Contract Mismatch** | `CONTRACT-*` | Correlates explicit MCP annotations (`readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`) with reachable single-file sinks (filesystem write/delete, subprocess execution, outbound network APIs). Missing annotations are never treated as assertions of read-only behavior. | Invokes `readOnlyHint=true` tools against a seeded disposable `/workspace` and compares pre/post host-side filesystem snapshots to confirm unauthorized mutation (or fixture deletion for `destructiveHint=false`). |
| **Filesystem Boundary Escape (Path Traversal)** | `FS-*` | Single-file taint correlation from untrusted MCP tool parameters to filesystem read sinks. | Executes only when the user explicitly supplies `{workspace}` or `--workspace-env`. Plants a unique per-run random canary file outside `/workspace` (`/restricted/<canary>`) inside the container, invokes the tool with bounded traversal payloads, and confirms escape only if the canary value appears in the MCP response. |

---

## 4. Core Product & Security Invariants

* **Zero Target Execution in Default Mode:** Without `--verify`, `telltale` never builds containers, never executes Python on repository files, and never runs repository scripts or hooks.
* **Explicit Build Consent:** Untrusted builds (`Dockerfile` or Option B fallback `Containerfile`) never run unless `--allow-build` is explicitly supplied alongside `--verify`.
* **Two Strict Security Boundaries:**
  * **Target boundary:** The MCP server's configured `/workspace` inside the container, which verifiers intentionally test.
  * **Sandbox boundary:** Host OS, host filesystem, host environment variables, credentials, container sockets, and external networks. Never relaxed to make a test pass.
* **Fail-Closed Isolation:** If Rootless Podman or Docker is unavailable or cannot enforce mandatory isolation flags (`--network=none`, non-root execution, dropped capabilities, read-only rootfs, PID/memory/CPU limits), `--verify` aborts with exit code `2`—never falls back to host subprocess execution.
* **Honest Evidence & Coverage Separation:**
  * Never collapse severity, confidence, verification status, and coverage into a single opaque trust score.
  * Never treat a failed, inconclusive, or skipped dynamic test as proof of safety.
  * Never label a legitimate dangerous capability (e.g., an unannotated delete tool or a file reader with no declared workspace restriction) as a confirmed vulnerability.
  * Unparseable files, unresolved dynamic registrations, and cross-file helper calls must be explicitly counted and reported in coverage outputs.
* **Canary Hygiene:** Every verification run generates a fresh cryptographically random canary token; the canary value is never placed inside test inputs; all temporary fixtures are destroyed on exit.
* **Safe, Deterministic Reporting:** Untrusted tool descriptions, source excerpts, and MCP responses are strictly size-bounded and contextually escaped in HTML reports to prevent XSS or terminal control-sequence injection.

---

## 5. CLI Exit-Code Contract

| Exit Code | Meaning | Conditions |
| :--- | :--- | :--- |
| `0` | **Pass** | Scan completed without fatal errors and zero findings met or exceeded `--fail-on` (default: `high`, matching both `confirmed` and `suspected` unless `--verified-only` is set). |
| `1` | **Policy Violation** | One or more findings met or exceeded `--fail-on` (respecting `--verified-only` if provided). |
| `2` | **Fatal Execution Error** | Invalid CLI flags, unreadable repo path, missing/crashed `opengrep`, invalid embedded rules, container runtime unavailable or isolation check failed when `--verify` requested, or unhandled internal error. Never exits `0`. |
| `3` | **Strict Coverage Failure** | Returned only when `--strict` is explicitly enabled and static coverage is incomplete (unparseable files, unresolved dynamic registrations) or one or more requested verifications ended `inconclusive` or `skipped`. |

---

## 6. Explicit v1 Non-Goals

The following are deliberately out of scope for v1 and must not be implemented:

* Full/magic auto-containerization of arbitrary Python projects (Poetry, Conda, Hatch, `uv` lockfiles, native `apt` dependencies, or automatic server entrypoint guessing) — explicitly deferred to a future version.
* Live web GUI server or HTTP API server.
* SQLite or any database/persistence layer or cross-run scan history (v1 is strictly stateless).
* Local YAML/TOML configuration file schemas (all v1 runtime overrides are strictly CLI flags).
* Python verifier subprocesses or third-party plugin loaders (v1 verification is pure Go).
* TypeScript, JavaScript, Go, or other non-Python target static extractors.
* Cross-file static taint tracking (Opengrep `--enable-interfile` remains disabled in v1) and runtime/symbolic resolution of dynamically registered tools.
* Consumer client-config (`mcp.json`) inventory or `mcp-lock.json` integrity/drift tracking.
* Multi-server or intra-server cross-tool exposure capability graphs.
* Live scanning of remote third-party MCP endpoints; Streamable HTTP and legacy SSE transports (`stdio` only in v1).
* SSRF verification / mock internal test networks, Command Injection verification, Token Passthrough / OAuth / Missing-Auth probing, and dependency CVE / SCA / SBOM scanning.
* LLM-as-a-judge classification or LLM-generated test payloads.

---

## 7. v1 Acceptance Criteria

* **Static Pipeline Accuracy:** Running `telltale audit` against the bundled positive (vulnerable) and negative (safe/benign) Python fixture suite detects all three v1 families with zero false positives on benign controls and explicitly reports unresolved dynamic registrations and unparseable files in coverage.
* **Dynamic Verification Proof (Rootless Podman 5.8.9 / `crun` on Fedora 44 and Docker):**
  * Confirms runtime description poisoning diff via live `tools/list`.
  * Confirms filesystem mutation on a `readOnlyHint=true` vulnerable fixture and reports `not_reproduced` on the patched fixture.
  * Confirms Path Traversal canary leakage on the vulnerable fixture when `{workspace}` or `--workspace-env` is provided, reports `not_reproduced` on the patched fixture, and reports `skipped` when no workspace injection flag is given.
  * Option B fallback builds and verifies a simple `requirements.txt` fixture with `--allow-build --run-cmd` and fails fast to `inconclusive` (`build_failed`) on an unsupported complex fixture without discarding static findings.
* **Isolation & Cleanup Fidelity:** Integration tests confirm `--network=none`, dropped capabilities, read-only rootfs, zero leaked host environment variables, proper Fedora SELinux confinement on disposable mounts, and zero orphaned containers or temp directories after normal runs and timeout cancellation.
* **Output Validity:** Canonical JSON conforms to schema version `1.0`; SARIF 2.1.0 validates cleanly with accurate line/column spans for source-addressable findings; standalone HTML renders fully offline and neutralizes embedded `<script>` / HTML payloads inside malicious tool descriptions.
* **Exit-Code Fidelity:** Automated CLI tests verify exact exit codes `0`, `1`, `2`, and `3` across pass, policy violation, fatal error, and `--strict` incomplete-coverage scenarios.