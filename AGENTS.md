# telltale — Agent Operating Map

## Purpose & Architecture
- **What:** Go (`github.com/Timatoot/telltale`) grey-box CLI security scanner for Python `stdio` MCP servers using Tree-sitter, Opengrep, and rootless Podman verification (`POISON-*`, `CONTRACT-*`, `FS-*`) to emit terminal, Canonical JSON `1.0`, SARIF `2.1.0`, and standalone HTML reports.
- **Core boundary:** Static packages (`internal/ingest`, `internal/extract`, `internal/opengrep`, `internal/rules`) must treat target repositories as untrusted bytes with zero target code execution; all slice sorting, fingerprinting, and report generation must remain deterministic.
- **Authoritative docs (read on demand, not upfront):**
  - `docs/SPEC.md` — v1 scope/non-goals, CLI flags, exit codes (`0`/`1`/`2`/`3`), and output schemas
  - `docs/ARCHITECTURE.md` — package layering, data flow, and sandbox security boundaries

## Exact Commands (Use These, Never Guess)
- **Build (CGo required):** `CGO_ENABLED=1 go build -o bin/telltale ./cmd/telltale`
- **Fast unit tests (hermetic, race-enabled):** `go test -race -count=1 ./...`
- **Single test:** `go test -race -count=1 -v -run <TestName> ./<pkg>`
- **Lint & format (zero warnings):** `golangci-lint fmt ./... && golangci-lint run ./...`
- **Opengrep rule validation & tests:** `opengrep validate ./internal/opengrep/rules && opengrep test ./internal/opengrep/rules`
- **Container integration tests (Podman/Docker):** `go test -tags=integration -race -count=1 ./internal/sandbox/... ./internal/verify/... ./cmd/telltale/...`

## Non-Inferable Constraints & Gotchas
- **Strict v1 stop-rule:** Python `stdio` targets and `POISON-*` / `CONTRACT-*` / `FS-*` only. Never add v2 features (TypeScript, HTTP/SSE, SSRF, Command Injection, OAuth/Token Passthrough, Missing-Auth, SCA/CVEs, LLM calls, `mcp.json`/`mcp-lock.json`, cross-tool graphs, web GUI, DBs, config files, magic auto-containerization, or Opengrep `--enable-interfile`)—stop and ask instead.
- **Dependency freeze:** Never add third-party `go.mod` dependencies without explicit approval; prefer Go stdlib (`os.Root`, `html/template`, `encoding/json`, `crypto/rand`, `os/exec`, `embed`, `context.WithoutCancel`). Keep `go-tree-sitter` (+ Python grammar) as the sole CGo dependency and never add Docker/Podman Go SDKs.
- **Subprocess & sandbox invariants:** Zero shell interpolation (`sh -c`/`bash -c` forbidden; always pass explicit arg slices to `exec.CommandContext` with `context.Context` first). Sandbox execution must fail closed (never fall back to host execution; never relax `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`, or resource limits) and always clean up containers, temp images, and temp dirs via `context.WithoutCancel`.
- **Fedora SELinux & symlink safety:** Apply `:Z` mount relabeling *only* to fresh per-run disposable temp dirs (`/workspace`, `/restricted`)—never to user repo or shared host paths. Always use `os.Root` or non-following `Lstat` when scanning untrusted repos or diffing mounted `/workspace` snapshots.
- **Canaries, evidence & output safety:** Generate `crypto/rand` per-run canaries and never place canary values inside tool inputs or payloads. Never mark a finding confirmed without an independent positive oracle, never treat missing MCP annotations as `readOnlyHint=true`, and always surface Opengrep exit code `3` parse errors and unresolved Tree-sitter registrations in coverage output. Render HTML strictly via `html/template` (never cast untrusted data to `template.HTML`), redact high-entropy secrets (never log host env vars), and cap Opengrep `stdout`, container `stderr`, and MCP JSON-RPC frame sizes.
- **Public contracts & testing:** CLI exit codes (`0`/`1`/`2`/`3`), Canonical JSON `1.0`, SARIF `2.1.0`, and HTML XSS neutralization are public contracts; sync any flag, schema, exit-code, or security-invariant change back to `docs/SPEC.md` and `docs/ARCHITECTURE.md`. Every rule and verifier must ship with both positive (vulnerable) and negative (benign) fixtures in `testdata/fixtures/`, and container tests must remain gated behind the `integration` build tag.
- **Linter gotchas (`.golangci.yml` v2):** Wrap errors with `%w` and compare via `errors.Is`/`errors.As` (`errorlint`), never return `nil` when `err != nil` without justification (`nilerr`), and never globally suppress `gosec`—validate inputs first and document any narrowly scoped inline `//nolint:gosec`.
