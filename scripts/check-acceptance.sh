#!/usr/bin/env bash
set -u

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <package> <test-name>" >&2
    exit 2
fi
package=$1
test_name=$2
case "$test_name" in
    TestOpengrepIntegration|TestSARIFSchema|TestStaticE2E|TestHeldOutCorpus) ;;
    *) echo "Unknown acceptance test: $test_name" >&2; exit 2 ;;
esac

# Stream the Go output, preserve its exit status, and reject successful
# invocations that silently ran zero tests, skipped, or matched twice.
go test -tags=staticacceptance -race -count=1 -v -run "^$test_name$" "$package" |
    awk -v name="$test_name" '
        { print }
        $0 ~ ("^--- PASS: " name " \\(") { passed++ }
        $0 ~ ("^--- SKIP: " name " \\(") { skipped++ }
        END {
            if (passed != 1 || skipped) {
                print "Expected exactly one passing " name > "/dev/stderr"
                exit 1
            }
        }'
status=("${PIPESTATUS[@]}")
if (( status[0] != 0 )); then
    exit "${status[0]}"
fi
exit "${status[1]}"
