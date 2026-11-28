package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/sandbox"
)

const fsSchema = `{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}`

func fsFixtures(t *testing.T) (*sandbox.FixtureManager, string) {
	t.Helper()
	fixtures, err := sandbox.NewFixtureManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixtures.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	token, err := fixtures.ContentToken()
	if err != nil {
		t.Fatal(err)
	}
	return fixtures, token
}

func fsJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fsText(t *testing.T, text string) mcpclient.CallResult {
	t.Helper()
	return mcpclient.CallResult{Content: []json.RawMessage{fsJSON(t, map[string]string{"type": "text", "text": text})}}
}

func assertFSOutcome(t *testing.T, result VerificationResult, err error, status model.DynamicStatus, reason model.DynamicReason) {
	t.Helper()
	if err != nil || result.Status != status || (result.Reason == nil) != (reason == "") || (result.Reason != nil && *result.Reason != reason) {
		t.Fatalf("outcome status=%s reason=%v err=%v, want %s %s", result.Status, result.Reason, err, status, reason)
	}
}

func TestFSVerifierResponses(t *testing.T) {
	for _, kind := range []string{"text", "raw frame", "data", "blob", "structured", "hex lower", "hex upper", "split text", "rpc error", "isError", "positive truncated", "clean", "echo", "negative isError", "negative rpc error", "truncated", "crash", "timeout", "protocol", "watchdog", "late success", "error then clean", "error then timeout"} {
		t.Run(kind, func(t *testing.T) {
			fixtures, token := fsFixtures(t)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			calls, handshakes := 0, 0
			status, reason, path := model.Confirmed, model.DynamicReason(""), "content[0].text"
			switch kind {
			case "raw frame", "rpc error":
				path = "raw_frame"
			case "data":
				path = "content[0].data"
			case "blob":
				path = "content[0].resource.blob"
			case "structured":
				path = "structuredContent"
			case "split text":
				path = "content[].text (concatenated)"
			case "clean", "echo":
				status = model.NotReproduced
			case "negative isError", "negative rpc error", "error then clean":
				status, reason = model.Inconclusive, model.ToolError
			case "truncated":
				status, reason = model.Inconclusive, model.ResponseTruncated
			case "crash":
				status, reason = model.Inconclusive, model.ServerCrash
			case "timeout", "error then timeout":
				status, reason = model.Inconclusive, model.Timeout
			case "protocol":
				status, reason = model.Inconclusive, model.ProtocolViolation
			case "watchdog":
				status, reason = model.Inconclusive, model.ResourceLimit
			}
			peer := contractPeer{ctx: ctx, init: func() error { handshakes++; return nil }, call: func(name string, args map[string]any) (mcpclient.CallResult, error) {
				calls++
				outgoing := fsJSON(t, args)
				if name != "read_file" || bytes.Contains(outgoing, []byte(token)) {
					t.Fatal("invalid request or token in outgoing arguments")
				}
				payload, ok := args["path"].(string)
				expectedPayload := strings.Repeat("../", calls) + "restricted/" + fixtures.FileID()
				switch calls {
				case 9:
					expectedPayload = "/restricted/" + fixtures.FileID()
				case 10:
					expectedPayload = "/workspace/../restricted/" + fixtures.FileID()
				}
				if !ok || payload != expectedPayload {
					t.Fatal("unexpected payload sequence")
				}
				switch kind {
				case "clean", "echo":
					raw, err := os.ReadFile("../../testdata/fixtures/fs_benign/oracle_response.json")
					if err != nil {
						t.Fatal(err)
					}
					var result mcpclient.CallResult
					if err := json.Unmarshal(bytes.ReplaceAll(raw, []byte("${PAYLOAD}"), []byte(payload)), &result); err != nil {
						t.Fatal(err)
					}
					return result, nil
				case "raw frame", "rpc error":
					return mcpclient.CallResult{RawFrame: fsJSON(t, map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -1, "message": token}})}, &mcpclient.RPCError{}
				case "data":
					return mcpclient.CallResult{Content: []json.RawMessage{fsJSON(t, map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(token))})}}, nil
				case "blob":
					return mcpclient.CallResult{Content: []json.RawMessage{fsJSON(t, map[string]any{"resource": map[string]string{"blob": base64.StdEncoding.EncodeToString([]byte(token))}})}}, nil
				case "structured":
					return mcpclient.CallResult{StructuredContent: fsJSON(t, map[string]string{"result": token})}, nil
				case "hex lower":
					return fsText(t, hex.EncodeToString([]byte(token))), nil
				case "hex upper":
					return fsText(t, strings.ToUpper(hex.EncodeToString([]byte(token)))), nil
				case "split text":
					return mcpclient.CallResult{Content: []json.RawMessage{fsJSON(t, map[string]string{"text": token[:21]}), fsJSON(t, map[string]string{"text": token[21:43]}), fsJSON(t, map[string]string{"text": token[43:]})}}, nil
				case "isError":
					result := fsText(t, token)
					result.IsError = true
					return result, nil
				case "positive truncated":
					return fsText(t, token), mcpclient.ErrResponseTruncated
				case "negative isError":
					return mcpclient.CallResult{IsError: true}, nil
				case "negative rpc error":
					return mcpclient.CallResult{}, &mcpclient.RPCError{}
				case "truncated":
					return mcpclient.CallResult{}, mcpclient.ErrResponseTruncated
				case "crash":
					return mcpclient.CallResult{}, mcpclient.ErrServerCrash
				case "timeout":
					return mcpclient.CallResult{}, mcpclient.ErrTimeout
				case "protocol":
					return mcpclient.CallResult{}, mcpclient.ErrProtocolViolation
				case "watchdog":
					cancel(sandbox.ErrResourceLimit)
					return mcpclient.CallResult{}, context.Canceled
				case "late success":
					if calls < 10 {
						return mcpclient.CallResult{IsError: true}, nil
					}
				case "error then clean":
					return mcpclient.CallResult{IsError: calls == 1}, nil
				case "error then timeout":
					if calls == 1 {
						return mcpclient.CallResult{IsError: true}, nil
					}
					return mcpclient.CallResult{}, mcpclient.ErrTimeout
				}
				raw, err := os.ReadFile("../../testdata/fixtures/fs_vuln/oracle_response.json")
				if err != nil {
					t.Fatal(err)
				}
				var result mcpclient.CallResult
				if err := json.Unmarshal(bytes.ReplaceAll(raw, []byte("${CANARY}"), []byte(token)), &result); err != nil {
					t.Fatal(err)
				}
				return result, nil
			}}
			result, err := (FSVerifier{}).Verify(peer, config.Config{HasWorkspaceClaim: true}, fixtures, mcpclient.LiveTool{Name: "read_file", InputSchema: json.RawMessage(fsSchema)}, "path")
			assertFSOutcome(t, result, err, status, reason)
			wantCalls := 1
			switch kind {
			case "clean", "echo", "negative isError", "negative rpc error", "late success", "error then clean":
				wantCalls = 10
			case "error then timeout":
				wantCalls = 2
			}
			if calls != wantCalls || handshakes != 1 {
				t.Fatalf("calls=%d handshakes=%d", calls, handshakes)
			}
			evidence := fsJSON(t, result.Evidence)
			if canaryVariants(token).match(evidence) != "" {
				t.Fatal("content token leaked in evidence")
			}
			if status == model.Confirmed {
				if len(result.Evidence) != 1 || result.Evidence[0].Kind != model.EvidenceObserved || result.Evidence[0].Source != model.SourceMCPStdio {
					t.Fatal("missing observation")
				}
				expectedVariant := "raw"
				switch kind {
				case "hex lower", "hex upper":
					// Hex-encoded ASCII hex tokens contain only decimal digits.
					expectedVariant = "hex_lower"
				}
				for _, expected := range []string{"boundary_claim=run_cmd_workspace_placeholder", "payload=" + traversalPayloads(fixtures.FileID())[calls-1], "variant=" + expectedVariant + " ", "content_path=" + path} {
					if !strings.Contains(result.Evidence[0].Detail, expected) {
						t.Fatalf("missing evidence field %s", expected)
					}
				}
			} else if len(result.Evidence) != 0 {
				t.Fatal("unexpected positive evidence")
			}
		})
	}
}

func TestFSVerifierSkipsWithoutWorkspace(t *testing.T) {
	result, err := (FSVerifier{}).Verify(nil, config.Config{}, nil, mcpclient.LiveTool{}, "")
	assertFSOutcome(t, result, err, model.Skipped, model.NoWorkspaceClaim)
}

func TestFSVerifierUnsupportedArguments(t *testing.T) {
	fixtures, token := fsFixtures(t)
	for _, schema := range []string{
		`{}`, `{"oneOf":[]}`, `{"required":["path"],"properties":{"path":{"enum":["fixed"]}}}`,
		`{"required":["path"],"properties":{"path":{"type":"integer"}}}`,
		`{"required":["path"],"properties":{"path":{"type":"object"}}}`,
		`{"required":["path","echo"],"properties":{"path":{"type":"string"},"echo":{"enum":["` + token + `"]}}}`,
	} {
		peer := contractPeer{ctx: t.Context(), init: func() error { return nil }, call: func(string, map[string]any) (mcpclient.CallResult, error) {
			t.Fatal("unsupported arguments were sent")
			return mcpclient.CallResult{}, nil
		}}
		result, err := (FSVerifier{}).Verify(peer, config.Config{HasWorkspaceClaim: true}, fixtures, mcpclient.LiveTool{InputSchema: json.RawMessage(schema)}, "path")
		assertFSOutcome(t, result, err, model.Inconclusive, model.UnsupportedSchema)
	}
}

func TestFSVerifierSetupFailures(t *testing.T) {
	fixtures, _ := fsFixtures(t)
	for _, err := range []error{mcpclient.ErrHandshakeFailed, mcpclient.ErrTimeout, mcpclient.ErrServerCrash} {
		peer := contractPeer{ctx: t.Context(), init: func() error { return err }}
		result, callErr := (FSVerifier{}).Verify(peer, config.Config{HasWorkspaceClaim: true}, fixtures, mcpclient.LiveTool{}, "path")
		expected := verificationFailure(t.Context(), err)
		assertFSOutcome(t, result, callErr, expected.Status, *expected.Reason)
	}
	if err := fixtures.Cleanup(); err != nil {
		t.Fatal(err)
	}
	_, err := (FSVerifier{}).Verify(nil, config.Config{HasWorkspaceClaim: true}, fixtures, mcpclient.LiveTool{}, "path")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture error not propagated: %v", err)
	}
}

func TestCanaryBase64Alignments(t *testing.T) {
	_, token := fsFixtures(t)
	matcher := canaryVariants(token)
	for _, enc := range []struct {
		name     string
		encoding *base64.Encoding
	}{{"standard", base64.StdEncoding}, {"url", base64.URLEncoding}} {
		for offset := range 3 {
			for _, trailing := range []string{"", "\xff", "\xff\xfe"} {
				t.Run(fmt.Sprintf("%s/%d/%d", enc.name, offset, len(trailing)), func(t *testing.T) {
					encoded := enc.encoding.EncodeToString([]byte(strings.Repeat("\xfe", offset) + token + trailing))
					variant, path, err := matcher.scan(fsText(t, encoded))
					if err != nil || variant == "" || path != "content[0].text" {
						t.Fatalf("encoded token missed: %s %s %v", variant, path, err)
					}
					if enc.name == "standard" {
						response := mcpclient.CallResult{Content: []json.RawMessage{fsJSON(t, map[string]string{"data": encoded})}}
						variant, path, err = matcher.scan(response)
						if err != nil || variant != "raw" || path != "content[0].data" {
							t.Fatalf("decoded token missed: %s %s %v", variant, path, err)
						}
					}
				})
			}
		}
	}
}

func TestCanaryOracleBounds(t *testing.T) {
	_, token := fsFixtures(t)
	matcher := canaryVariants(token)
	for _, tc := range []struct {
		name     string
		response mcpclient.CallResult
		want     error
	}{
		{"raw frame", mcpclient.CallResult{RawFrame: bytes.Repeat([]byte("a"), oracleByteLimit+1)}, mcpclient.ErrResponseTruncated},
		{"structured", mcpclient.CallResult{StructuredContent: bytes.Repeat([]byte("a"), oracleByteLimit+1)}, mcpclient.ErrResponseTruncated},
		{"aggregate", mcpclient.CallResult{Content: []json.RawMessage{fsJSON(t, map[string]string{"text": strings.Repeat("a", oracleByteLimit/2)}), fsJSON(t, map[string]string{"text": strings.Repeat("b", oracleByteLimit/2)})}}, mcpclient.ErrResponseTruncated},
		{"bad base64", mcpclient.CallResult{Content: []json.RawMessage{json.RawMessage(`{"data":"???"}`)}}, mcpclient.ErrProtocolViolation},
		{"bad content", mcpclient.CallResult{Content: []json.RawMessage{json.RawMessage(`{"text":[]}`)}}, mcpclient.ErrProtocolViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			variant, _, err := matcher.scan(tc.response)
			if variant != "" || !errors.Is(err, tc.want) {
				t.Fatalf("variant=%s err=%v", variant, err)
			}
		})
	}
	_, err := decodeCanaryData(strings.Repeat("A", base64.StdEncoding.EncodedLen(oracleByteLimit+1)))
	if !errors.Is(err, mcpclient.ErrResponseTruncated) {
		t.Fatalf("decode bound: %v", err)
	}
}

func TestCanaryDecodedLimit(t *testing.T) {
	for _, size := range []int{oracleByteLimit - 1, oracleByteLimit, oracleByteLimit + 1} {
		data := bytes.Repeat([]byte("a"), size)
		decoded, err := decodeCanaryData(base64.StdEncoding.EncodeToString(data))
		if size <= oracleByteLimit {
			if err != nil || !bytes.Equal(decoded, data) {
				t.Fatalf("size %d: decoded %d, error %v", size, len(decoded), err)
			}
		} else if !errors.Is(err, mcpclient.ErrResponseTruncated) {
			t.Fatalf("oversize accepted: %v", err)
		}
	}
}

func TestFSVerifierMCPClient(t *testing.T) {
	for _, kind := range []string{"escaped text", "rpc error", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			fixtures, token := fsFixtures(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			requests, input := io.Pipe()
			output, responses := io.Pipe()
			client := mcpclient.New(ctx, input, output, io.NopCloser(strings.NewReader("")))
			defer func() { _ = client.Close(); _ = requests.Close(); _ = responses.Close() }()
			done := make(chan error, 1)
			go func() {
				decoder := json.NewDecoder(requests)
				for _, method := range []string{"initialize", "notifications/initialized", "tools/call"} {
					var request struct {
						Method string
						ID     json.RawMessage
						Params json.RawMessage
					}
					if err := decoder.Decode(&request); err != nil {
						done <- err
						return
					}
					if request.Method != method || bytes.Contains(request.Params, []byte(token)) {
						done <- errors.New("unexpected request or canary in request")
						return
					}
					switch method {
					case "initialize":
						if _, err := fmt.Fprintf(responses, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2025-11-25\"}}\n", request.ID); err != nil {
							done <- err
							return
						}
					case "tools/call":
						var err error
						switch kind {
						case "escaped text":
							var escaped strings.Builder
							for _, r := range token {
								fmt.Fprintf(&escaped, `\u%04x`, r)
							}
							_, err = fmt.Fprintf(responses, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}]}}\n", request.ID, escaped.String())
						case "rpc error":
							_, err = fmt.Fprintf(responses, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-1,\"message\":\"%s\"}}\n", request.ID, token)
						case "truncated":
							_, err = responses.Write(bytes.Repeat([]byte("x"), oracleByteLimit))
						}
						done <- err
						return
					}
				}
			}()
			peer := contractPeer{ctx: ctx, init: func() error { return client.Initialize(ctx) }, call: func(name string, args map[string]any) (mcpclient.CallResult, error) {
				return client.CallTool(ctx, name, args)
			}}
			result, err := (FSVerifier{}).Verify(peer, config.Config{HasWorkspaceClaim: true}, fixtures, mcpclient.LiveTool{Name: "read", InputSchema: json.RawMessage(fsSchema)}, "path")
			status, reason := model.Confirmed, model.DynamicReason("")
			if kind == "truncated" {
				status, reason = model.Inconclusive, model.ResponseTruncated
			}
			assertFSOutcome(t, result, err, status, reason)
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
			if canaryVariants(token).match(fsJSON(t, result.Evidence)) != "" {
				t.Fatal("canary leaked into evidence")
			}
		})
	}
}

func TestCanaryDistinctEncodingVariants(t *testing.T) {
	// Exercise alphabet differences that the fixture's ASCII hex tokens lack.
	token := make([]byte, 64)
	for i := range token {
		token[i] = byte(151 + i*7)
	}
	matcher := canaryVariants(string(token))
	encodedHex := hex.EncodeToString(token)
	for _, tc := range []struct{ value, name string }{{encodedHex, "hex_lower"}, {strings.ToUpper(encodedHex), "hex_upper"}} {
		if got := matcher.match([]byte(tc.value)); got != tc.name {
			t.Fatalf("variant=%s, want %s", got, tc.name)
		}
	}
	for _, enc := range []struct {
		name     string
		encoding *base64.Encoding
	}{{"standard", base64.StdEncoding}, {"url", base64.URLEncoding}} {
		for offset := range 3 {
			data := append(bytes.Repeat([]byte{0xfe}, offset), token...)
			encoded := enc.encoding.EncodeToString(append(data, 0xff))
			want := fmt.Sprintf("base64_%s_offset_%d", enc.name, offset)
			if got := matcher.match([]byte(encoded)); got != want {
				t.Fatalf("variant=%s, want %s", got, want)
			}
		}
	}
}
