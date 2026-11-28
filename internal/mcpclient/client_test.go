package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/model"
)

// Tests drive the peer synchronously. A session deadline also unblocks the
// fixture's pipe operations if the client fails to send a required message.
type peer struct {
	client *Client
	in     *bufio.Reader
	out    *io.PipeWriter
	stderr *io.PipeWriter
}

func newPeer(t *testing.T) *peer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	pr, cw := io.Pipe()
	cr, pw := io.Pipe()
	er, ew := io.Pipe()
	c := New(ctx, cw, cr, er)
	t.Cleanup(func() {
		cancel()
		if err := c.Close(); err != nil {
			t.Error(err)
		}
		_ = pr.Close()
		_ = pw.Close()
		_ = ew.Close()
	})
	return &peer{client: c, in: bufio.NewReader(pr), out: pw, stderr: ew}
}

func async[T any](fn func() T) <-chan T {
	result := make(chan T, 1)
	go func() { result <- fn() }()
	return result
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client")
		var zero T
		return zero
	}
}

func (p *peer) read(t *testing.T) envelope {
	t.Helper()
	line, err := p.in.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var msg envelope
	if err := json.Unmarshal(line, &msg); err != nil || msg.Version != "2.0" {
		t.Fatalf("invalid outgoing message %q", line)
	}
	return msg
}

func (p *peer) send(t *testing.T, data string) {
	t.Helper()
	if _, err := io.WriteString(p.out, data); err != nil {
		t.Fatal(err)
	}
}

func (p *peer) result(t *testing.T, id json.RawMessage, result string) {
	t.Helper()
	p.send(t, fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", id, result))
}

func (p *peer) beginHandshake(t *testing.T) (json.RawMessage, <-chan error) {
	t.Helper()
	done := async(func() error { return p.client.Initialize(t.Context()) })
	msg := p.read(t)
	var params struct {
		Version string                     `json:"protocolVersion"`
		Caps    map[string]json.RawMessage `json:"capabilities"`
		Info    implementation             `json:"clientInfo"`
	}
	if msg.Method != "initialize" || len(msg.ID) == 0 || json.Unmarshal(msg.Params, &params) != nil ||
		params.Version != "2025-11-25" || params.Caps == nil || len(params.Caps) != 0 ||
		params.Info.Name != "telltale" || params.Info.Version == "" {
		t.Fatalf("unexpected handshake %+v", msg)
	}
	return msg.ID, done
}

func (p *peer) initialize(t *testing.T) {
	t.Helper()
	id, done := p.beginHandshake(t)
	p.result(t, id, `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`)
	msg := p.read(t)
	if msg.Method != "notifications/initialized" || msg.ID != nil {
		t.Fatalf("unexpected notification %+v", msg)
	}
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
}

func wantError(t *testing.T, actual, want error) {
	t.Helper()
	if !errors.Is(actual, want) {
		t.Fatalf("got %v, want %v", actual, want)
	}
}

func TestHandshakeAndPeerTraffic(t *testing.T) {
	p := newPeer(t)
	p.initialize(t)
	for _, request := range []struct{ method, id string }{
		{"roots/list", `"peer-id"`}, {"sampling/createMessage", "1"},
	} {
		p.send(t, fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":%q,\"id\":%s}\n", request.method, request.id))
		msg := p.read(t)
		var rpcErr RPCError
		if string(msg.ID) != request.id || msg.Result != nil || json.Unmarshal(msg.Error, &rpcErr) != nil || rpcErr.Code != -32601 {
			t.Fatalf("unexpected peer request reply %+v", msg)
		}
	}

	done := async(func() error {
		result, err := p.client.CallTool(t.Context(), "echo", map[string]any{"word": "hello"})
		if err != nil {
			return err
		}
		if !result.IsError || len(result.Content) != 1 || string(result.Content[0]) != `{"type":"text","text":"hello"}` ||
			string(result.StructuredContent) != `{"count":1}` || !bytes.HasPrefix(result.RawFrame, []byte("  {")) {
			return errors.New("tool result lost content, structuredContent, isError or original frame")
		}
		return nil
	})
	msg := p.read(t)
	if msg.Method != "tools/call" || string(msg.Params) != `{"name":"echo","arguments":{"word":"hello"}}` {
		t.Fatalf("unexpected call %+v", msg)
	}
	p.send(t, fmt.Sprintf("  {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello\"}],\"structuredContent\":{\"count\":1},\"isError\":true}}\n", msg.ID))
	if err := receive(t, done); err != nil {
		t.Fatal(err)
	}
	p.send(t, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/other\"}\n")
	// A peer request is a synchronization barrier for prior notifications.
	barrier := func() {
		p.send(t, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n")
		_ = p.read(t)
	}
	barrier()
	if len(p.client.Evidence()) != 0 {
		t.Fatal("unexpected evidence for unknown notification")
	}
	for range 3 {
		p.send(t, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n")
	}
	barrier()
	evidence := p.client.Evidence()
	if len(evidence) != 1 || evidence[0].Kind != model.EvidenceObserved || evidence[0].Source != model.SourceMCPStdio ||
		evidence[0].Detail != "notifications/tools/list_changed" {
		t.Fatalf("unexpected evidence %+v", evidence)
	}
}

func TestCallErrors(t *testing.T) {
	for _, tc := range []string{"RPC error", "EOF", "partial EOF", "invalid result"} {
		t.Run(tc, func(t *testing.T) {
			p := newPeer(t)
			p.initialize(t)
			type outcome struct {
				r   CallResult
				err error
			}
			done := async(func() outcome {
				r, err := p.client.CallTool(t.Context(), "echo", nil)
				return outcome{r, err}
			})
			msg := p.read(t)
			switch tc {
			case "RPC error":
				frame := fmt.Sprintf(` {"jsonrpc":"2.0","id":%s,"error":{"code":-1,"message":"private peer text","data":{"key":"value"}}}`, msg.ID)
				p.send(t, frame+"\n")
				got := receive(t, done)
				var e *RPCError
				if !errors.As(got.err, &e) || e.Code != -1 || string(got.r.RawFrame) != frame || strings.Contains(e.Error(), "private") {
					t.Fatal("JSON-RPC error or its raw frame was lost or exposed")
				}
			case "invalid result":
				p.result(t, msg.ID, `{}`)
				wantError(t, receive(t, done).err, ErrProtocolViolation)
			default:
				if tc == "partial EOF" {
					p.send(t, `{"jsonrpc":"2.0"`)
				}
				_ = p.out.Close()
				wantError(t, receive(t, done).err, ErrServerCrash)
			}
		})
	}
}

func TestUnsupportedVersion(t *testing.T) {
	p := newPeer(t)
	id, done := p.beginHandshake(t)
	p.result(t, id, `{"protocolVersion":"2025-06-18"}`)
	wantError(t, receive(t, done), ErrHandshakeFailed)
	_, err := p.in.ReadByte()
	wantError(t, err, io.EOF)
}

func TestStdoutBudgets(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want error
	}{
		{"noise at limit", strings.Repeat("x", (64<<10)-2) + "\n\n", nil},
		{"noise over limit", strings.Repeat("x", (64<<10)-1) + "\n\n", ErrProtocolViolation},
		{"no newline at cap", strings.Repeat("x", 2<<20), ErrResponseTruncated},
		{"oversized frame", strings.Repeat("x", 2<<20) + "\n", ErrResponseTruncated},
		{"invalid envelope", "{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":{}}\n", ErrProtocolViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPeer(t)
			id, done := p.beginHandshake(t)
			// The client may close before the final byte of an oversized write.
			_, _ = io.WriteString(p.out, tc.line)
			if tc.want == nil {
				frame := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25"}}`, id)
				p.send(t, frame+strings.Repeat(" ", (2<<20)-len(frame)-1)+"\n")
				_ = p.read(t)
			}
			wantError(t, receive(t, done), tc.want)
		})
	}
}

func TestIDDiscardBudget(t *testing.T) {
	for _, n := range []int{16, 17} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			p := newPeer(t)
			id, handshake := p.beginHandshake(t)
			for range 8 {
				p.result(t, json.RawMessage(`"1"`), `{}`) // A string ID cannot match numeric 1.
			}
			p.result(t, id, `{"protocolVersion":"2025-11-25"}`)
			_ = p.read(t)
			wantError(t, receive(t, handshake), nil)
			done := async(func() error {
				_, err := p.client.CallTool(t.Context(), "echo", nil)
				return err
			})
			call := p.read(t)
			for range n - 8 {
				p.result(t, id, `{}`) // Duplicate completed initialize ID.
			}
			if n == 17 {
				wantError(t, receive(t, done), ErrProtocolViolation)
			} else {
				p.result(t, call.ID, `{"content":[]}`)
				wantError(t, receive(t, done), nil)
			}
		})
	}
}

func TestPagination(t *testing.T) {
	const tool = `{"name":"echo","description":"text","inputSchema":{"type":"object"},"annotations":{"destructiveHint":false}}`
	for _, tc := range []struct {
		name            string
		pages           int
		lastTools       int
		continueAtLimit bool
		repeat          bool
		want            error
	}{
		{"two pages", 2, 1, false, false, nil},
		{"repeated cursor", 2, 1, false, true, ErrProtocolViolation},
		{"page boundary", 50, 1, false, false, nil},
		{"page overflow", 50, 1, true, false, ErrProtocolViolation},
		{"tool boundary", 2, 999, false, false, nil},
		{"tool overflow in page", 2, 1000, false, false, ErrProtocolViolation},
		{"tool continuation", 2, 999, true, false, ErrProtocolViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPeer(t)
			p.initialize(t)
			type outcome struct {
				tools []LiveTool
				err   error
			}
			done := async(func() outcome {
				tools, err := p.client.ListTools(t.Context())
				return outcome{tools, err}
			})
			var cursor *string
			for page := 1; page <= tc.pages; page++ {
				msg := p.read(t)
				var params listParams
				if msg.Method != "tools/list" || json.Unmarshal(msg.Params, &params) != nil ||
					(params.Cursor == nil) != (cursor == nil) || cursor != nil && *params.Cursor != *cursor {
					t.Fatalf("unexpected list request on page %d: %+v", page, msg)
				}
				next := ""
				if page < tc.pages || tc.continueAtLimit || tc.repeat {
					token := strconv.Itoa(page)
					if tc.repeat {
						token = "same"
					}
					cursor = &token
					next = fmt.Sprintf(`,"nextCursor":%q`, token)
				}
				count := 1
				if page == tc.pages {
					count = tc.lastTools
				}
				items := strings.Repeat(tool+",", count)
				p.result(t, msg.ID, `{"tools":[`+strings.TrimSuffix(items, ",")+`]`+next+`}`)
			}
			got := receive(t, done)
			wantError(t, got.err, tc.want)
			if tc.want != nil {
				if got.tools != nil {
					t.Fatal("partial inventory returned")
				}
				_, err := p.in.ReadByte()
				wantError(t, err, io.EOF)
				return
			}
			if len(got.tools) != tc.pages-1+tc.lastTools {
				t.Fatalf("got %d tools", len(got.tools))
			}
			first := got.tools[0]
			if first.Name != "echo" || first.Description == nil || *first.Description != "text" ||
				string(first.InputSchema) != `{"type":"object"}` || first.Annotations.ReadOnlyHint != nil ||
				first.Annotations.DestructiveHint == nil || *first.Annotations.DestructiveHint {
				t.Fatalf("lost wire tool metadata: %+v", first)
			}
		})
	}
}

func TestDeadlinesAndClose(t *testing.T) {
	for _, tc := range []struct {
		name            string
		readRequest     bool
		sessionDeadline bool
		explicitClose   bool
	}{
		{"blocked read RPC", true, false, false},
		{"blocked write RPC", false, false, false},
		{"blocked read session", true, true, false},
		{"blocked write session", false, true, false},
		{"close during read", true, false, true},
		{"close during write", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session, rpc := t.Context(), t.Context()
			timeout, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			if tc.sessionDeadline {
				session = timeout
			} else if !tc.explicitClose {
				rpc = timeout
			}
			pr, cw := io.Pipe()
			cr, pw := io.Pipe()
			er, ew := io.Pipe()
			t.Cleanup(func() {
				_ = pr.Close()
				_ = pw.Close()
				_ = ew.Close()
			})
			// Wait until Write actually starts before asserting it is interrupted.
			started := make(chan struct{})
			c := New(session, &signalWrite{cw, started}, cr, er)
			t.Cleanup(func() { _ = c.Close() })
			done := async(func() error { return c.Initialize(rpc) })
			receive(t, started)
			if tc.readRequest {
				if _, err := bufio.NewReader(pr).ReadBytes('\n'); err != nil {
					t.Fatal(err)
				}
			}
			if tc.explicitClose {
				wantError(t, receive(t, async(c.Close)), nil)
				wantError(t, receive(t, done), io.ErrClosedPipe)
			} else {
				err := receive(t, done)
				wantError(t, err, ErrTimeout)
				wantError(t, err, context.DeadlineExceeded)
			}
			wantError(t, receive(t, async(c.Close)), nil)
			_, err := pr.Read(make([]byte, 1))
			wantError(t, err, io.EOF)
			for _, w := range []*io.PipeWriter{pw, ew} {
				_, err = w.Write([]byte{'x'})
				wantError(t, err, io.ErrClosedPipe)
			}
		})
	}
}

type signalWrite struct {
	io.WriteCloser
	started chan struct{}
}

func (s *signalWrite) Write(p []byte) (int, error) {
	close(s.started)
	return s.WriteCloser.Write(p)
}

func TestStderrRing(t *testing.T) {
	p := newPeer(t)
	p.initialize(t)
	chunk := strings.Repeat("a", 64<<10)
	for _, s := range []string{"discarded prefix", chunk, chunk, " tail; password=example\x1b"} {
		if _, err := io.WriteString(p.stderr, s); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.stderr.Close()
	wantError(t, p.client.Close(), nil)
	raw := p.client.stderr.tail()
	if len(raw) != 64<<10 || !strings.HasSuffix(raw, " tail; password=example\x1b") || strings.Contains(raw, "prefix") {
		t.Fatal("incorrect retained stderr tail")
	}
}

func TestStderrRedaction(t *testing.T) {
	p := newPeer(t)
	if _, err := io.WriteString(p.stderr, "password=example\x1b canary"); err != nil {
		t.Fatal(err)
	}
	wantError(t, p.client.Close(), nil)
	if got := p.client.StderrExcerpt("canary"); got != "password=[REDACTED]<U+001B> [REDACTED]" {
		t.Errorf("sanitized stderr %q", got)
	}
}
