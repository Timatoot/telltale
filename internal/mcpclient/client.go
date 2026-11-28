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
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/report"
)

const (
	protocolVersion = "2025-11-25"
	frameLimit      = 2 << 20 // Includes the terminating newline.
	noiseLimit      = 64 << 10
	stderrLimit     = 64 << 10
	discardLimit    = 16
	pageLimit       = 50
	toolLimit       = 1000
	listChanged     = "notifications/tools/list_changed"
)

type reply struct {
	frame  []byte
	result json.RawMessage
	err    *RPCError
}

// Client serializes operations while continuously servicing incoming traffic,
// including notifications between RPCs. Close joins all transport workers.
type Client struct {
	ctx   context.Context
	stop  context.CancelCauseFunc
	stdin io.WriteCloser
	gate  chan struct{}

	// Only the operation holding gate advances nextID or changes initialized.
	nextID      int64
	initialized bool
	writeMu     sync.Mutex
	pendingMu   sync.Mutex
	pendingID   string
	pending     chan reply

	workers  sync.WaitGroup
	closeErr error // Published by workers.Wait.
	changed  atomic.Bool
	stderr   stderrRing
}

// New takes ownership of the pipes. Their Close methods must interrupt pending
// I/O. A session without an explicit deadline uses telltale's session default.
func New(session context.Context, stdin io.WriteCloser, stdout, stderr io.ReadCloser) *Client {
	release := func() {}
	if _, ok := session.Deadline(); !ok {
		session, release = context.WithTimeout(session, config.DefaultTimeout)
	}
	ctx, stop := context.WithCancelCause(session)
	c := &Client{ctx: ctx, stop: stop, stdin: stdin, gate: make(chan struct{}, 1)}
	c.workers.Go(func() {
		<-ctx.Done()
		c.closeErr = errors.Join(stdin.Close(), stdout.Close(), stderr.Close())
		release()
	})
	c.workers.Go(func() {
		_, _ = io.Copy(&c.stderr, stderr)
	})
	c.workers.Go(func() { c.stop(c.readLoop(stdout)) })
	return c
}

func (c *Client) Close() error {
	c.stop(io.ErrClosedPipe)
	c.workers.Wait()
	return c.closeErr
}

// Evidence coalesces repeated notifications into one observed fact.
func (c *Client) Evidence() []model.EvidenceItem {
	if !c.changed.Load() {
		return nil
	}
	return []model.EvidenceItem{{Kind: model.EvidenceObserved, Source: model.SourceMCPStdio, Detail: listChanged}}
}

// StderrExcerpt returns a sanitized snapshot of the retained stderr tail.
func (c *Client) StderrExcerpt(canary string) string {
	return report.Sanitize(c.stderr.tail(), canary, stderrLimit)
}

type stderrRing struct {
	mu   sync.Mutex
	buf  [stderrLimit]byte
	end  int
	size int
}

func (r *stderrRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	if n >= len(r.buf) {
		p = p[n-len(r.buf):]
	}
	first := copy(r.buf[r.end:], p)
	copy(r.buf[:], p[first:])
	r.end = (r.end + len(p)) % len(r.buf)
	r.size = min(len(r.buf), r.size+len(p))
	return n, nil
}

func (r *stderrRing) tail() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size < len(r.buf) {
		return string(r.buf[:r.size])
	}
	return string(r.buf[r.end:]) + string(r.buf[:r.end])
}

func transportError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrTimeout, err)
	}
	return err
}

// operate owns the request sequence for the entire handshake, list, or call.
// Cancellation during an operation invalidates its session and interrupts both
// pipes, including a write of a -32601 reply blocked in the reader worker.
func (c *Client) operate(ctx context.Context, fn func() error) error {
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return transportError(ctx.Err())
	case <-c.ctx.Done():
		return transportError(context.Cause(c.ctx))
	}
	if err := ctx.Err(); err != nil {
		return transportError(err)
	}
	if err := context.Cause(c.ctx); err != nil {
		return transportError(err)
	}
	done := make(chan struct{})
	cancel := context.AfterFunc(ctx, func() {
		c.stop(ctx.Err())
		close(done)
	})
	err := fn()
	if !cancel() {
		<-done
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		c.stop(ctxErr)
		return transportError(ctxErr)
	}
	return err
}

func (c *Client) write(msg envelope) error {
	line, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode MCP message: %w", err)
	}
	if len(line) >= frameLimit {
		return ErrProtocolViolation
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.stdin.Write(append(line, '\n'))
	if err != nil || n != len(line)+1 {
		c.stop(ErrServerCrash)
		return transportError(context.Cause(c.ctx))
	}
	return nil
}

func (c *Client) exchange(method string, params any) (reply, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return reply{}, fmt.Errorf("encode MCP params: %w", err)
	}
	c.nextID++
	id := strconv.FormatInt(c.nextID, 10)
	ch := make(chan reply, 1)
	c.pendingMu.Lock()
	c.pendingID, c.pending = id, ch
	c.pendingMu.Unlock()
	if err := c.write(envelope{Version: "2.0", ID: json.RawMessage(id), Method: method, Params: data}); err != nil {
		c.stop(err)
		return reply{}, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-c.ctx.Done():
		// A peer can close stdout immediately after a complete final reply.
		select {
		case r := <-ch:
			return r, nil
		default:
			return reply{}, transportError(context.Cause(c.ctx))
		}
	}
}

func (c *Client) readLoop(stdout io.Reader) error {
	reader := bufio.NewReaderSize(stdout, frameLimit)
	var noise, discards int
	for c.ctx.Err() == nil {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return ErrResponseTruncated
		}
		if err != nil {
			return ErrServerCrash
		}
		if !json.Valid(line) {
			noise += len(line)
			if noise > noiseLimit {
				return ErrProtocolViolation
			}
			continue
		}
		var msg envelope
		if !utf8.Valid(line) || json.Unmarshal(line, &msg) != nil || msg.Version != "2.0" {
			return ErrProtocolViolation
		}
		if msg.Method != "" {
			if err := c.peerMethod(msg); err != nil {
				return err
			}
			continue
		}
		if !validID(msg.ID) || (msg.Error == nil) == (msg.Result == nil) {
			return ErrProtocolViolation
		}
		r := reply{result: msg.Result}
		if msg.Error != nil {
			var e struct {
				Code    *int            `json:"code"`
				Message *string         `json:"message"`
				Data    json.RawMessage `json:"data"`
			}
			if json.Unmarshal(msg.Error, &e) != nil || e.Code == nil || e.Message == nil {
				return ErrProtocolViolation
			}
			r.err = &RPCError{Code: *e.Code, Message: *e.Message, Data: e.Data}
		}
		c.pendingMu.Lock()
		if c.pending != nil && c.pendingID == string(msg.ID) {
			r.frame = bytes.Clone(line[:len(line)-1])
			c.pending <- r
			c.pending = nil
		} else {
			discards++
		}
		c.pendingMu.Unlock()
		if discards > discardLimit {
			return ErrProtocolViolation
		}
	}
	return context.Cause(c.ctx)
}

// Called only for raw IDs from syntactically valid JSON.
func validID(id json.RawMessage) bool {
	if len(id) == 0 {
		return false
	}
	return id[0] == '"' || ((id[0] == '-' || id[0] >= '0' && id[0] <= '9') && !bytes.ContainsAny(id, ".eE"))
}

func (c *Client) peerMethod(msg envelope) error {
	if msg.Result != nil || msg.Error != nil {
		return ErrProtocolViolation
	}
	if msg.ID == nil {
		if msg.Method == listChanged {
			c.changed.Store(true)
		}
		return nil
	}
	if !validID(msg.ID) {
		return ErrProtocolViolation
	}
	return c.write(envelope{Version: "2.0", ID: msg.ID, Error: json.RawMessage(`{"code":-32601,"message":"Method not found"}`)})
}

// Initialize negotiates the pinned revision and completes the MCP handshake.
func (c *Client) Initialize(ctx context.Context) error {
	return c.operate(ctx, func() error {
		if c.initialized {
			return ErrProtocolViolation
		}
		r, err := c.exchange("initialize", initializeParams{
			ProtocolVersion: protocolVersion,
			ClientInfo:      implementation{Name: "telltale", Version: "dev"},
		})
		if err != nil {
			return err
		}
		var result initializeResult
		if r.err != nil || json.Unmarshal(r.result, &result) != nil || result.ProtocolVersion != protocolVersion {
			c.stop(ErrHandshakeFailed)
			return ErrHandshakeFailed
		}
		if err := c.write(envelope{Version: "2.0", Method: "notifications/initialized"}); err != nil {
			return err
		}
		c.initialized = true
		return nil
	})
}

// appendPage decodes one tool at a time to enforce the inventory bound before
// allocating a slice proportional to the peer's claimed number of tools.
func appendPage(tools []LiveTool, raw json.RawMessage) ([]LiveTool, error) {
	if len(raw) == 0 || raw[0] != '[' {
		return tools, ErrProtocolViolation
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return tools, ErrProtocolViolation
	}
	for dec.More() {
		if len(tools) >= toolLimit {
			return tools, ErrProtocolViolation
		}
		var tool LiveTool
		if dec.Decode(&tool) != nil || tool.Name == "" || len(tool.InputSchema) == 0 || tool.InputSchema[0] != '{' {
			return tools, ErrProtocolViolation
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

// ListTools returns only complete inventories. A continuation beyond either
// bound or a cursor cycle invalidates the session and the whole inventory.
func (c *Client) ListTools(ctx context.Context) ([]LiveTool, error) {
	var tools []LiveTool
	err := c.operate(ctx, func() error {
		if !c.initialized {
			return ErrHandshakeFailed
		}
		var cursor *string
		seen := make(map[string]bool)
		for page := 1; ; page++ {
			r, err := c.exchange("tools/list", listParams{Cursor: cursor})
			if err != nil {
				return err
			}
			if r.err != nil {
				return r.err
			}
			var result listResult
			if json.Unmarshal(r.result, &result) != nil {
				c.stop(ErrProtocolViolation)
				return ErrProtocolViolation
			}
			tools, err = appendPage(tools, result.Tools)
			if err != nil {
				c.stop(err)
				return err
			}
			cursor = result.NextCursor
			if cursor == nil {
				return nil
			}
			if seen[*cursor] || page == pageLimit || len(tools) == toolLimit {
				c.stop(ErrProtocolViolation)
				return ErrProtocolViolation
			}
			seen[*cursor] = true
		}
	})
	if err != nil {
		return nil, err
	}
	return tools, nil
}

// CallTool preserves the full matching response, including JSON-RPC errors.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (CallResult, error) {
	var result CallResult
	err := c.operate(ctx, func() error {
		if !c.initialized {
			return ErrHandshakeFailed
		}
		if args == nil {
			args = map[string]any{}
		}
		r, err := c.exchange("tools/call", callParams{Name: name, Arguments: args})
		if err != nil {
			return err
		}
		result.RawFrame = r.frame
		if r.err != nil {
			return r.err
		}
		if json.Unmarshal(r.result, &result) != nil || result.Content == nil {
			c.stop(ErrProtocolViolation)
			return ErrProtocolViolation
		}
		return nil
	})
	return result, err
}
