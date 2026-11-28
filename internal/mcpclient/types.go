// Package mcpclient speaks MCP JSON-RPC over an already isolated stdio session.
package mcpclient

import (
	"encoding/json"
	"errors"
)

var (
	ErrHandshakeFailed   = errors.New("MCP handshake failed")
	ErrProtocolViolation = errors.New("MCP protocol violation")
	ErrResponseTruncated = errors.New("MCP response exceeded frame limit")
	ErrTimeout           = errors.New("MCP deadline exceeded")
	ErrServerCrash       = errors.New("MCP peer disconnected")
)

// Raw IDs preserve the distinction between a peer's string and numeric IDs.
type envelope struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type initializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    struct{}       `json:"capabilities"`
	ClientInfo      implementation `json:"clientInfo"`
}

type implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
}

type listParams struct {
	Cursor *string `json:"cursor,omitempty"`
}

type listResult struct {
	Tools      json.RawMessage `json:"tools"`
	NextCursor *string         `json:"nextCursor"`
}

// ToolAnnotations mirrors optional MCP tool annotation hints from tools/list.
type ToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint"`
	DestructiveHint *bool `json:"destructiveHint"`
	OpenWorldHint   *bool `json:"openWorldHint"`
}

// LiveTool keeps the peer's schema intact for the inventory consumer.
type LiveTool struct {
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations ToolAnnotations `json:"annotations"`
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// CallResult includes the original response frame (without the delimiter),
// even when CallTool returns an RPCError. Content items are kept verbatim so
// consumers can interpret every MCP content type without losing fields.
type CallResult struct {
	RawFrame          []byte            `json:"-"`
	Content           []json.RawMessage `json:"content"`
	StructuredContent json.RawMessage   `json:"structuredContent"`
	IsError           bool              `json:"isError"`
}

// RPCError identifies a valid error response. Error() excludes peer text.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (*RPCError) Error() string { return "MCP peer returned a JSON-RPC error" }
