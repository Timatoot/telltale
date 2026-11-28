package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/sandbox"
)

const oracleByteLimit = 2 << 20

// FSVerifier tests the asserted workspace boundary using a private canary.
type FSVerifier struct{}

// Verify uses one fresh, already isolated session for all payloads. The caller
// owns teardown. Only local fixture failures return an error, while target
// failures become verification outcomes.
func (FSVerifier) Verify(session verifierSession, cfg config.Config, fixtures *sandbox.FixtureManager, tool mcpclient.LiveTool, taintedParameter string) (VerificationResult, error) {
	if !cfg.HasWorkspaceClaim {
		return VerificationResult{Status: model.Skipped, Reason: new(model.NoWorkspaceClaim)}, nil
	}
	token, err := fixtures.ContentToken()
	if err != nil {
		return VerificationResult{}, fmt.Errorf("read verification canary: %w", err)
	}
	if len(token) != 64 {
		return VerificationResult{}, errors.New("invalid verification canary length")
	}
	return verifyFS(session, tool, taintedParameter, traversalPayloads(fixtures.FileID()), canaryVariants(token)), nil
}

func verifyFS(session verifierSession, tool mcpclient.LiveTool, taintedParameter string, payloads []string, variants canaryMatcher) VerificationResult {
	ctx := session.Context()
	if err := session.Initialize(ctx); err != nil {
		return verificationFailure(ctx, err)
	}
	toolError := false
	for _, payload := range payloads {
		if ctx.Err() != nil {
			return verificationFailure(ctx, ctx.Err())
		}
		args, err := SynthesizeArgs(tool.InputSchema, taintedParameter, payload)
		// Optional, enum, and non-string arguments can prevent injection. An
		// unexercised parameter cannot support a clean negative result.
		if err != nil || args[taintedParameter] != payload {
			return inconclusive(model.UnsupportedSchema)
		}
		request, err := json.Marshal(struct {
			Name      string
			Arguments map[string]any
		}{tool.Name, args})
		if err != nil || variants.match(request) != "" {
			return inconclusive(model.UnsupportedSchema)
		}
		response, callErr := session.CallTool(ctx, tool.Name, args)
		variant, path, scanErr := variants.scan(response)
		if variant != "" {
			return VerificationResult{Status: model.Confirmed, Evidence: []model.EvidenceItem{{
				Kind: model.EvidenceObserved, Source: model.SourceMCPStdio,
				Detail: fmt.Sprintf("boundary_claim=run_cmd_workspace_placeholder payload=%s variant=%s content_path=%s", payload, variant, path),
			}}}
		}
		var rpcErr *mcpclient.RPCError
		if scanErr != nil || ctx.Err() != nil || (callErr != nil && !errors.As(callErr, &rpcErr)) {
			return verificationFailure(ctx, errors.Join(callErr, scanErr))
		}
		toolError = toolError || response.IsError || callErr != nil
	}
	if toolError {
		return inconclusive(model.ToolError)
	}
	return VerificationResult{Status: model.NotReproduced}
}

func traversalPayloads(fileID string) []string {
	return []string{
		"../restricted/" + fileID,
		"../../restricted/" + fileID,
		"../../../restricted/" + fileID,
		"../../../../restricted/" + fileID,
		"../../../../../restricted/" + fileID,
		"../../../../../../restricted/" + fileID,
		"../../../../../../../restricted/" + fileID,
		"../../../../../../../../restricted/" + fileID,
		"/restricted/" + fileID,
		"/workspace/../restricted/" + fileID,
	}
}

type canaryVariant struct {
	name  string
	value []byte
}

type canaryMatcher []canaryVariant

func canaryVariants(token string) canaryMatcher {
	variants := canaryMatcher{{"raw", []byte(token)}}
	for _, enc := range []struct {
		name     string
		encoding *base64.Encoding
	}{{"base64_standard", base64.StdEncoding}, {"base64_url", base64.URLEncoding}} {
		for offset := range 3 {
			encoded := enc.encoding.EncodeToString([]byte(strings.Repeat("\x00", offset) + token))
			// Keep only sextets wholly inside the token. Boundary sextets can
			// depend on arbitrary preceding/following bytes or padding.
			start := (offset*8 + 5) / 6
			end := (offset + len(token)) * 8 / 6
			variants = append(variants, canaryVariant{fmt.Sprintf("%s_offset_%d", enc.name, offset), []byte(encoded[start:end])})
		}
	}
	encodedHex := hex.EncodeToString([]byte(token))
	return append(variants, canaryVariant{"hex_lower", []byte(encodedHex)}, canaryVariant{"hex_upper", []byte(strings.ToUpper(encodedHex))})
}

func (v canaryMatcher) match(data []byte) string {
	for _, variant := range v {
		if len(variant.value) > 0 && bytes.Contains(data, variant.value) {
			return variant.name
		}
	}
	return ""
}

func (v canaryMatcher) scan(response mcpclient.CallResult) (variant, path string, err error) {
	// Production frames are capped by mcpclient. Keep the oracle bounded even
	// for independently constructed CallResults, including aggregate text.
	raw := response.RawFrame
	if len(raw) > oracleByteLimit {
		raw = raw[:oracleByteLimit]
		err = mcpclient.ErrResponseTruncated
	}
	if variant := v.match(raw); variant != "" {
		return variant, "raw_frame", nil
	}
	remaining := oracleByteLimit
	var texts strings.Builder
	for i, rawItem := range response.Content {
		if len(rawItem) > remaining || i >= oracleByteLimit {
			return "", "", mcpclient.ErrResponseTruncated
		}
		remaining -= len(rawItem)
		var item struct {
			Text     string `json:"text"`
			Data     string `json:"data"`
			Resource struct {
				Blob string `json:"blob"`
			} `json:"resource"`
		}
		if json.Unmarshal(rawItem, &item) != nil {
			if err == nil {
				err = mcpclient.ErrProtocolViolation
			}
			continue
		}
		if variant := v.match([]byte(item.Text)); variant != "" {
			return variant, fmt.Sprintf("content[%d].text", i), nil
		}
		texts.WriteString(item.Text)
		for _, field := range []struct{ name, value string }{{"data", item.Data}, {"resource.blob", item.Resource.Blob}} {
			decoded, decodeErr := decodeCanaryData(field.value)
			if variant := v.match(decoded); variant != "" {
				return variant, fmt.Sprintf("content[%d].%s", i, field.name), nil
			}
			if err == nil {
				err = decodeErr
			}
		}
	}
	if variant := v.match([]byte(texts.String())); variant != "" {
		return variant, "content[].text (concatenated)", nil
	}
	if len(response.StructuredContent) > remaining {
		return "", "", mcpclient.ErrResponseTruncated
	}
	if variant := v.match(response.StructuredContent); variant != "" {
		return variant, "structuredContent", nil
	}
	return "", "", err
}

func decodeCanaryData(data string) ([]byte, error) {
	// Bound both the encoded input and decoded output. A streaming decoder
	// accepts padding at the exact decoded limit without overallocating.
	if len(data) > base64.StdEncoding.EncodedLen(oracleByteLimit) {
		return nil, mcpclient.ErrResponseTruncated
	}
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	decoded, err := io.ReadAll(io.LimitReader(decoder, oracleByteLimit+1))
	if len(decoded) > oracleByteLimit {
		return decoded[:oracleByteLimit], mcpclient.ErrResponseTruncated
	}
	if err != nil {
		return decoded, mcpclient.ErrProtocolViolation
	}
	return decoded, nil
}
