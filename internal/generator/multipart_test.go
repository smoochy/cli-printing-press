package generator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/naming"
	"github.com/mvanhorn/cli-printing-press/v4/internal/openapi"
	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMultipartRequestBodyUsesMultipartClient(t *testing.T) {
	t.Parallel()

	apiSpec := minimalSpec("uploadapi")
	apiSpec.Resources = map[string]spec.Resource{
		"assets": {
			Description: "Manage assets",
			Endpoints: map[string]spec.Endpoint{
				"list": {
					Method:      "GET",
					Path:        "/assets",
					Description: "List assets",
				},
				"upload": {
					Method:             "POST",
					Path:               "/assets",
					Description:        "Upload an asset",
					RequestContentType: "multipart/form-data",
					Body: []spec.Param{
						{Name: "assetData", Type: "string", Format: "binary", Required: true, Description: "Asset file"},
						{Name: "filename", Type: "string", Required: true, Description: "File name"},
						{Name: "metadata", Type: "object", Description: "Metadata as JSON"},
					},
				},
			},
		},
		"avatars": {
			Description: "Manage avatars",
			Endpoints: map[string]spec.Endpoint{
				"upload": {
					Method:             "POST",
					Path:               "/avatars",
					Description:        "Upload an avatar",
					RequestContentType: "multipart/form-data",
					Body: []spec.Param{
						{Name: "image", Type: "string", Format: "binary", Required: true, Description: "Avatar image"},
						{Name: "label", Type: "string", Description: "Label"},
					},
				},
			},
		},
	}

	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	require.NoError(t, New(apiSpec, outputDir).Generate())

	clientSrc := readGeneratedFile(t, outputDir, "internal", "client", "client.go")
	assert.Contains(t, clientSrc, `func (c *Client) PostMultipart(ctx context.Context, path string, fields map[string]string, fileFields map[string]string) (json.RawMessage, int, error)`)
	assert.Contains(t, clientSrc, `mime.TypeByExtension(filepath.Ext(path))`)
	assert.Contains(t, clientSrc, `writer.CreatePart(h)`)
	assert.NotContains(t, clientSrc, `writer.CreateFormFile(`)
	assert.Contains(t, clientSrc, `req.Header.Set("Content-Type", contentType)`)

	endpointSrc := readGeneratedFile(t, outputDir, "internal", "cli", "assets_upload.go")
	assert.Contains(t, endpointSrc, `return fmt.Errorf("required flag \"%s\" not set", "asset-data")`)
	assert.Contains(t, endpointSrc, `return fmt.Errorf("required flag \"%s\" not set", "filename")`)
	assert.Contains(t, endpointSrc, `fileFields["assetData"] = bodyAssetData`)
	assert.Contains(t, endpointSrc, `fields["filename"] = bodyFilename`)
	assert.Contains(t, endpointSrc, `fields["metadata"] = bodyMetadata`)
	assert.Contains(t, endpointSrc, `c.PostMultipartWithParams(cmd.Context(), path, params, fields, fileFields)`)
	assert.NotContains(t, endpointSrc, `"stdin"`)

	promotedSrc := readGeneratedFile(t, outputDir, "internal", "cli", "promoted_avatars.go")
	assert.Contains(t, promotedSrc, `return fmt.Errorf("required flag \"%s\" not set", "image")`)
	assert.Contains(t, promotedSrc, `fileFields["image"] = bodyImage`)
	assert.Contains(t, promotedSrc, `fields["label"] = bodyLabel`)
	assert.Contains(t, promotedSrc, `c.PostMultipartWithParams(cmd.Context(), path, params, fields, fileFields)`)
	assert.NotContains(t, promotedSrc, `"stdin"`)

	mcpSrc := readGeneratedFile(t, outputDir, "internal", "mcp", "tools.go")
	assert.Contains(t, mcpSrc, `makeAPIHandler("POST", "/assets", false, false, nil, mcpPageConfig{}, []mcpParamBinding`)
	assert.Contains(t, mcpSrc, `Format: "binary"`)
	assert.Contains(t, mcpSrc, `RequestContentType: "multipart/form-data"`)
	// Binary multipart params over MCP are routed through the confinement
	// resolver (base64 content by default, opt-in os.Root path mode) rather
	// than passed straight to the client as a raw caller-supplied path. This
	// locks out the regression where an MCP caller could name an arbitrary
	// local file for the server to read (CWE-22/CWE-73).
	assert.Contains(t, mcpSrc, `stagedPath, cleanupUpload, uploadErr := resolveMCPMultipartFile(binding.WireName, filenameHint, v)`)
	assert.Contains(t, mcpSrc, `multipartFileFields[binding.WireName] = stagedPath`)
	assert.NotContains(t, mcpSrc, `multipartFileFields[binding.WireName] = fmt.Sprintf("%v", v)`)
	assert.Contains(t, mcpSrc, `func resolveMCPMultipartFile(field, filenameHint string, v any) (string, func(), error)`)
	// The optional companion filename arg is declared in the tool schema and
	// registered as a known arg, and a decoded payload is bounded by a size cap.
	assert.Contains(t, mcpSrc, `mcplib.WithString("assetData_filename"`)
	assert.Contains(t, mcpSrc, `knownArgs[binding.PublicName+"_filename"] = true`)
	assert.Contains(t, mcpSrc, `const mcpMaxUploadBytes =`)
	// The opt-in path mode is a dedicated helper that opens once through
	// os.Root, requires a regular file, and bounds the read with io.LimitReader;
	// the base64 default rejects an over-cap payload before decoding it.
	assert.Contains(t, mcpSrc, `func resolveMCPUploadFromRoot(field, root, raw string) (string, func(), error)`)
	assert.Contains(t, mcpSrc, `io.LimitReader(f, mcpMaxUploadBytes+1)`)
	assert.Contains(t, mcpSrc, `base64.StdEncoding.EncodedLen(mcpMaxUploadBytes)`)
	assert.Contains(t, mcpSrc, `raw, ok := v.(string)`)
	assert.Contains(t, mcpSrc, `data, _, err = c.PostMultipartWithParams(ctx, path, params, multipartFields, multipartFileFields)`)

	// An object/array body param binds to its native JSON type even on a
	// multipart endpoint (not WithString). The non-file field then flows
	// through mcpMultipartFieldValue, which JSON-encodes a native composite
	// rather than rendering it with Go's "%v". This locks the multipart path
	// that became live once array/object params stopped binding as WithString —
	// without it, a future refactor of the helper could silently reintroduce a
	// malformed multipart field for composite params.
	assert.Contains(t, mcpSrc, `mcplib.WithObject("metadata"`)
	assert.Contains(t, mcpSrc, `multipartFields[binding.WireName] = mcpMultipartFieldValue(v)`)
	assert.Regexp(t, `(?s)func mcpMultipartFieldValue\(v any\) string \{.*?json\.Marshal\(v\)`, mcpSrc)

	assertMultipartDryRunSkipsFileIO(t, clientSrc)

	runGoCommand(t, outputDir, "mod", "tidy")
	runGoCommand(t, outputDir, "build", "./...")
}

func TestMultipartDryRunDoesNotOpenFileFields(t *testing.T) {
	t.Parallel()

	apiSpec := minimalSpec("multipart-dryrun")
	apiSpec.Resources = map[string]spec.Resource{
		"assets": {
			Description: "Manage assets",
			Endpoints: map[string]spec.Endpoint{
				"upload": {
					Method:             "POST",
					Path:               "/assets",
					Description:        "Upload an asset",
					RequestContentType: "multipart/form-data",
					Body: []spec.Param{
						{Name: "assetData", Type: "string", Format: "binary", Required: true, Description: "Asset file"},
						{Name: "filename", Type: "string", Required: true, Description: "File name"},
					},
				},
			},
		},
	}

	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	require.NoError(t, New(apiSpec, outputDir).Generate())

	clientSrc := readGeneratedFile(t, outputDir, "internal", "client", "client.go")
	assertMultipartDryRunSkipsFileIO(t, clientSrc)

	const runtimeTest = `package client

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multipart-dryrun-pp-cli/internal/config"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe() error = %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = original }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("closing stderr pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading stderr pipe: %v", err)
	}
	return string(out)
}

func TestMultipartDryRunDoesNotOpenFileFields(t *testing.T) {
	c := New(&config.Config{BaseURL: "https://api.example.invalid"}, time.Second, 0)
	c.DryRun = true
	c.NoCache = true

	missing := filepath.Join(t.TempDir(), "does-not-exist.bin")
	stderr := captureStderr(t, func() {
		_, _, err := c.PostMultipartWithParams(context.Background(), "/assets", nil,
			map[string]string{"filename": "clip.wav"},
			map[string]string{"assetData": missing})
		if err != nil {
			t.Fatalf("dry-run opened or failed on missing file: %v", err)
		}
	})
	if !strings.Contains(stderr, "@"+missing) {
		t.Fatalf("dry-run preview did not name the file field; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "assetData") {
		t.Fatalf("dry-run preview omitted the file field name; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "clip.wav") {
		t.Fatalf("dry-run preview did not name the text field; stderr=%s", stderr)
	}
}

func TestMultipartLivePathStillOpensFileFields(t *testing.T) {
	c := New(&config.Config{BaseURL: "https://api.example.invalid"}, time.Second, 0)
	c.NoCache = true

	missing := filepath.Join(t.TempDir(), "does-not-exist.bin")
	_, _, err := c.PostMultipartWithParams(context.Background(), "/assets", nil,
		map[string]string{"filename": "clip.wav"},
		map[string]string{"assetData": missing})
	if err == nil {
		t.Fatal("live multipart path must still open FileFields")
	}
	if !strings.Contains(err.Error(), "opening multipart file field") {
		t.Fatalf("live error = %v, want opening multipart file field", err)
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(outputDir, "internal", "client", "multipart_dryrun_runtime_test.go"), []byte(runtimeTest), 0o600))
	requireGeneratedCompiles(t, outputDir)
	runGoCommand(t, outputDir, "test", "./internal/client", "-run", "^TestMultipart(DryRunDoesNotOpenFileFields|LivePathStillOpensFileFields)$", "-count=1")
}

func assertMultipartDryRunSkipsFileIO(t *testing.T, clientSrc string) {
	t.Helper()

	implStart := strings.Index(clientSrc, "func (c *Client) doInternal(")
	require.NotEqual(t, -1, implStart, "client.go must contain Client.doInternal")
	implBody := clientSrc[implStart:]
	if next := strings.Index(implBody[1:], "\nfunc "); next != -1 {
		implBody = implBody[:next+1]
	}
	dryRunIdx := strings.Index(implBody, "if c.DryRun {")
	encodeIdx := strings.Index(implBody, "b, ct, err := encodeMultipartBody(multipartBody)")
	require.GreaterOrEqual(t, dryRunIdx, 0, "doInternal must short-circuit multipart encoding under DryRun")
	require.GreaterOrEqual(t, encodeIdx, 0, "doInternal must still call encodeMultipartBody on the live path")
	assert.Less(t, dryRunIdx, encodeIdx, "doInternal must skip encodeMultipartBody (and its os.Open) under DryRun")
	assert.Contains(t, implBody, `preview[name] = "@" + filePath`)
	assert.Contains(t, clientSrc, "file, err := os.Open(filePath)")
}

func TestGenerateOpenAPIMultipartRequestBodyUsesMultipartClient(t *testing.T) {
	t.Parallel()

	apiSpec, err := openapi.Parse([]byte(`
openapi: 3.0.3
info:
  title: Upload API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /assets:
    post:
      operationId: uploadAsset
      summary: Upload asset
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required: [assetData, filename]
              properties:
                assetData:
                  type: string
                  format: binary
                  description: Asset file
                filename:
                  type: string
                  description: File name
      responses:
        "201":
          description: created
  /attachments:
    post:
      operationId: uploadAttachments
      summary: Upload attachments
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: array
              items:
                type: object
                properties:
                  name:
                    type: string
      responses:
        "201":
          description: created
  /notes:
    post:
      operationId: createNote
      summary: Create note
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [title]
              properties:
                title:
                  type: string
      responses:
        "201":
          description: created
`))
	require.NoError(t, err)

	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	require.NoError(t, New(apiSpec, outputDir).Generate())

	uploadSrc := readGeneratedFile(t, outputDir, "internal", "cli", "promoted_assets.go")
	assert.Contains(t, uploadSrc, `return fmt.Errorf("required flag \"%s\" not set", "asset-data")`)
	assert.Contains(t, uploadSrc, `return fmt.Errorf("required flag \"%s\" not set", "filename")`)
	assert.Contains(t, uploadSrc, `fileFields["assetData"] = bodyAssetData`)
	assert.Contains(t, uploadSrc, `fields["filename"] = bodyFilename`)
	assert.Contains(t, uploadSrc, `c.PostMultipartWithParams(cmd.Context(), path, params, fields, fileFields)`)
	assert.NotContains(t, uploadSrc, `body["assetData"] = bodyAssetData`)
	assert.NotContains(t, uploadSrc, `body["filename"] = bodyFilename`)

	attachmentsSrc := readGeneratedFile(t, outputDir, "internal", "cli", "promoted_attachments.go")
	assert.Contains(t, attachmentsSrc, `cmd.Flags().StringVar(&bodyFile, "file", "", "Path to the file to upload.")`)
	assert.Contains(t, attachmentsSrc, `return fmt.Errorf("required flag \"%s\" not set", "file")`)
	assert.Contains(t, attachmentsSrc, `fileFields["file"] = bodyFile`)
	assert.Contains(t, attachmentsSrc, `c.PostMultipartWithParams(cmd.Context(), path, params, fields, fileFields)`)
	assert.NotContains(t, attachmentsSrc, `"stdin"`)

	createSrc := readGeneratedFile(t, outputDir, "internal", "cli", "promoted_notes.go")
	assert.Contains(t, createSrc, `bodyMap["title"] = bodyTitle`)
	assert.Contains(t, createSrc, `c.PostWithParams(cmd.Context(), path, params, body)`)
	assert.NotContains(t, createSrc, `c.PostMultipartWithParams`)

	requireGeneratedCompiles(t, outputDir)
}

func TestMultipartFilePartContentTypeFromExtension(t *testing.T) {
	t.Parallel()

	apiSpec := minimalSpec("multipart-part-type")
	apiSpec.Resources = map[string]spec.Resource{
		"assets": {
			Description: "Manage assets",
			Endpoints: map[string]spec.Endpoint{
				"upload": {
					Method:             "POST",
					Path:               "/assets",
					Description:        "Upload an asset",
					RequestContentType: "multipart/form-data",
					Body: []spec.Param{
						{Name: "assetData", Type: "string", Format: "binary", Required: true, Description: "Asset file"},
					},
				},
			},
		},
	}

	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	require.NoError(t, New(apiSpec, outputDir).Generate())

	clientSrc := readGeneratedFile(t, outputDir, "internal", "client", "client.go")
	assert.Contains(t, clientSrc, `mime.TypeByExtension(filepath.Ext(path))`)
	assert.Contains(t, clientSrc, `writer.CreatePart(h)`)
	assert.NotContains(t, clientSrc, `writer.CreateFormFile(`)

	endpointSrc := readGeneratedFile(t, outputDir, "internal", "cli", "promoted_assets.go")
	assert.Contains(t, endpointSrc, `fileFields["assetData"] = bodyAssetData`)
	assert.NotContains(t, endpointSrc, `fields["assetData"]`)

	const runtimeTest = `package client

import (
	"bytes"
	"mime"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeMultipartFilePartContentType(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		ext  string
		want string
	}{
		{name: "pdf", ext: ".pdf", want: "application/pdf"},
		{name: "png", ext: ".png", want: "image/png"},
		{name: "jpeg", ext: ".jpeg", want: "image/jpeg"},
		{name: "unknown", ext: ".nope123", want: "application/octet-stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "sample"+tc.ext)
			if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if got := multipartFileContentType(path); got != tc.want {
				t.Fatalf("multipartFileContentType(%q) = %q, want %q", path, got, tc.want)
			}
			body, contentType, err := encodeMultipartBody(multipartRequestBody{
				FileFields: map[string]string{"assetData": path},
			})
			if err != nil {
				t.Fatalf("encodeMultipartBody() error = %v", err)
			}
			_, params, err := mime.ParseMediaType(contentType)
			if err != nil {
				t.Fatalf("ParseMediaType() error = %v", err)
			}
			part, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).NextPart()
			if err != nil {
				t.Fatalf("NextPart() error = %v", err)
			}
			got := part.Header.Get("Content-Type")
			if got != tc.want {
				t.Fatalf("part Content-Type = %q, want %q", got, tc.want)
			}
			if tc.want != "application/octet-stream" && strings.EqualFold(got, "application/octet-stream") {
				t.Fatalf("known extension %q still encoded as application/octet-stream", tc.ext)
			}
		})
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(outputDir, "internal", "client", "multipart_part_type_runtime_test.go"), []byte(runtimeTest), 0o600))
	requireGeneratedCompiles(t, outputDir)
	runGoCommand(t, outputDir, "test", "./internal/client", "-run", "^TestEncodeMultipartFilePartContentType$", "-count=1")
}

func TestGenerateBinaryResponseWritesRawBytes(t *testing.T) {
	t.Parallel()

	apiSpec := minimalSpec("audioapi")
	apiSpec.Resources = map[string]spec.Resource{
		"audio": {
			Description: "Audio",
			Endpoints: map[string]spec.Endpoint{
				"create": {
					Method:         "POST",
					Path:           "/audio",
					Description:    "Create audio",
					ResponseFormat: spec.ResponseFormatBinary,
					Body: []spec.Param{
						{Name: "text", Type: "string", Required: true, Description: "Text"},
					},
				},
			},
		},
	}

	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	require.NoError(t, New(apiSpec, outputDir).Generate())

	endpointSrc := readGeneratedFile(t, outputDir, "internal", "cli", "promoted_audio.go")
	assert.Contains(t, endpointSrc, `binary response cannot be rendered as structured output`)
	assert.Contains(t, endpointSrc, `cmd.OutOrStdout().Write(data)`)
}

// TestMCPMultipartFileParamConfinement locks the MCP multipart file-read
// hardening end to end: the generated resolveMCPMultipartFile accepts base64
// file content by default (so an MCP caller cannot name an arbitrary local
// path for the server to read), and in the opt-in upload-root mode it confines
// reads to the configured directory, refusing traversal, absolute paths, and
// symlinks (CWE-22/CWE-73).
func TestMCPMultipartFileParamConfinement(t *testing.T) {
	t.Parallel()

	apiSpec := minimalSpec("uploadconfine")
	apiSpec.Resources = map[string]spec.Resource{
		"assets": {
			Description: "Manage assets",
			Endpoints: map[string]spec.Endpoint{
				"upload": {
					Method:             "POST",
					Path:               "/assets",
					Description:        "Upload an asset",
					RequestContentType: "multipart/form-data",
					Body: []spec.Param{
						{Name: "file", Type: "string", Format: "binary", Required: true, Description: "Asset file"},
						{Name: "label", Type: "string", Description: "Label"},
					},
				},
			},
		},
	}

	outputDir := filepath.Join(t.TempDir(), naming.CLI(apiSpec.Name))
	require.NoError(t, New(apiSpec, outputDir).Generate())

	runtimeTest := `package mcp

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveMCPMultipartFile_Base64Default(t *testing.T) {
	path, cleanup, err := resolveMCPMultipartFile("file", "", base64.StdEncoding.EncodeToString([]byte("HELLO")))
	if err != nil {
		t.Fatalf("base64 content rejected: %v", err)
	}
	defer cleanup()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged: %v", err)
	}
	if string(b) != "HELLO" {
		t.Fatalf("staged = %q, want HELLO", b)
	}
	if filepath.Base(path) != "file" {
		t.Fatalf("default filename = %q, want the parameter name \"file\"", filepath.Base(path))
	}
}

func TestResolveMCPMultipartFile_FilenameHint(t *testing.T) {
	// A usable hint becomes the multipart filename so a server can sniff by
	// extension.
	path, cleanup, err := resolveMCPMultipartFile("file", "photo.png", base64.StdEncoding.EncodeToString([]byte("IMG")))
	if err != nil {
		t.Fatalf("hint rejected: %v", err)
	}
	cleanup()
	if filepath.Base(path) != "photo.png" {
		t.Fatalf("filename = %q, want photo.png", filepath.Base(path))
	}

	// Unsafe hints are rejected and fall back to the parameter name.
	for _, bad := range []string{"", ".", "..", "a/b.png", "a\\b.png", "x\x00y", "a:b.png", "\u202eevil.png", strings.Repeat("x", 300) + ".png"} {
		p, c, err := resolveMCPMultipartFile("file", bad, base64.StdEncoding.EncodeToString([]byte("Z")))
		if err != nil {
			t.Fatalf("content with bad hint %q rejected: %v", bad, err)
		}
		if filepath.Base(p) != "file" {
			t.Fatalf("bad hint %q produced filename %q, want fallback \"file\"", bad, filepath.Base(p))
		}
		c()
	}
}

func TestResolveMCPMultipartFile_RejectsRawPathByDefault(t *testing.T) {
	_, _, err := resolveMCPMultipartFile("file", "", "/etc/passwd")
	if err == nil {
		t.Fatal("default mode accepted a raw local path instead of base64 content")
	}
	// The error must name the opt-in env var and the base64 alternative.
	if !strings.Contains(err.Error(), mcpUploadRootEnvVar) {
		t.Fatalf("error %q does not name %s", err, mcpUploadRootEnvVar)
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Fatalf("error %q does not mention base64", err)
	}
}

func TestResolveMCPMultipartFile_SizeCap(t *testing.T) {
	big := make([]byte, mcpMaxUploadBytes+1)
	if _, _, err := resolveMCPMultipartFile("file", "", base64.StdEncoding.EncodeToString(big)); err == nil {
		t.Fatal("default mode accepted a payload over the size cap")
	}
}

func TestResolveMCPMultipartFile_RequiresString(t *testing.T) {
	// A non-string MCP value is rejected rather than coerced via fmt, so a
	// number or object cannot slip into the base64 decoder or the path resolver.
	if _, _, err := resolveMCPMultipartFile("file", "", 123); err == nil {
		t.Fatal("non-string multipart value was accepted")
	}
}

func TestResolveMCPMultipartFile_RejectsOversizeBase64BeforeDecode(t *testing.T) {
	// A base64 payload whose length alone exceeds the cap is rejected before any
	// decode allocation happens.
	huge := strings.Repeat("A", base64.StdEncoding.EncodedLen(mcpMaxUploadBytes)+5000)
	if _, _, err := resolveMCPMultipartFile("file", "", huge); err == nil {
		t.Fatal("oversize base64 payload was accepted")
	}
}

func TestResolveMCPMultipartFile_RootModeConfines(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.bin"), []byte("INSIDE"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(mcpUploadRootEnvVar, root)

	path, cleanup, err := resolveMCPMultipartFile("file", "ignored.txt", "ok.bin")
	if err != nil {
		t.Fatalf("in-root relative path rejected: %v", err)
	}
	b, _ := os.ReadFile(path)
	// Path mode derives the filename from the confined path, ignoring the hint.
	if filepath.Base(path) != "ok.bin" {
		t.Fatalf("path-mode filename = %q, want ok.bin", filepath.Base(path))
	}
	cleanup()
	if string(b) != "INSIDE" {
		t.Fatalf("staged = %q, want INSIDE", b)
	}

	if _, _, err := resolveMCPMultipartFile("file", "", "../escape"); err == nil {
		t.Fatal("root mode accepted a traversal path")
	}
	if _, _, err := resolveMCPMultipartFile("file", "", "/etc/passwd"); err == nil {
		t.Fatal("root mode accepted an absolute path outside the root")
	}

	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, _, err := resolveMCPMultipartFile("file", "", "link"); err == nil {
		t.Fatal("root mode followed a symlink out of the root")
	}

	// A non-regular file inside the root (here a directory) is refused so a read
	// cannot hang on a FIFO/device or pull in a directory.
	if err := os.Mkdir(filepath.Join(root, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveMCPMultipartFile("file", "", "adir"); err == nil {
		t.Fatal("root mode accepted a non-regular file")
	}

	// An absolute path that still lives inside the root is accepted (made
	// root-relative), so operators can pass a fully-qualified in-root path.
	if err := os.WriteFile(filepath.Join(root, "ok2.bin"), []byte("ABS"), 0o600); err != nil {
		t.Fatal(err)
	}
	ap, ac, err := resolveMCPMultipartFile("file", "", filepath.Join(root, "ok2.bin"))
	if err != nil {
		t.Fatalf("absolute in-root path rejected: %v", err)
	}
	if ab, _ := os.ReadFile(ap); string(ab) != "ABS" {
		t.Fatalf("absolute in-root read = %q, want ABS", ab)
	}
	ac()

	// os.Root refuses a symlink whose target is an absolute path even when it
	// resolves inside the root. That is conservative and safe: upload-root mode
	// reads only real files placed directly under the root.
	if err := os.Symlink(filepath.Join(root, "ok.bin"), filepath.Join(root, "inlink")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, _, err := resolveMCPMultipartFile("file", "", "inlink"); err == nil {
		t.Fatal("root mode followed an absolute-target symlink inside the root")
	}
}
`
	require.NoError(t, os.WriteFile(filepath.Join(outputDir, "internal", "mcp", "multipart_confine_runtime_test.go"), []byte(runtimeTest), 0o600))
	runGoCommand(t, outputDir, "mod", "tidy")
	runGoCommandRequired(t, outputDir, "test", "./internal/mcp", "-run", "^TestResolveMCPMultipartFile_", "-count=1")
	requireGeneratedCompiles(t, outputDir)
}
