package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_ValidManifest(t *testing.T) {
	data := []byte(`{
		"schema_version": "1.0",
		"package": {
			"id": "acme/hello",
			"version": "1.0.0",
			"git_sha": "abc123"
		},
		"bundle": {
			"digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"size_bytes": 1024
		},
		"transport": {
			"type": "stdio"
		},
		"entrypoints": [
			{
				"os": "linux",
				"arch": "amd64",
				"command": "./bin/server"
			}
		],
		"permissions_requested": {},
		"limits_recommended": {}
	}`)

	m, err := Parse(data)
	require.NoError(t, err)
	assert.Equal(t, "acme/hello", m.Package.ID)
	assert.Equal(t, "1.0.0", m.Package.Version)
	assert.Equal(t, "stdio", m.Transport.Type)
	assert.Len(t, m.Entrypoints, 1)
}

func TestParse_EmptyData(t *testing.T) {
	_, err := Parse([]byte{})
	assert.Error(t, err)
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := Parse([]byte(`{invalid json}`))
	assert.Error(t, err)
}

func TestValidate_ValidManifest(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
			GitSHA:  "abc123",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./bin/server",
			},
		},
	}

	err := Validate(m)
	assert.NoError(t, err)
}

func TestValidate_NilManifest(t *testing.T) {
	err := Validate(nil)
	assert.Error(t, err)
}

func TestValidate_MissingSchemaVersion(t *testing.T) {
	m := &Manifest{
		Package: PackageInfo{ID: "acme/hello", Version: "1.0.0"},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "schema_version")
}

func TestValidate_InvalidPackageID(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "invalid",
			Version: "1.0.0",
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "org/name")
}

func TestValidate_InvalidDigest(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "invalid",
			SizeBytes: 1024,
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "digest")
}

func TestValidate_InvalidTransportType(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "invalid",
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport")
}

func TestValidate_HTTPTransportWithoutPort(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "http",
			Port: 0,
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

func TestValidate_NoEntrypoints(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entrypoint")
}

func TestValidate_InvalidEntrypointOS(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "invalid",
				Arch:    "amd64",
				Command: "./bin/server",
			},
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "os")
}

func TestValidate_InvalidEntrypointArch(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "invalid",
				Command: "./bin/server",
			},
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "arch")
}

func TestSelectEntrypoint_FoundForCurrentOS(t *testing.T) {
	m := &Manifest{
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./bin/linux",
			},
			{
				OS:      "linux",
				Arch:    "arm64",
				Command: "./bin/linux-arm",
			},
			{
				OS:      "darwin",
				Arch:    "amd64",
				Command: "./bin/darwin",
			},
			{
				OS:      "darwin",
				Arch:    "arm64",
				Command: "./bin/darwin-arm",
			},
			{
				OS:      "windows",
				Arch:    "amd64",
				Command: "./bin/windows.exe",
			},
		},
	}

	ep, err := SelectEntrypoint(m)
	require.NoError(t, err)
	assert.NotNil(t, ep)
	// The result depends on runtime environment, so just check it's one of them
	assert.Contains(t, []string{"linux", "darwin", "windows"}, ep.OS)
	assert.Contains(t, []string{"amd64", "arm64"}, ep.Arch)
}

func TestSelectEntrypoint_NotFound(t *testing.T) {
	m := &Manifest{
		Entrypoints: []Entrypoint{
			{
				OS:      "freebsd",
				Arch:    "amd64",
				Command: "./bin/freebsd",
			},
		},
	}

	_, err := SelectEntrypoint(m)
	assert.Error(t, err)
}

func TestSelectEntrypoint_NilManifest(t *testing.T) {
	_, err := SelectEntrypoint(nil)
	assert.Error(t, err)
}

func TestIsValidPackageID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"acme/hello", true},
		{"org-123/pkg_name", true},
		{"org/pkg", true},
		{"org", false},
		{"org/", false},
		{"/name", false},
		{"org/name/extra", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := isValidPackageID(tt.id)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		digest string
		valid  bool
	}{
		{"sha256:0000000000000000000000000000000000000000000000000000000000000000", true},
		{"sha256:abc123def456", false},
		{"sha1:abc123", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			result := isValidDigest(tt.digest)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestIsValidOS(t *testing.T) {
	tests := []struct {
		os    string
		valid bool
	}{
		{"linux", true},
		{"darwin", true},
		{"windows", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.os, func(t *testing.T) {
			result := isValidOS(tt.os)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestIsValidArch(t *testing.T) {
	tests := []struct {
		arch  string
		valid bool
	}{
		{"amd64", true},
		{"arm64", true},
		{"386", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			result := isValidArch(tt.arch)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestParse_HubManifestWithSecurityMetadata(t *testing.T) {
	data := []byte(`{
		"schema_version": "1",
		"package": {
			"id": "acme/hello",
			"version": "1.0.0",
			"git_sha": "abc123"
		},
		"runtime": {
			"type": "node",
			"version": "20"
		},
		"entrypoint": {
			"command": ["node", "dist/index.js"]
		},
		"certification": {
			"level": 2,
			"score": 85,
			"security_score": 90,
			"supply_chain_score": 80,
			"maturity_score": 75,
			"findings": {
				"total": 5,
				"critical": 1,
				"high": 2,
				"medium": 1,
				"low": 1
			},
			"capabilities": {
				"tools": [
					{"name": "exec_command", "description": "Execute shell commands", "risk_level": "critical"},
					{"name": "read_file", "description": "Read files", "risk_level": "medium"}
				],
				"resources": [
					{"uri": "file:///data", "name": "data"}
				],
				"transport": "stdio",
				"auth_signals": ["api_key"]
			},
			"compliance": {
				"total_controls": 10,
				"passed_controls": 8,
				"failed_controls": 2,
				"failed_items": [
					{"control_id": "A1", "severity": "high", "message": "Command injection detected"},
					{"control_id": "B2", "severity": "medium", "message": "Missing input validation"}
				]
			}
		}
	}`)

	m, err := Parse(data)
	require.NoError(t, err)
	assert.True(t, m.HubFormat)
	assert.Equal(t, "acme/hello", m.Package.ID)

	// Verify SecurityMeta is populated
	require.NotNil(t, m.SecurityMeta)
	assert.Equal(t, 85, m.SecurityMeta.Score)
	assert.Equal(t, 90, m.SecurityMeta.SecurityScore)
	assert.Equal(t, 80, m.SecurityMeta.SupplyChainScore)
	assert.Equal(t, 75, m.SecurityMeta.MaturityScore)
	assert.Equal(t, 2, m.SecurityMeta.CertLevel)

	// Verify findings
	require.NotNil(t, m.SecurityMeta.Findings)
	assert.Equal(t, 5, m.SecurityMeta.Findings.Total)
	assert.Equal(t, 1, m.SecurityMeta.Findings.Critical)
	assert.Equal(t, 2, m.SecurityMeta.Findings.High)
	assert.Equal(t, 1, m.SecurityMeta.Findings.Medium)
	assert.Equal(t, 1, m.SecurityMeta.Findings.Low)

	// Verify capabilities
	require.NotNil(t, m.SecurityMeta.Capabilities)
	assert.Len(t, m.SecurityMeta.Capabilities.Tools, 2)
	assert.Equal(t, "exec_command", m.SecurityMeta.Capabilities.Tools[0].Name)
	assert.Equal(t, "critical", m.SecurityMeta.Capabilities.Tools[0].RiskLevel)
	assert.Len(t, m.SecurityMeta.Capabilities.Resources, 1)
	assert.Equal(t, "stdio", m.SecurityMeta.Capabilities.Transport)
	assert.Equal(t, []string{"api_key"}, m.SecurityMeta.Capabilities.AuthSignals)

	// Verify compliance
	require.NotNil(t, m.SecurityMeta.Compliance)
	assert.Equal(t, 10, m.SecurityMeta.Compliance.TotalControls)
	assert.Equal(t, 8, m.SecurityMeta.Compliance.PassedControls)
	assert.Equal(t, 2, m.SecurityMeta.Compliance.FailedControls)
	assert.Len(t, m.SecurityMeta.Compliance.FailedItems, 2)
	assert.Equal(t, "A1", m.SecurityMeta.Compliance.FailedItems[0].ControlID)
}

func TestParse_HubManifestBackwardsCompat(t *testing.T) {
	// Old hub manifest without new security fields should parse cleanly
	data := []byte(`{
		"schema_version": "1",
		"package": {
			"id": "acme/legacy",
			"version": "0.5.0"
		},
		"runtime": {
			"type": "python",
			"version": "3.12"
		},
		"entrypoint": {
			"command": ["python", "-m", "server"]
		},
		"certification": {
			"level": 1,
			"score": 65
		}
	}`)

	m, err := Parse(data)
	require.NoError(t, err)
	assert.True(t, m.HubFormat)
	assert.Equal(t, "acme/legacy", m.Package.ID)

	// SecurityMeta should be populated with basic fields
	require.NotNil(t, m.SecurityMeta)
	assert.Equal(t, 65, m.SecurityMeta.Score)
	assert.Equal(t, 1, m.SecurityMeta.CertLevel)
	assert.Equal(t, 0, m.SecurityMeta.SecurityScore)
	assert.Equal(t, 0, m.SecurityMeta.SupplyChainScore)
	assert.Equal(t, 0, m.SecurityMeta.MaturityScore)

	// Optional sub-fields should be nil
	assert.Nil(t, m.SecurityMeta.Findings)
	assert.Nil(t, m.SecurityMeta.Capabilities)
	assert.Nil(t, m.SecurityMeta.Compliance)
}

func TestParse_HubManifestNoCertification(t *testing.T) {
	// Hub manifest without certification section at all
	data := []byte(`{
		"schema_version": "1",
		"package": {
			"id": "acme/nocert",
			"version": "0.1.0"
		},
		"runtime": {
			"type": "node",
			"version": "20"
		},
		"entrypoint": {
			"command": ["node", "index.js"]
		}
	}`)

	m, err := Parse(data)
	require.NoError(t, err)
	assert.True(t, m.HubFormat)
	assert.Nil(t, m.SecurityMeta)
}

func TestParseHubManifest_RuntimeCommandMismatch(t *testing.T) {
	// Test that a runtime/command mismatch doesn't cause an error (just a warning)
	manifest := `{
		"schema_version": 1,
		"package": {"id": "acme/test", "version": "1.0.0"},
		"runtime": {"type": "python", "version": ">=3.10"},
		"entrypoint": {"command": ["node", "dist/index.js"]},
		"certification": {"level": 1, "score": 65}
	}`

	m, err := Parse([]byte(manifest))
	require.NoError(t, err)
	assert.Equal(t, "node", m.Entrypoints[0].Command)
	assert.Equal(t, []string{"dist/index.js"}, m.Entrypoints[0].Args)
}

func TestParseHubManifest_RuntimeCommandConsistent(t *testing.T) {
	// Test that consistent runtime/command works fine
	manifest := `{
		"schema_version": 1,
		"package": {"id": "acme/test", "version": "1.0.0"},
		"runtime": {"type": "python", "version": ">=3.10"},
		"entrypoint": {"command": ["uv", "run", "my-tool"]},
		"certification": {"level": 1, "score": 65}
	}`

	m, err := Parse([]byte(manifest))
	require.NoError(t, err)
	assert.Equal(t, "uv", m.Entrypoints[0].Command)
	assert.Equal(t, []string{"run", "my-tool"}, m.Entrypoints[0].Args)
}

func TestParse_ClientManifestNoSecurityMeta(t *testing.T) {
	// Client-format manifests should never have SecurityMeta
	data := []byte(`{
		"schema_version": "1.0",
		"package": {
			"id": "acme/hello",
			"version": "1.0.0",
			"git_sha": "abc123"
		},
		"bundle": {
			"digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"size_bytes": 1024
		},
		"transport": {
			"type": "stdio"
		},
		"entrypoints": [
			{
				"os": "linux",
				"arch": "amd64",
				"command": "./bin/server"
			}
		],
		"permissions_requested": {},
		"limits_recommended": {}
	}`)

	m, err := Parse(data)
	require.NoError(t, err)
	assert.False(t, m.HubFormat)
	assert.Nil(t, m.SecurityMeta)
}
