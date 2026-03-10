# Semantic Versioning and Version Handling in Go

## Overview

This skill covers semantic versioning (semver) in Go, with focus on the mcp-cage project. Version handling is critical for package management (resolving `org/name@version` references), compatibility (MAJOR.MINOR.PATCH), and release workflows.

**mcp-cage context:** Package references use semver: `org/name@1.2.3`, `org/name@1.0.0-alpha`, `org/name@latest`. Version resolution, comparison, and range matching are core operations.

---

## Core Principles

1. **Semver Format:** MAJOR.MINOR.PATCH with optional pre-release and build metadata
2. **Immutable Versions:** Once published, version cannot change
3. **Breaking Changes:** MAJOR bump = breaking API changes
4. **Backward Compatibility:** MINOR.PATCH never break existing code
5. **Pre-release Precedence:** 1.0.0-alpha < 1.0.0-beta < 1.0.0
6. **Build Metadata:** +buildN is for informational only, not versioning
7. **Version Comparison:** Robust comparison handling pre-release logic
8. **Range Matching:** Support ^1.0.0 (compatible), ~1.2.3 (patch), >=1.0.0 <2.0.0
9. **Latest Resolution:** Find latest stable version, or latest including pre-release
10. **Testing:** Parsing, comparison, ranges, edge cases

---

## Semantic Versioning Format

### Standard Semver Pattern

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]

Examples:
1.2.3                  # Release: major=1, minor=2, patch=3
1.0.0-alpha            # Pre-release (alpha)
2.1.0-beta.1           # Pre-release with number
1.5.0-rc.1             # Release candidate
1.0.0+20130313144700   # Build metadata only
1.0.0-beta+exp.sha.5114f85  # Pre-release + build metadata
0.1.0                  # Valid pre-1.0 release
```

### Regex Pattern for Validation

```go
package version

import "regexp"

// Semver regex following https://semver.org
var semverPattern = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)` +
	`(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`,
)

func IsValidSemver(v string) bool {
	return semverPattern.MatchString(v)
}

// Test cases
func ExampleIsValidSemver() {
	println(IsValidSemver("1.2.3"))                  // true
	println(IsValidSemver("1.0.0-alpha"))            // true
	println(IsValidSemver("2.1.0-beta.1"))           // true
	println(IsValidSemver("1.2.3.4"))                // false (4 components)
	println(IsValidSemver("1.2"))                    // false (missing patch)
	println(IsValidSemver("v1.2.3"))                 // false (has 'v' prefix)
	println(IsValidSemver("1.2.3-"))                 // false (empty pre-release)
}
```

---

## Parsing Semantic Versions

### Custom Version Struct

```go
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed semantic version
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string // empty for stable releases
	Build      string // empty if not specified
}

// Parse parses a semantic version string
func Parse(v string) (*Version, error) {
	if v == "" {
		return nil, fmt.Errorf("version string cannot be empty")
	}

	// Remove 'v' prefix if present (common but not standard)
	if v[0] == 'v' || v[0] == 'V' {
		v = v[1:]
	}

	// Split by + to separate build metadata
	var build string
	if plusIdx := strings.Index(v, "+"); plusIdx >= 0 {
		build = v[plusIdx+1:]
		v = v[:plusIdx]
	}

	// Split by - to separate pre-release
	var prerelease string
	if dashIdx := strings.Index(v, "-"); dashIdx >= 0 {
		prerelease = v[dashIdx+1:]
		v = v[:dashIdx]
	}

	// Parse major.minor.patch
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("version must have 3 parts (major.minor.patch), got: %s", v)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	patch, err := strconv.Atoi(parts[2])
	if err != nil || patch < 0 {
		return nil, fmt.Errorf("invalid patch version: %s", parts[2])
	}

	return &Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Build:      build,
	}, nil
}

// String returns the string representation
func (v *Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)

	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}

	if v.Build != "" {
		s += "+" + v.Build
	}

	return s
}

// Examples
func ExampleParse() {
	v, _ := Parse("1.2.3")
	fmt.Println(v)  // 1.2.3
	fmt.Println(v.Major)  // 1

	v, _ = Parse("2.1.0-alpha.1")
	fmt.Println(v)  // 2.1.0-alpha.1
	fmt.Println(v.Prerelease)  // alpha.1

	v, _ = Parse("v1.0.0")  // Strips 'v' prefix
	fmt.Println(v)  // 1.0.0
}
```

### Using golang.org/x/mod/semver

Go's standard library has semver support:

```go
import "golang.org/x/mod/semver"

// Parse and validate
v := "1.2.3"
if !semver.IsValid(v) {
	return fmt.Errorf("not a valid semver: %s", v)
}

// Compare versions
if semver.Compare(v1, v2) < 0 {
	fmt.Println(v1, "is older than", v2)
}

// Find latest
versions := []string{"1.0.0", "1.1.0", "1.0.5", "2.0.0"}
latest := semver.Max(versions...)
fmt.Println(latest) // "2.0.0"
```

### Using github.com/Masterminds/semver

Third-party library with richer API:

```go
import "github.com/Masterminds/semver/v3"

v, err := semver.NewVersion("1.2.3")
if err != nil {
	return fmt.Errorf("invalid version: %w", err)
}

fmt.Println(v.Major())  // 1
fmt.Println(v.Minor())  // 2
fmt.Println(v.Patch())  // 3

// Pre-release info
v2, _ := semver.NewVersion("1.0.0-alpha.1")
fmt.Println(v2.Prerelease())  // "alpha.1"

// Comparison
if v.LessThan(v2) {
	fmt.Println("v is older")
}
```

---

## Comparison: <, >, =, <=, >=

### Comparison Logic with Pre-release Handling

Key rule: **Pre-release versions have lower precedence than the normal version.**

- `1.0.0-alpha < 1.0.0`
- `1.0.0-alpha < 1.0.0-beta`
- `1.0.0-beta < 1.0.0-rc < 1.0.0`

```go
// Compare returns:
// -1 if v < other
//  0 if v == other
//  1 if v > other
func (v *Version) Compare(other *Version) int {
	// Compare major.minor.patch
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}

	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}

	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}

	// Both have same major.minor.patch
	// Pre-release versions have lower precedence than release

	bothRelease := v.Prerelease == "" && other.Prerelease == ""
	if bothRelease {
		return 0 // Both are releases with same version
	}

	// v is release, other is pre-release: v > other
	if v.Prerelease == "" && other.Prerelease != "" {
		return 1
	}

	// v is pre-release, other is release: v < other
	if v.Prerelease != "" && other.Prerelease == "" {
		return -1
	}

	// Both are pre-releases: compare pre-release versions
	return comparePrerelease(v.Prerelease, other.Prerelease)
}

// Compare pre-release strings: "alpha" < "beta" < "rc"
func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}

	// Pre-release versions are compared by identifier
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aID := aParts[i]
		bID := bParts[i]

		// Numeric identifiers: 1 < 2 < 10
		if isNumeric(aID) && isNumeric(bID) {
			aNum, _ := strconv.Atoi(aID)
			bNum, _ := strconv.Atoi(bID)
			if aNum != bNum {
				if aNum < bNum {
					return -1
				}
				return 1
			}
		} else {
			// Alphanumeric: lexical order
			if aID != bID {
				if aID < bID {
					return -1
				}
				return 1
			}
		}
	}

	// Shorter pre-release has lower precedence: 1.0.0-alpha < 1.0.0-alpha.1
	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}

	return 0
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Helper methods
func (v *Version) Equal(other *Version) bool {
	return v.Compare(other) == 0
}

func (v *Version) LessThan(other *Version) bool {
	return v.Compare(other) < 0
}

func (v *Version) LessThanOrEqual(other *Version) bool {
	return v.Compare(other) <= 0
}

func (v *Version) GreaterThan(other *Version) bool {
	return v.Compare(other) > 0
}

func (v *Version) GreaterThanOrEqual(other *Version) bool {
	return v.Compare(other) >= 0
}

// Examples
func ExampleCompare() {
	v1, _ := Parse("1.0.0")
	v2, _ := Parse("1.0.0-alpha")
	v3, _ := Parse("1.0.0-alpha.1")
	v4, _ := Parse("1.0.0-beta")
	v5, _ := Parse("2.0.0")

	println(v1.GreaterThan(v2))     // true: 1.0.0 > 1.0.0-alpha
	println(v2.LessThan(v3))        // true: alpha < alpha.1
	println(v3.LessThan(v4))        // true: alpha.1 < beta
	println(v4.LessThan(v1))        // true: beta < release
	println(v1.LessThan(v5))        // true: 1.0.0 < 2.0.0
}
```

### Sorting Versions

```go
// Sort versions in ascending order
type Versions []*Version

func (vs Versions) Len() int {
	return len(vs)
}

func (vs Versions) Less(i, j int) bool {
	return vs[i].LessThan(vs[j])
}

func (vs Versions) Swap(i, j int) {
	vs[i], vs[j] = vs[j], vs[i]
}

// Usage
import "sort"

versions := []*Version{
	Parse("1.0.0"),
	Parse("1.0.0-alpha"),
	Parse("2.0.0"),
	Parse("1.1.0"),
}

sort.Sort(Versions(versions))
// Result: [1.0.0-alpha, 1.0.0, 1.1.0, 2.0.0]
```

---

## Version Ranges: ^, ~, >=, <=, etc.

### Caret Ranges: ^1.2.0 (Compatible)

**^1.2.3** = >=1.2.3, <2.0.0

Allows changes that do not modify the left-most non-zero element.

```go
// IsCompatibleWith checks if v is compatible with constraint (^)
// ^1.2.3 matches >=1.2.3, <2.0.0
func (v *Version) IsCompatibleWith(constraint *Version) bool {
	// Major must match (for non-zero major)
	if constraint.Major > 0 {
		return v.Major == constraint.Major &&
			(v.Minor > constraint.Minor ||
				(v.Minor == constraint.Minor && v.Patch >= constraint.Patch))
	}

	// If major is 0, minor must match
	if constraint.Minor > 0 {
		return v.Major == constraint.Major &&
			v.Minor == constraint.Minor &&
			v.Patch >= constraint.Patch
	}

	// If both major and minor are 0, must match exactly
	return v.Major == constraint.Major &&
		v.Minor == constraint.Minor &&
		v.Patch == constraint.Patch
}

// Examples
func ExampleCompatible() {
	base, _ := Parse("1.2.3")
	tests := []struct {
		version   string
		compatible bool
	}{
		{"1.2.3", true},   // Exact match
		{"1.2.4", true},   // Patch bump
		{"1.3.0", true},   // Minor bump
		{"2.0.0", false},  // Major bump (incompatible)
		{"1.2.2", false},  // Lower version
	}

	for _, tt := range tests {
		v, _ := Parse(tt.version)
		if v.IsCompatibleWith(base) != tt.compatible {
			fmt.Printf("%s compatible with %s: expected %v\n", v, base, tt.compatible)
		}
	}
}
```

### Tilde Ranges: ~1.2.3 (Patch-safe)

**~1.2.3** = >=1.2.3, <1.3.0

Allows only patch-level changes.

```go
// IsPatchCompatibleWith checks if v matches ~constraint
// ~1.2.3 matches >=1.2.3, <1.3.0
func (v *Version) IsPatchCompatibleWith(constraint *Version) bool {
	return v.Major == constraint.Major &&
		v.Minor == constraint.Minor &&
		v.Patch >= constraint.Patch
}

// Examples
func ExamplePatchCompatible() {
	base, _ := Parse("1.2.3")

	matches := []string{"1.2.3", "1.2.4", "1.2.100"}
	notMatches := []string{"1.1.9", "1.3.0", "2.0.0"}

	for _, v := range matches {
		parsed, _ := Parse(v)
		if !parsed.IsPatchCompatibleWith(base) {
			fmt.Printf("%s should match ~%s\n", v, base)
		}
	}

	for _, v := range notMatches {
		parsed, _ := Parse(v)
		if parsed.IsPatchCompatibleWith(base) {
			fmt.Printf("%s should not match ~%s\n", v, base)
		}
	}
}
```

### Range Expressions: >=, <=, <, >, ==

```go
type VersionRange struct {
	Operator string // ">=", "<=", ">", "<", "==", "!="
	Version  *Version
}

func (vr *VersionRange) Matches(v *Version) bool {
	switch vr.Operator {
	case ">=":
		return v.GreaterThanOrEqual(vr.Version)
	case "<=":
		return v.LessThanOrEqual(vr.Version)
	case ">":
		return v.GreaterThan(vr.Version)
	case "<":
		return v.LessThan(vr.Version)
	case "==":
		return v.Equal(vr.Version)
	case "!=":
		return !v.Equal(vr.Version)
	default:
		return false
	}
}

// Complex range: >=1.0.0 <2.0.0
func (v *Version) InRange(min, max *Version) bool {
	return v.GreaterThanOrEqual(min) && v.LessThan(max)
}

// Examples
func ExampleRanges() {
	v, _ := Parse("1.5.0")
	minV, _ := Parse("1.0.0")
	maxV, _ := Parse("2.0.0")

	println(v.InRange(minV, maxV)) // true: 1.5.0 in [1.0.0, 2.0.0)
}
```

### Parsing Range Expressions

```go
// Parse range like ">=1.0.0" or "^1.2.3" or "~1.2.3"
func ParseRange(expr string) (*VersionRange, error) {
	expr = strings.TrimSpace(expr)

	// Caret: ^1.2.3
	if strings.HasPrefix(expr, "^") {
		v, err := Parse(expr[1:])
		if err != nil {
			return nil, fmt.Errorf("invalid caret range: %w", err)
		}
		return &VersionRange{Operator: "^", Version: v}, nil
	}

	// Tilde: ~1.2.3
	if strings.HasPrefix(expr, "~") {
		v, err := Parse(expr[1:])
		if err != nil {
			return nil, fmt.Errorf("invalid tilde range: %w", err)
		}
		return &VersionRange{Operator: "~", Version: v}, nil
	}

	// Comparison operators: >=, <=, !=, ==, >, <
	for _, op := range []string{">=", "<=", "!=", "==", ">", "<"} {
		if strings.HasPrefix(expr, op) {
			v, err := Parse(expr[len(op):])
			if err != nil {
				return nil, fmt.Errorf("invalid range: %w", err)
			}
			return &VersionRange{Operator: op, Version: v}, nil
		}
	}

	// No operator: exact match
	v, err := Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}
	return &VersionRange{Operator: "==", Version: v}, nil
}

// Match version against range
func (vr *VersionRange) Matches(v *Version) bool {
	switch vr.Operator {
	case "^":
		return v.IsCompatibleWith(vr.Version)
	case "~":
		return v.IsPatchCompatibleWith(vr.Version)
	default:
		// Use standard comparison
		switch vr.Operator {
		case ">=":
			return v.GreaterThanOrEqual(vr.Version)
		case "<=":
			return v.LessThanOrEqual(vr.Version)
		case ">":
			return v.GreaterThan(vr.Version)
		case "<":
			return v.LessThan(vr.Version)
		case "==":
			return v.Equal(vr.Version)
		case "!=":
			return !v.Equal(vr.Version)
		}
	}
	return false
}
```

---

## Latest Resolution: Stable vs Pre-release

### Finding Latest Version

```go
// FindLatest returns the latest stable version
func FindLatest(versions []string) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions provided")
	}

	var parsed []*Version
	for _, v := range versions {
		p, err := Parse(v)
		if err != nil {
			return "", fmt.Errorf("invalid version %q: %w", v, err)
		}
		parsed = append(parsed, p)
	}

	// Sort descending
	sort.Sort(sort.Reverse(Versions(parsed)))

	// Return first stable version (no pre-release)
	for _, v := range parsed {
		if v.Prerelease == "" {
			return v.String(), nil
		}
	}

	// No stable version, return latest even if pre-release
	return parsed[0].String(), nil
}

// FindLatestIncludingPrerelease returns latest version (including pre-release)
func FindLatestIncludingPrerelease(versions []string) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions provided")
	}

	var parsed []*Version
	for _, v := range versions {
		p, err := Parse(v)
		if err != nil {
			return "", fmt.Errorf("invalid version %q: %w", v, err)
		}
		parsed = append(parsed, p)
	}

	sort.Sort(sort.Reverse(Versions(parsed)))
	return parsed[0].String(), nil
}

// Examples
func ExampleFindLatest() {
	versions := []string{"1.0.0", "1.1.0", "2.0.0-alpha", "1.1.1", "0.9.0"}

	stable, _ := FindLatest(versions)
	fmt.Println(stable) // "1.1.1" (latest stable)

	latest, _ := FindLatestIncludingPrerelease(versions)
	fmt.Println(latest) // "2.0.0-alpha" (latest including pre-release)
}
```

### Finding Latest in Range

```go
// FindLatestInRange returns the latest version matching the range
func FindLatestInRange(versions []string, rangeExpr string) (string, error) {
	rangeObj, err := ParseRange(rangeExpr)
	if err != nil {
		return "", fmt.Errorf("invalid range: %w", err)
	}

	var matching []*Version
	for _, v := range versions {
		p, err := Parse(v)
		if err != nil {
			continue
		}

		if rangeObj.Matches(p) {
			matching = append(matching, p)
		}
	}

	if len(matching) == 0 {
		return "", fmt.Errorf("no versions match range %q", rangeExpr)
	}

	sort.Sort(sort.Reverse(Versions(matching)))
	return matching[0].String(), nil
}

// Examples
func ExampleFindLatestInRange() {
	versions := []string{"1.0.0", "1.2.0", "1.5.0", "2.0.0", "2.1.0"}

	latest, _ := FindLatestInRange(versions, "^1.0.0")
	fmt.Println(latest) // "1.5.0" (latest in [1.0.0, 2.0.0))

	latest, _ = FindLatestInRange(versions, ">=1.2.0 <2.0.0")
	fmt.Println(latest) // "1.5.0"
}
```

---

## Breaking Changes: MAJOR Bump

Semantic versioning communicates breaking changes through major version bumps:

- **MAJOR**: Breaking changes to the API (incompatible)
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Detecting Breaking Changes

```go
// HasBreakingChange returns true if upgrading from old to new is breaking
func HasBreakingChange(oldVersion, newVersion string) bool {
	old, err := Parse(oldVersion)
	if err != nil {
		return false // Assume not breaking if parsing fails
	}

	new, err := Parse(newVersion)
	if err != nil {
		return false
	}

	// Major version bump = breaking change
	return new.Major != old.Major
}

// Examples
func ExampleBreakingChange() {
	println(HasBreakingChange("1.0.0", "2.0.0")) // true
	println(HasBreakingChange("1.0.0", "1.1.0")) // false
	println(HasBreakingChange("1.0.0", "1.0.1")) // false
	println(HasBreakingChange("1.5.0", "1.5.1")) // false
}
```

### Version Compatibility Check

```go
// CanUpgrade checks if upgrading from `from` to `to` is safe
func CanUpgrade(from, to, constraint string) (bool, error) {
	// constraint: how strict can we be? (^, ~, exact)

	fromV, err := Parse(from)
	if err != nil {
		return false, err
	}

	toV, err := Parse(to)
	if err != nil {
		return false, err
	}

	switch constraint {
	case "^": // Compatible: allow MINOR and PATCH bumps
		return toV.IsCompatibleWith(fromV), nil
	case "~": // Patch-safe: allow only PATCH bumps
		return toV.IsPatchCompatibleWith(fromV), nil
	case "exact": // Exact: no changes allowed
		return toV.Equal(fromV), nil
	default:
		return false, fmt.Errorf("unknown constraint: %s", constraint)
	}
}
```

---

## Testing: Parsing, Comparison, Ranges, Edge Cases

```go
// From internal/version/version_test.go

func TestParse_ValidVersions(t *testing.T) {
	tests := []struct {
		input string
		want  *Version
	}{
		{
			input: "1.2.3",
			want: &Version{Major: 1, Minor: 2, Patch: 3},
		},
		{
			input: "0.0.1",
			want: &Version{Major: 0, Minor: 0, Patch: 1},
		},
		{
			input: "1.0.0-alpha",
			want: &Version{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"},
		},
		{
			input: "2.1.0-beta.1",
			want: &Version{Major: 2, Minor: 1, Patch: 0, Prerelease: "beta.1"},
		},
		{
			input: "1.0.0+20130313",
			want: &Version{Major: 1, Minor: 0, Patch: 0, Build: "20130313"},
		},
		{
			input: "v1.2.3",  // With v prefix
			want: &Version{Major: 1, Minor: 2, Patch: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tt.input, err)
			}

			if !versionsEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParse_InvalidVersions(t *testing.T) {
	tests := []string{
		"",           // Empty
		"1.2",        // Missing patch
		"1.2.3.4",    // Too many components
		"1.2.a",      // Non-numeric patch
		"1.2.3-",     // Empty pre-release
		"1.2.3+",     // Empty build
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_, err := Parse(tt)
			if err == nil {
				t.Errorf("Parse(%q) should have failed", tt)
			}
		})
	}
}

func TestCompare_PrereleasePrecedence(t *testing.T) {
	tests := []struct {
		a, b string
		want int // -1 if a < b, 0 if a == b, 1 if a > b
	}{
		{"1.0.0-alpha", "1.0.0", -1},      // Pre-release < release
		{"1.0.0-alpha", "1.0.0-beta", -1}, // alpha < beta (lexical)
		{"1.0.0-1", "1.0.0-2", -1},        // 1 < 2 (numeric)
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1}, // alpha.1 < alpha.2
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},   // Shorter < longer
		{"1.0.0", "1.0.0", 0},             // Equal
		{"1.0.0", "1.0.0-alpha", 1},       // Release > pre-release
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s vs %s", tt.a, tt.b), func(t *testing.T) {
			aV, _ := Parse(tt.a)
			bV, _ := Parse(tt.b)

			got := aV.Compare(bV)
			if got != tt.want {
				t.Errorf("Compare(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsCompatibleWith(t *testing.T) {
	base, _ := Parse("1.2.3")

	tests := []struct {
		version string
		want    bool
	}{
		{"1.2.3", true},   // Exact
		{"1.2.4", true},   // Patch bump
		{"1.3.0", true},   // Minor bump
		{"2.0.0", false},  // Major bump
		{"1.2.2", false},  // Downgrade
		{"1.0.0", false},  // Downgrade
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v, _ := Parse(tt.version)
			got := v.IsCompatibleWith(base)
			if got != tt.want {
				t.Errorf("IsCompatibleWith(%s with ^%s) = %v, want %v",
					tt.version, base, got, tt.want)
			}
		})
	}
}

func TestFindLatest(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "2.0.0-alpha", "1.1.1", "0.9.0"}

	latest, err := FindLatest(versions)
	if err != nil {
		t.Fatalf("FindLatest failed: %v", err)
	}

	if latest != "1.1.1" {
		t.Errorf("FindLatest = %s, want 1.1.1", latest)
	}
}

func TestFindLatestIncludingPrerelease(t *testing.T) {
	versions := []string{"1.0.0", "2.0.0-alpha", "1.1.0"}

	latest, err := FindLatestIncludingPrerelease(versions)
	if err != nil {
		t.Fatalf("FindLatestIncludingPrerelease failed: %v", err)
	}

	if latest != "2.0.0-alpha" {
		t.Errorf("FindLatestIncludingPrerelease = %s, want 2.0.0-alpha", latest)
	}
}

func TestSorting(t *testing.T) {
	versions := []string{"1.0.0", "1.0.0-alpha", "2.0.0", "1.1.0", "0.9.0"}

	var parsed Versions
	for _, v := range versions {
		p, _ := Parse(v)
		parsed = append(parsed, p)
	}

	sort.Sort(parsed)

	expected := []string{"0.9.0", "1.0.0-alpha", "1.0.0", "1.1.0", "2.0.0"}
	for i, v := range parsed {
		if v.String() != expected[i] {
			t.Errorf("sorted[%d] = %s, want %s", i, v, expected[i])
		}
	}
}

func versionsEqual(a, b *Version) bool {
	return a.Major == b.Major &&
		a.Minor == b.Minor &&
		a.Patch == b.Patch &&
		a.Prerelease == b.Prerelease &&
		a.Build == b.Build
}
```

---

## Real Code Examples: mcp-cage Package References

### Parsing Package References

From `/internal/cli/pull.go`:

```go
// Package reference format: org/name@version
// Examples: acme/hello-world@1.2.3, org/tool@latest, pkg/name@sha:abc123

func parsePackageRef(ref string) (org, name, version string, err error) {
	// Split by @ to separate name and version
	parts := strings.Split(ref, "@")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("expected format org/name@version")
	}

	orgName := parts[0]
	version = parts[1]

	// Split org/name
	orgNameParts := strings.Split(orgName, "/")
	if len(orgNameParts) != 2 {
		return "", "", "", fmt.Errorf("expected format org/name@version")
	}

	org = orgNameParts[0]
	name = orgNameParts[1]

	if org == "" || name == "" || version == "" {
		return "", "", "", fmt.Errorf("org, name, and version cannot be empty")
	}

	return org, name, version, nil
}

// Integration with version handling
func ResolvePackage(ctx context.Context, ref string) (*Package, error) {
	org, name, versionRef, err := parsePackageRef(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid package reference: %w", err)
	}

	// versionRef could be:
	// - "1.2.3" (semver)
	// - "latest" (resolve to latest stable)
	// - "sha:abc123..." (specific SHA)
	// - "digest:sha256:abc..." (specific digest)

	// For semver version, validate it
	if !strings.HasPrefix(versionRef, "sha:") && !strings.HasPrefix(versionRef, "digest:") {
		if versionRef != "latest" {
			if _, err := Parse(versionRef); err != nil {
				return nil, fmt.Errorf("invalid version %q: %w", versionRef, err)
			}
		}
	}

	// Query registry
	resolveResp, err := registryClient.Resolve(ctx, org, name, versionRef)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s/%s@%s: %w", org, name, versionRef, err)
	}

	return &Package{
		Org:     org,
		Name:    name,
		Version: resolveResp.Resolved.Version,
		Digest:  resolveResp.Resolved.Bundle.Digest,
	}, nil
}
```

---

## Common Mistakes and How to Avoid Them

### 1. String Comparison Instead of Semantic Comparison

```go
// Bad: string comparison
versions := []string{"1.10.0", "1.2.0", "1.9.0"}
sort.Strings(versions)
// Result: ["1.10.0", "1.2.0", "1.9.0"] // WRONG!

// Good: semantic comparison
var parsed Versions
for _, v := range versions {
	p, _ := Parse(v)
	parsed = append(parsed, p)
}
sort.Sort(parsed)
// Result: [1.2.0, 1.9.0, 1.10.0]
```

### 2. Ignoring Pre-release Precedence

```go
// Bad: treating pre-release as equal to release
if version == "1.0.0" {
	// This fails for "1.0.0-alpha"!
}

// Good: use Compare() method
v, _ := Parse(version)
release, _ := Parse("1.0.0")
if v.LessThan(release) {
	// Handles pre-releases correctly
}
```

### 3. Wrong Compatibility Range

```go
// Bad: using wrong range for compatibility check
if !isCompatible(newVersion, "~1.2.3") {
	// If newVersion is "1.3.0", this rejects it!
	// But 1.3.0 is compatible with 1.2.3
}

// Good: use correct range operator
if !isCompatible(newVersion, "^1.2.3") {
	// Now 1.3.0 is accepted
}
```

### 4. Not Handling "latest" Specially

```go
// Bad: trying to parse "latest" as semver
version, _ := Parse("latest")
// Fails!

// Good: handle "latest" separately
if ref == "latest" {
	latest, err := FindLatest(availableVersions)
	ref = latest
} else {
	version, err := Parse(ref)
}
```

### 5. Accepting Any Version Without Validation

```go
// Bad: no validation
manifest.Version = userInput

// Good: validate version format
if _, err := Parse(userInput); err != nil {
	return fmt.Errorf("invalid version: %w", err)
}
manifest.Version = userInput
```

---

## Summary Checklist

- [x] Understand semver format (MAJOR.MINOR.PATCH[-prerelease][+build])
- [x] Parse versions correctly (handle pre-release and build metadata)
- [x] Compare versions with pre-release precedence rules
- [x] Sort versions correctly (not lexically)
- [x] Implement compatibility ranges (^, ~, >=, <=, etc.)
- [x] Handle "latest" version resolution
- [x] Distinguish stable vs pre-release versions
- [x] Validate versions reject invalid formats
- [x] Test parsing, comparison, ranges, edge cases
- [x] Never use string comparison for version ordering
- [x] Document breaking changes (MAJOR bump)
- [x] Support version constraints in package references
