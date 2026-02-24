package policy

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScorePolicy(t *testing.T) {
	tests := []struct {
		name         string
		minScore     int
		enforceMode  string
		expectedMin  int
		expectedMode string
	}{
		{"default_no_enforcement", 0, DisabledMode, 0, DisabledMode},
		{"score_75_strict", 75, StrictMode, 75, StrictMode},
		{"score_60_warn", 60, WarnMode, 60, WarnMode},
		{"score_90_strict", 90, StrictMode, 90, StrictMode},
		{"invalid_mode_defaults_disabled", 50, "invalid", 50, DisabledMode},
		{"clamp_negative_score", -10, StrictMode, 0, StrictMode},
		{"clamp_over_max_score", 150, StrictMode, 100, StrictMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewScorePolicy(tt.minScore, tt.enforceMode)
			assert.Equal(t, tt.expectedMin, p.MinScore)
			assert.Equal(t, tt.expectedMode, p.EnforceMode)
		})
	}
}

func TestNewScorePolicyWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	p := NewScorePolicyWithLogger(75, StrictMode, logger)

	assert.Equal(t, 75, p.MinScore)
	assert.Equal(t, StrictMode, p.EnforceMode)
	assert.NotNil(t, p.logger)
}

func TestScorePolicy_ValidateDisabledMode(t *testing.T) {
	p := NewScorePolicy(75, DisabledMode)

	// Should allow any score in disabled mode
	assert.NoError(t, p.Validate(0))
	assert.NoError(t, p.Validate(50))
	assert.NoError(t, p.Validate(75))
	assert.NoError(t, p.Validate(100))
}

func TestScorePolicy_ValidateNoMinimum(t *testing.T) {
	p := NewScorePolicy(0, StrictMode)

	// With minimum 0, should allow all scores
	assert.NoError(t, p.Validate(0))
	assert.NoError(t, p.Validate(50))
	assert.NoError(t, p.Validate(100))
}

func TestScorePolicy_ValidateStrictMode(t *testing.T) {
	tests := []struct {
		name        string
		minScore    int
		score       int
		shouldError bool
	}{
		{"score_meets_minimum", 75, 75, false},
		{"score_exceeds_minimum", 75, 90, false},
		{"score_below_minimum", 75, 60, true},
		{"score_zero_below_minimum", 50, 0, true},
		{"score_boundary", 80, 80, false},
		{"score_one_below", 80, 79, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewScorePolicy(tt.minScore, StrictMode)
			err := p.Validate(tt.score)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "security score")
				assert.Contains(t, err.Error(), "below minimum")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestScorePolicy_ValidateWarnMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	p := NewScorePolicyWithLogger(75, WarnMode, logger)

	// Warn mode should allow execution even when score is below minimum
	tests := []struct {
		score int
	}{
		{0},
		{50},
		{74},
		{75},
		{100},
	}

	for _, tt := range tests {
		t.Run("warn_mode_allows_all_scores", func(t *testing.T) {
			err := p.Validate(tt.score)
			assert.NoError(t, err, "warn mode should not return error")
		})
	}
}

func TestScorePolicy_ValidateClamping(t *testing.T) {
	p := NewScorePolicy(50, StrictMode)

	// Negative score should be clamped to 0
	err := p.Validate(-10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")

	// Over-max score should be clamped to 100
	err = p.Validate(200)
	assert.NoError(t, err) // 100 >= 50
}

func TestScorePolicy_IsEnforced(t *testing.T) {
	tests := []struct {
		mode       string
		isEnforced bool
	}{
		{DisabledMode, false},
		{StrictMode, true},
		{WarnMode, true},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			p := NewScorePolicy(50, tt.mode)
			assert.Equal(t, tt.isEnforced, p.IsEnforced())
		})
	}
}

func TestScorePolicy_GetMinScore(t *testing.T) {
	p := NewScorePolicy(75, StrictMode)
	assert.Equal(t, 75, p.GetMinScore())
}

func TestScorePolicy_GetEnforceMode(t *testing.T) {
	p := NewScorePolicy(50, WarnMode)
	assert.Equal(t, WarnMode, p.GetEnforceMode())
}

func TestScorePolicy_ErrorMessages(t *testing.T) {
	p := NewScorePolicy(80, StrictMode)

	err := p.Validate(60)
	require.Error(t, err)

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "security score 60")
	assert.Contains(t, errorMsg, "minimum required score 80")
}

func TestScorePolicy_AllModes(t *testing.T) {
	// Test strict mode blocking
	strictPolicy := NewScorePolicy(75, StrictMode)
	assert.Error(t, strictPolicy.Validate(50))

	// Test warn mode allowing
	warnPolicy := NewScorePolicy(75, WarnMode)
	assert.NoError(t, warnPolicy.Validate(50))

	// Test disabled mode allowing
	disabledPolicy := NewScorePolicy(75, DisabledMode)
	assert.NoError(t, disabledPolicy.Validate(50))
}

func TestScorePolicy_BoundaryValues(t *testing.T) {
	tests := []struct {
		name        string
		minScore    int
		testScore   int
		expectError bool
	}{
		{"min_0_test_0", 0, 0, false},
		{"min_0_test_100", 0, 100, false},
		{"min_50_test_49", 50, 49, true},
		{"min_50_test_50", 50, 50, false},
		{"min_100_test_99", 100, 99, true},
		{"min_100_test_100", 100, 100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewScorePolicy(tt.minScore, StrictMode)
			err := p.Validate(tt.testScore)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
