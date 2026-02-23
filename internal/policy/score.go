package policy

import (
	"fmt"
	"log/slog"
)

// ScorePolicy represents policy enforcement for security scores
type ScorePolicy struct {
	MinScore    int    // 0-100
	EnforceMode string // strict, warn, disabled
	logger      *slog.Logger
}

// NewScorePolicy creates a new score policy
func NewScorePolicy(minScore int, enforceMode string) *ScorePolicy {
	logger := slog.Default()
	return NewScorePolicyWithLogger(minScore, enforceMode, logger)
}

// NewScorePolicyWithLogger creates a new score policy with custom logger
func NewScorePolicyWithLogger(minScore int, enforceMode string, logger *slog.Logger) *ScorePolicy {
	// Normalize enforce mode
	if enforceMode != StrictMode && enforceMode != WarnMode && enforceMode != DisabledMode {
		enforceMode = DisabledMode // Default to disabled for invalid modes
	}

	// Clamp min score to valid range (0-100)
	if minScore < 0 {
		minScore = 0
	}
	if minScore > 100 {
		minScore = 100
	}

	return &ScorePolicy{
		MinScore:    minScore,
		EnforceMode: enforceMode,
		logger:      logger,
	}
}

// Validate checks if the given score meets the policy requirements.
// Returns nil if allowed, error if blocked (in strict mode).
func (p *ScorePolicy) Validate(score int) error {
	// If enforcement is disabled, always allow
	if p.EnforceMode == DisabledMode {
		return nil
	}

	// If minimum is not set (0), allow everything
	if p.MinScore == 0 {
		return nil
	}

	// Clamp score to valid range
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// Check if score meets minimum requirement
	if score >= p.MinScore {
		return nil
	}

	// Score is below minimum
	message := fmt.Sprintf(
		"security score %d is below minimum required score %d",
		score, p.MinScore,
	)

	if p.EnforceMode == WarnMode {
		p.logger.Warn(message,
			slog.Int("score", score),
			slog.Int("minimum_required", p.MinScore),
			slog.String("enforce_mode", "warn"),
		)
		return nil // Allow execution in warn mode
	}

	// Strict mode: block execution
	return fmt.Errorf("%s", message) //nolint:goerr113 // dynamic message based on scores
}

// IsEnforced returns true if the policy is actively enforced (not disabled)
func (p *ScorePolicy) IsEnforced() bool {
	return p.EnforceMode != DisabledMode
}

// GetMinScore returns the minimum score required
func (p *ScorePolicy) GetMinScore() int {
	return p.MinScore
}

// GetEnforceMode returns the enforcement mode
func (p *ScorePolicy) GetEnforceMode() string {
	return p.EnforceMode
}
