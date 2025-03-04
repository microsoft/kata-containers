package core

import (
	"context"
	"time"
)

type TestResult struct {
	Name           string                 `json:"name"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	Success        bool                   `json:"success"`
	Metrics        map[string]interface{} `json:"metrics"`
	ExpectedValues map[string]interface{} `json:"expected_values"`
	Error          string                 `json:"error,omitempty"`
}

type Test interface {
	Name() string
	Run(ctx context.Context, expectedValues map[string]interface{}) TestResult
}
