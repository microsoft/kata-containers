package core

import (
    "context"
    "time"
)

// TestResult represents the result of a single test
type TestResult struct {
    Name      string                 `json:"name"`
    StartTime time.Time             `json:"start_time"`
    EndTime   time.Time             `json:"end_time"`
    Success   bool                  `json:"success"`
    Metrics   map[string]interface{} `json:"metrics"`
    Error     string                `json:"error,omitempty"`
}

// Test interface that all tests must implement
type Test interface {
    Name() string
    Run(context.Context) TestResult
}