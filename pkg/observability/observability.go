// Package observability provides observability utilities for ocis-ftp-bridge.
//
// It defines interfaces and implementations for logging, metrics, and tracing.
package observability

import "fmt"

// Client is the interface for observability operations.
type Client interface {
	// Start initializes observability
	Start() error
	
	// Stop shuts down observability
	Stop() error
	
	// Log logs a message
	Log(level, message string)
	
	// Metric records a metric
	Metric(name, value string)
	
	// Trace starts a trace
	Trace(name string) Context
}

// Context represents a tracing context
type Context interface {
	// Finish completes the trace
	Finish()
}

// Config contains configuration for observability
type Config struct {
	// Debug enables verbose logging
	Debug bool `json:"debug"`
}

// New creates a new observability client
func New(cfg Config) (Client, error) {
	if cfg.Debug {
		fmt.Println("Observability: debug mode enabled")
	}
	return &defaultClient{}, nil
}

// defaultClient is the default implementation of Client
type defaultClient struct {
	debug bool
}

// Start implements Client.Start
func (c *defaultClient) Start() error {
	fmt.Println("Observability started")
	return nil
}

// Stop implements Client.Stop
func (c *defaultClient) Stop() error {
	fmt.Println("Observability stopped")
	return nil
}

// Log implements Client.Log
func (c *defaultClient) Log(level, message string) {
	fmt.Printf("[%s] %s\n", level, message)
}

// Metric implements Client.Metric
func (c *defaultClient) Metric(name, value string) {
	fmt.Printf("Metric: %s=%s\n", name, value)
}

// Trace implements Client.Trace
func (c *defaultClient) Trace(name string) Context {
	fmt.Printf("Trace started: %s\n", name)
	return &defaultContext{}
}

// defaultContext is the default implementation of Context
type defaultContext struct{}

// Finish implements Context.Finish
func (c *defaultContext) Finish() {
	fmt.Println("Trace finished")
}

// Errors
type ObservabilityError struct {
	msg string
}

func (e *ObservabilityError) Error() string {
	return fmt.Sprintf("observability error: %s", e.msg)
}

var (
	ErrInvalidConfig     = &ObservabilityError{msg: "invalid observability config"}
	ErrObservabilityStop = &ObservabilityError{msg: "failed to stop observability"}
)
