// Package observability provides observability utilities for ocis-ftp-bridge.
//
// It defines interfaces and implementations for logging, metrics, and tracing.
package observability

import (
	"log/slog"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
)

// Client is the interface for observability operations.
type Client interface {
	// Start initializes observability
	Start() error
	
	// Stop shuts down observability
	Stop() error
	
	// Logger returns the structured logger
	Logger() *Logger
	
	// Log logs a message (deprecated, use structured logging)
	Log(level, message string)
	
	// Debug logs a debug message with structured fields
	Debug(msg string, args ...any)
	
	// Info logs an info message with structured fields
	Info(msg string, args ...any)
	
	// Warn logs a warning message with structured fields
	Warn(msg string, args ...any)
	
	// Error logs an error message with structured fields
	Error(msg string, args ...any)
	
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
	// Logger contains logging configuration
	Logger config.LoggerConfig `json:"logger" yaml:"logger"`
}

// defaultClient is the default implementation of Client
type defaultClient struct {
	logger *Logger
	debug  bool
}

// New creates a new observability client
func New(cfg Config) (Client, error) {
	logger, err := NewLogger(cfg.Logger)
	if err != nil {
		return nil, err
	}
	
	if cfg.Debug {
		logger.Debug("Observability: debug mode enabled")
	}
	
	return &defaultClient{
		logger: logger,
		debug:  cfg.Debug,
	}, nil
}

// Start implements Client.Start
func (c *defaultClient) Start() error {
	c.logger.Info("Observability started")
	return nil
}

// Stop implements Client.Stop
func (c *defaultClient) Stop() error {
	c.logger.Info("Observability stopped")
	return nil
}

// Logger implements Client.Logger
func (c *defaultClient) Logger() *Logger {
	return c.logger
}

// Log implements Client.Log (deprecated compatibility method)
func (c *defaultClient) Log(level, message string) {
	// Convert old-style log calls to structured logging
	c.logger.Info(message, slog.String("level", level))
}

// Debug implements Client.Debug
func (c *defaultClient) Debug(msg string, args ...any) {
	c.logger.Debug(msg, args...)
}

// Info implements Client.Info
func (c *defaultClient) Info(msg string, args ...any) {
	c.logger.Info(msg, args...)
}

// Warn implements Client.Warn
func (c *defaultClient) Warn(msg string, args ...any) {
	c.logger.Warn(msg, args...)
}

// Error implements Client.Error
func (c *defaultClient) Error(msg string, args ...any) {
	c.logger.Error(msg, args...)
}

// Metric implements Client.Metric
func (c *defaultClient) Metric(name, value string) {
	// For now, log metrics as debug
	c.logger.Debug("Metric recorded", slog.String("name", name), slog.String("value", value))
}

// Trace implements Client.Trace
func (c *defaultClient) Trace(name string) Context {
	c.logger.Debug("Trace started", slog.String("name", name))
	return &defaultContext{}
}

// defaultContext is the default implementation of Context
type defaultContext struct{}

// Finish implements Context.Finish
func (c *defaultContext) Finish() {
	// Get the global logger for context finish
	GetLogger().Debug("Trace finished")
}

// Errors
type ObservabilityError struct {
	msg string
}

func (e *ObservabilityError) Error() string {
	return "observability error: " + e.msg
}

var (
	ErrInvalidConfig     = &ObservabilityError{msg: "invalid observability config"}
	ErrObservabilityStop = &ObservabilityError{msg: "failed to stop observability"}
)
