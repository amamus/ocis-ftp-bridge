// Package observability provides observability utilities for ocis-ftp-bridge.
//
// This file implements structured logging using slog.
package observability

import (
	"log/slog"
	"os"
	"sync"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
)

// Level represents the logging level
type Level int

const (
	// LevelDebug is the debug level
	LevelDebug Level = iota
	// LevelInfo is the info level
	LevelInfo
	// LevelWarn is the warn level
	LevelWarn
	// LevelError is the error level
	LevelError
)

// String returns the string representation of the log level
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// SLogLevel converts Level to slog.Level
func (l Level) SLogLevel() slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseLevel parses a string level into a Level
func ParseLevel(level string) Level {
	switch level {
	case "DEBUG", "debug":
		return LevelDebug
	case "INFO", "info":
		return LevelInfo
	case "WARN", "warn", "WARNING", "warning":
		return LevelWarn
	case "ERROR", "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger is a structured logger that wraps slog.Logger
type Logger struct {
	logger *slog.Logger
	level  Level
	mu     sync.Mutex
}

// DefaultLoggerConfig returns the default logger configuration
func DefaultLoggerConfig() config.LoggerConfig {
	return config.LoggerConfig{
		Level:     "info",
		Format:    "json",
		Output:    "stdout",
		AddSource: true,
	}
}

// NewLogger creates a new Logger with the given configuration
func NewLogger(cfg config.LoggerConfig) (*Logger, error) {
	level := ParseLevel(cfg.Level)
	
	var handler slog.Handler
	
	// Create handler based on format
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(getOutputWriter(cfg.Output), &slog.HandlerOptions{
			AddSource: cfg.AddSource,
		})
	case "text":
		handler = slog.NewTextHandler(getOutputWriter(cfg.Output), &slog.HandlerOptions{
			AddSource: cfg.AddSource,
		})
	default:
		// Default to JSON
		handler = slog.NewJSONHandler(getOutputWriter(cfg.Output), &slog.HandlerOptions{
			AddSource: cfg.AddSource,
		})
	}
	
	// Create slog logger with the handler
	slogLogger := slog.New(handler)
	
	// Set the level
	slogLogger = slogLogger.With(
		slog.String("logger", "ocis-ftp-bridge"),
	)
	
	return &Logger{
		logger: slogLogger,
		level:  level,
	}, nil
}

// getOutputWriter returns the appropriate writer for the output
func getOutputWriter(output string) *os.File {
	switch output {
	case "stdout":
		return os.Stdout
	case "stderr":
		return os.Stderr
	case "":
		return os.Stdout
	default:
		// For file paths, open the file
		file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			// Fall back to stdout if file cannot be opened
			return os.Stdout
		}
		return file
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...any) {
	l.log(LevelDebug, msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...any) {
	l.log(LevelInfo, msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...any) {
	l.log(LevelWarn, msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...any) {
	l.log(LevelError, msg, args...)
}

// log handles the actual logging with level checking
func (l *Logger) log(level Level, msg string, args ...any) {
	if level < l.level {
		return
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// Add level to the args
	allArgs := append([]any{"level", level.String()}, args...)
	
	l.logger.Log(nil, level.SLogLevel(), msg, allArgs...)
}

// With adds fields to the logger
func (l *Logger) With(args ...any) *Logger {
	newLogger := &Logger{
		logger: l.logger.With(args...),
		level:  l.level,
	}
	return newLogger
}

// WithGroup adds a group of fields to the logger
func (l *Logger) WithGroup(key string, args ...any) *Logger {
	newLogger := &Logger{
		logger: l.logger.WithGroup(key).With(args...),
		level:  l.level,
	}
	return newLogger
}

// SLog returns the underlying slog.Logger for advanced usage
func (l *Logger) SLog() *slog.Logger {
	return l.logger
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// Global logger instance
var globalLogger *Logger
var globalLoggerOnce sync.Once

// GetLogger returns the global logger, initializing it if necessary
func GetLogger() *Logger {
	globalLoggerOnce.Do(func() {
		// Create default logger
		logger, err := NewLogger(DefaultLoggerConfig())
		if err != nil {
			// Fall back to a basic logger
			globalLogger = &Logger{
				logger: slog.Default(),
				level:  LevelInfo,
			}
			return
		}
		globalLogger = logger
	})
	return globalLogger
}

// SetGlobalLogger sets the global logger
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// Package-level convenience functions that use the global logger

// Debug logs a debug message using the global logger
func Debug(msg string, args ...any) {
	GetLogger().Debug(msg, args...)
}

// Info logs an info message using the global logger
func Info(msg string, args ...any) {
	GetLogger().Info(msg, args...)
}

// Warn logs a warning message using the global logger
func Warn(msg string, args ...any) {
	GetLogger().Warn(msg, args...)
}

// Error logs an error message using the global logger
func Error(msg string, args ...any) {
	GetLogger().Error(msg, args...)
}