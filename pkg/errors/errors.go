// Package errors provides a consistent error handling framework for ocis-ftp-bridge.
// It standardizes error creation, wrapping, and checking across all packages.
package errors

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorCode represents a category of errors for consistent handling.
type ErrorCode string

// Standard error codes for the application.
const (
	// General errors
	ErrCodeUnknown         ErrorCode = "UNKNOWN"
	ErrCodeInvalidInput   ErrorCode = "INVALID_INPUT"
	ErrCodeNotFound       ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists  ErrorCode = "ALREADY_EXISTS"
	ErrCodeNotImplemented ErrorCode = "NOT_IMPLEMENTED"
	
	// Authentication and authorization errors
	ErrCodeUnauthorized   ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden      ErrorCode = "FORBIDDEN"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	
	// Configuration errors
	ErrCodeInvalidConfig  ErrorCode = "INVALID_CONFIG"
	ErrCodeConfigNotFound ErrorCode = "CONFIG_NOT_FOUND"
	
	// File and storage errors
	ErrCodeIO             ErrorCode = "IO_ERROR"
	ErrCodeFileTooLarge   ErrorCode = "FILE_TOO_LARGE"
	ErrCodeStorageFull    ErrorCode = "STORAGE_FULL"
	
	// Network and connection errors
	ErrCodeConnection     ErrorCode = "CONNECTION_ERROR"
	ErrCodeTimeout        ErrorCode = "TIMEOUT"
	
	// Security errors
	ErrCodePathTraversal  ErrorCode = "PATH_TRAVERSAL"
	ErrCodeSecurity       ErrorCode = "SECURITY_ERROR"
	
	// Rate limiting errors
	ErrCodeRateLimited    ErrorCode = "RATE_LIMITED"
	
	// Service errors
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeInternal        ErrorCode = "INTERNAL_ERROR"
)

// AppError is the structured error type for the application.
// It provides error codes, messages, and additional context for consistent error handling.
type AppError struct {
	// Code is the error category for programmatic error handling
	Code ErrorCode
	// Message is the human-readable error message
	Message string
	// Details contains additional context information
	Details map[string]interface{}
	// Err is the underlying error, if any
	Err error
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap implements the errors.Unwrap interface for error chaining.
func (e *AppError) Unwrap() error {
	return e.Err
}

// Is implements the errors.Is interface for error comparison.
func (e *AppError) Is(target error) bool {
	if target == nil {
		return false
	}
	
	// Check if target is an AppError with the same code
	if other, ok := target.(*AppError); ok {
		return e.Code == other.Code
	}
	
	// Check if target is a simple error with matching message
	if e.Err != nil {
		return errors.Is(e.Err, target)
	}
	
	return false
}

// New creates a new AppError with the given code and message.
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: make(map[string]interface{}),
		Err:     nil,
	}
}

// NewWithDetails creates a new AppError with the given code, message, and details.
func NewWithDetails(code ErrorCode, message string, details map[string]interface{}) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: details,
		Err:     nil,
	}
}

// Wrap creates a new AppError that wraps an existing error.
func Wrap(code ErrorCode, message string, err error) *AppError {
	if err == nil {
		return New(code, message)
	}
	
	return &AppError{
		Code:    code,
		Message: message,
		Details: make(map[string]interface{}),
		Err:     err,
	}
}

// WrapWithDetails creates a new AppError that wraps an existing error with additional details.
func WrapWithDetails(code ErrorCode, message string, err error, details map[string]interface{}) *AppError {
	if err == nil {
		return NewWithDetails(code, message, details)
	}
	
	appErr := &AppError{
		Code:    code,
		Message: message,
		Details: details,
		Err:     err,
	}
	
	// If the wrapped error is also an AppError, preserve its details
	if other, ok := err.(*AppError); ok {
		for k, v := range other.Details {
			if _, exists := appErr.Details[k]; !exists {
				appErr.Details[k] = v
			}
		}
	}
	
	return appErr
}

// GetCode extracts the error code from an error.
// Returns ErrCodeUnknown if the error is not an AppError.
func GetCode(err error) ErrorCode {
	if err == nil {
		return ErrCodeUnknown
	}
	
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	
	return ErrCodeUnknown
}

// GetMessage extracts the message from an error.
// Returns the error string if not an AppError.
func GetMessage(err error) string {
	if err == nil {
		return ""
	}
	
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Message
	}
	
	return err.Error()
}

// GetDetails extracts the details from an error.
// Returns nil if the error is not an AppError.
func GetDetails(err error) map[string]interface{} {
	if err == nil {
		return nil
	}
	
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Details
	}
	
	return nil
}

// IsCode checks if the error has the specified error code.
func IsCode(err error, code ErrorCode) bool {
	return GetCode(err) == code
}

// IsAnyCode checks if the error has any of the specified error codes.
func IsAnyCode(err error, codes ...ErrorCode) bool {
	if err == nil {
		return false
	}
	
	code := GetCode(err)
	for _, c := range codes {
		if code == c {
			return true
		}
	}
	return false
}

// WithDetails adds details to an existing error.
// If the error is not an AppError, it creates a new AppError with the given details.
func WithDetails(err error, details map[string]interface{}) error {
	if err == nil {
		return nil
	}
	
	var appErr *AppError
	if errors.As(err, &appErr) {
		// Merge details
		for k, v := range details {
			appErr.Details[k] = v
		}
		return appErr
	}
	
	// For non-AppError, create a new AppError
	return &AppError{
		Code:    ErrCodeInternal,
		Message: err.Error(),
		Details: details,
		Err:     err,
	}
}

// Convenience constructors for common error scenarios

// NotFound creates a not found error.
func NotFound(resource string, id interface{}) error {
	return NewWithDetails(
		ErrCodeNotFound,
		fmt.Sprintf("%s not found: %v", resource, id),
		map[string]interface{}{
			"resource": resource,
			"id":       id,
		},
	)
}

// InvalidInput creates an invalid input error.
func InvalidInput(message string, details map[string]interface{}) error {
	return NewWithDetails(ErrCodeInvalidInput, message, details)
}

// Unauthorized creates an unauthorized error.
func Unauthorized(message string) error {
	return New(ErrCodeUnauthorized, message)
}

// Forbidden creates a forbidden error.
func Forbidden(message string) error {
	return New(ErrCodeForbidden, message)
}

// PathTraversal creates a path traversal error.
func PathTraversal(path string) error {
	return NewWithDetails(
		ErrCodePathTraversal,
		fmt.Sprintf("path traversal detected: %s", path),
		map[string]interface{}{
			"path": path,
		},
	)
}

// IOError creates an I/O error.
func IOError(message string, err error) error {
	return Wrap(ErrCodeIO, message, err)
}

// ConfigError creates a configuration error.
func ConfigError(message string, err error) error {
	return Wrap(ErrCodeInvalidConfig, message, err)
}

// InternalError creates an internal error.
func InternalError(message string, err error) error {
	return Wrap(ErrCodeInternal, message, err)
}

// AlreadyExists creates an already exists error.
func AlreadyExists(resource string, id interface{}) error {
	return NewWithDetails(
		ErrCodeAlreadyExists,
		fmt.Sprintf("%s already exists: %v", resource, id),
		map[string]interface{}{
			"resource": resource,
			"id":       id,
		},
	)
}

// RateLimited creates a rate limited error.
func RateLimited(message string) error {
	return New(ErrCodeRateLimited, message)
}

// StorageFull creates a storage full error.
func StorageFull(message string) error {
	return New(ErrCodeStorageFull, message)
}

// Join combines multiple errors into a single error.
// If all errors are nil, returns nil.
// If there's only one non-nil error, returns that error.
// Otherwise, returns an AppError with ErrCodeInternal containing all errors.
func Join(errs ...error) error {
	var nonNilErrs []error
	for _, err := range errs {
		if err != nil {
			nonNilErrs = append(nonNilErrs, err)
		}
	}
	
	if len(nonNilErrs) == 0 {
		return nil
	}
	
	if len(nonNilErrs) == 1 {
		return nonNilErrs[0]
	}
	
	// Create a combined error message
	var messages []string
	for _, err := range nonNilErrs {
		messages = append(messages, err.Error())
	}
	
	return New(
		ErrCodeInternal,
		fmt.Sprintf("multiple errors: %s", strings.Join(messages, "; ")),
	)
}

// HTTPStatus returns the appropriate HTTP status code for an error.
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}
	
	switch GetCode(err) {
	case ErrCodeNotFound:
		return 404
	case ErrCodeInvalidInput:
		return 400
	case ErrCodeUnauthorized:
		return 401
	case ErrCodeForbidden:
		return 403
	case ErrCodeAlreadyExists:
		return 409
	case ErrCodePathTraversal:
		return 400
	case ErrCodeRateLimited:
		return 429
	case ErrCodeServiceUnavailable:
		return 503
	case ErrCodeInvalidConfig:
		return 500
	case ErrCodeInternal:
		return 500
	default:
		return 500
	}
}