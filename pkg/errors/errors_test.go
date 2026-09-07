package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name:     "simple error",
			err:      New(ErrCodeNotFound, "user not found"),
			expected: "NOT_FOUND: user not found",
		},
		{
			name:     "error with underlying error",
			err:      Wrap(ErrCodeIO, "failed to read file", fmt.Errorf("permission denied")),
			expected: "IO_ERROR: failed to read file: permission denied",
		},
		{
			name:     "error with details",
			err:      NewWithDetails(ErrCodeInvalidInput, "invalid path", map[string]interface{}{"path": "/test/../file"}),
			expected: "INVALID_INPUT: invalid path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("AppError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	underlyingErr := fmt.Errorf("underlying error")
	wrappedErr := Wrap(ErrCodeIO, "wrapped message", underlyingErr)

	// Test Unwrap
	if unwrapped := wrappedErr.Unwrap(); unwrapped != underlyingErr {
		t.Errorf("AppError.Unwrap() = %v, want %v", unwrapped, underlyingErr)
	}

	// Test errors.Is
	if !errors.Is(wrappedErr, underlyingErr) {
		t.Error("errors.Is should find underlying error")
	}
}

func TestAppError_Is(t *testing.T) {
	// Create two errors with same code
	err1 := New(ErrCodeNotFound, "not found 1")
	err2 := New(ErrCodeNotFound, "not found 2")
	err3 := New(ErrCodeInvalidInput, "invalid input")

	// Same code should be equal
	if !err1.Is(err2) {
		t.Error("errors with same code should be equal")
	}

	// Different codes should not be equal
	if err1.Is(err3) {
		t.Error("errors with different codes should not be equal")
	}

	// Test with underlying errors
	underlying := fmt.Errorf("underlying")
	wrapped := Wrap(ErrCodeIO, "wrapped", underlying)
	
	if !wrapped.Is(underlying) {
		t.Error("wrapped error should be equal to underlying error")
	}
}

func TestGetCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected ErrorCode
	}{
		{
			name:     "AppError with code",
			err:      New(ErrCodeNotFound, "not found"),
			expected: ErrCodeNotFound,
		},
		{
			name:     "wrapped AppError",
			err:      Wrap(ErrCodeIO, "wrapped", fmt.Errorf("underlying")),
			expected: ErrCodeIO,
		},
		{
			name:     "regular error",
			err:      fmt.Errorf("regular error"),
			expected: ErrCodeUnknown,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: ErrCodeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCode(tt.err); got != tt.expected {
				t.Errorf("GetCode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "AppError message",
			err:      New(ErrCodeNotFound, "user not found"),
			expected: "user not found",
		},
		{
			name:     "regular error",
			err:      fmt.Errorf("regular error"),
			expected: "regular error",
		},
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetMessage(tt.err); got != tt.expected {
				t.Errorf("GetMessage() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetDetails(t *testing.T) {
	// Test with AppError that has details
	details := map[string]interface{}{"key": "value", "count": 42}
	err := NewWithDetails(ErrCodeInvalidInput, "invalid", details)

	gotDetails := GetDetails(err)
	if gotDetails == nil {
		t.Fatal("GetDetails should return non-nil map")
	}

	if gotDetails["key"] != "value" {
		t.Errorf("GetDetails()[key] = %v, want %v", gotDetails["key"], "value")
	}

	if gotDetails["count"] != 42 {
		t.Errorf("GetDetails()[count] = %v, want %v", gotDetails["count"], 42)
	}

	// Test with regular error
	regularErr := fmt.Errorf("regular error")
	if gotDetails := GetDetails(regularErr); gotDetails != nil {
		t.Error("GetDetails of regular error should return nil")
	}
}

func TestIsCode(t *testing.T) {
	err := New(ErrCodeNotFound, "not found")

	if !IsCode(err, ErrCodeNotFound) {
		t.Error("IsCode should return true for matching code")
	}

	if IsCode(err, ErrCodeInvalidInput) {
		t.Error("IsCode should return false for non-matching code")
	}

	if IsCode(nil, ErrCodeNotFound) {
		t.Error("IsCode should return false for nil error")
	}
}

func TestIsAnyCode(t *testing.T) {
	err := New(ErrCodeNotFound, "not found")

	if !IsAnyCode(err, ErrCodeNotFound, ErrCodeInvalidInput) {
		t.Error("IsAnyCode should return true when any code matches")
	}

	if IsAnyCode(err, ErrCodeInvalidInput, ErrCodeIO) {
		t.Error("IsAnyCode should return false when no codes match")
	}
}

func TestWithDetails(t *testing.T) {
	// Test adding details to AppError
	err := New(ErrCodeNotFound, "not found")
	newErr := WithDetails(err, map[string]interface{}{"id": "123"})

	if GetCode(newErr) != ErrCodeNotFound {
		t.Error("WithDetails should preserve error code")
	}

	if GetMessage(newErr) != "not found" {
		t.Error("WithDetails should preserve error message")
	}

	details := GetDetails(newErr)
	if details["id"] != "123" {
		t.Error("WithDetails should add new details")
	}

	// Test with regular error
	regularErr := fmt.Errorf("regular error")
	newRegularErr := WithDetails(regularErr, map[string]interface{}{"context": "test"})

	if GetCode(newRegularErr) != ErrCodeInternal {
		t.Error("WithDetails on regular error should create internal error")
	}
}

func TestConvenienceConstructors(t *testing.T) {
	// Test NotFound
	notFoundErr := NotFound("user", "123")
	if !IsCode(notFoundErr, ErrCodeNotFound) {
		t.Error("NotFound should create NOT_FOUND error")
	}

	details := GetDetails(notFoundErr)
	if details["resource"] != "user" || details["id"] != "123" {
		t.Error("NotFound should include resource and id in details")
	}

	// Test InvalidInput
	invalidInputErr := InvalidInput("bad path", map[string]interface{}{"path": "/test/../file"})
	if !IsCode(invalidInputErr, ErrCodeInvalidInput) {
		t.Error("InvalidInput should create INVALID_INPUT error")
	}

	// Test Unauthorized
	unauthorizedErr := Unauthorized("access denied")
	if !IsCode(unauthorizedErr, ErrCodeUnauthorized) {
		t.Error("Unauthorized should create UNAUTHORIZED error")
	}

	// Test Forbidden
	forbiddenErr := Forbidden("not allowed")
	if !IsCode(forbiddenErr, ErrCodeForbidden) {
		t.Error("Forbidden should create FORBIDDEN error")
	}

	// Test PathTraversal
	pathTraversalErr := PathTraversal("/test/../file")
	if !IsCode(pathTraversalErr, ErrCodePathTraversal) {
		t.Error("PathTraversal should create PATH_TRAVERSAL error")
	}

	// Test IOError
	underlyingErr := fmt.Errorf("permission denied")
	ioErr := IOError("failed to read", underlyingErr)
	if !IsCode(ioErr, ErrCodeIO) {
		t.Error("IOError should create IO_ERROR error")
	}
	if !errors.Is(ioErr, underlyingErr) {
		t.Error("IOError should wrap underlying error")
	}

	// Test ConfigError
	configErr := ConfigError("invalid config", fmt.Errorf("missing field"))
	if !IsCode(configErr, ErrCodeInvalidConfig) {
		t.Error("ConfigError should create INVALID_CONFIG error")
	}

	// Test InternalError
	internalErr := InternalError("internal error", fmt.Errorf("database failure"))
	if !IsCode(internalErr, ErrCodeInternal) {
		t.Error("InternalError should create INTERNAL_ERROR error")
	}

	// Test AlreadyExists
	alreadyExistsErr := AlreadyExists("user", "admin")
	if !IsCode(alreadyExistsErr, ErrCodeAlreadyExists) {
		t.Error("AlreadyExists should create ALREADY_EXISTS error")
	}

	// Test RateLimited
	rateLimitedErr := RateLimited("too many requests")
	if !IsCode(rateLimitedErr, ErrCodeRateLimited) {
		t.Error("RateLimited should create RATE_LIMITED error")
	}
}

func TestJoin(t *testing.T) {
	// Test with no errors
	if err := Join(); err != nil {
		t.Error("Join with no errors should return nil")
	}

	// Test with nil errors
	if err := Join(nil, nil); err != nil {
		t.Error("Join with nil errors should return nil")
	}

	// Test with single error
	singleErr := fmt.Errorf("single error")
	if err := Join(singleErr); err != singleErr {
		t.Error("Join with single error should return that error")
	}

	// Test with multiple errors
	err1 := fmt.Errorf("error 1")
	err2 := fmt.Errorf("error 2")
	joinedErr := Join(err1, err2)

	if joinedErr == nil {
		t.Error("Join with multiple errors should return non-nil error")
	}

	if !IsCode(joinedErr, ErrCodeInternal) {
		t.Error("Join with multiple errors should create INTERNAL error")
	}

	// Check that the error message contains both errors
	errMsg := joinedErr.Error()
	if !contains(errMsg, "error 1") || !contains(errMsg, "error 2") {
		t.Error("Join should include all error messages in the result")
	}
}

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{name: "NotFound", err: New(ErrCodeNotFound, "not found"), expected: 404},
		{name: "InvalidInput", err: New(ErrCodeInvalidInput, "invalid"), expected: 400},
		{name: "Unauthorized", err: New(ErrCodeUnauthorized, "unauthorized"), expected: 401},
		{name: "Forbidden", err: New(ErrCodeForbidden, "forbidden"), expected: 403},
		{name: "AlreadyExists", err: New(ErrCodeAlreadyExists, "exists"), expected: 409},
		{name: "PathTraversal", err: New(ErrCodePathTraversal, "traversal"), expected: 400},
		{name: "RateLimited", err: New(ErrCodeRateLimited, "rate limited"), expected: 429},
		{name: "ServiceUnavailable", err: New(ErrCodeServiceUnavailable, "unavailable"), expected: 503},
		{name: "InternalError", err: New(ErrCodeInternal, "internal"), expected: 500},
		{name: "InvalidConfig", err: New(ErrCodeInvalidConfig, "invalid config"), expected: 500},
		{name: "nil", err: nil, expected: 200},
		{name: "regular error", err: fmt.Errorf("regular error"), expected: 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTTPStatus(tt.err); got != tt.expected {
				t.Errorf("HTTPStatus() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Helper function for testing
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}