// Package graph provides LibreGraph client for drive resolution in ocis-ftp-bridge.
//
// This file implements target resolution logic for drives and spaces.
package graph

import (
	"fmt"
)

// TargetResolver provides methods for resolving drive targets based on configuration.
type TargetResolver interface {
	// ResolveTarget resolves a target by either drive ID or drive name.
	// Returns the resolved Drive and WebDAV URL.
	ResolveTarget(driveID, driveName string) (Drive, string, error)

	// ValidateTarget validates that a target configuration is valid.
	// This can be used during startup to ensure all configured targets can be resolved.
	ValidateTarget(driveID, driveName string) error
}

// targetResolver implements TargetResolver.
type targetResolver struct {
	client Client
}

// NewTargetResolver creates a new target resolver.
func NewTargetResolver(client Client) TargetResolver {
	return &targetResolver{client: client}
}

// ResolveTarget resolves a target by either drive ID or drive name.
// Resolution rules:
// 1. If driveID is configured, it is authoritative.
// 2. If only drive name is configured, exactly one matching drive must exist.
// 3. Zero matches are an error.
// 4. Multiple name matches are an error and the operator must configure drive_id.
// 5. Do not silently fall back to another drive.
func (r *targetResolver) ResolveTarget(driveID, driveName string) (Drive, string, error) {
	var drive Drive

	// Rule 1: If driveID is configured, it is authoritative.
	if driveID != "" {
		var err error
		drive, err = r.client.ResolveDrive(driveID)
		if err != nil {
			return Drive{}, "", fmt.Errorf("failed to resolve drive by ID %q: %w", driveID, err)
		}
		return drive, drive.WebDAVURL, nil
	}

	// Rule 2: If only drive name is configured, exactly one matching drive must exist.
	if driveName != "" {
		matches, err := r.client.SearchDrives("", driveName)
		if err != nil {
			return Drive{}, "", fmt.Errorf("failed to search drives by name %q: %w", driveName, err)
		}

		// Rule 3: Zero matches are an error.
		if len(matches) == 0 {
			return Drive{}, "", fmt.Errorf("drive with name %q not found", driveName)
		}

		// Rule 4: Multiple name matches are an error.
		if len(matches) > 1 {
			return Drive{}, "", fmt.Errorf("ambiguous drive name %q: found %d drives, operator must configure drive_id", driveName, len(matches))
		}

		return matches[0], matches[0].WebDAVURL, nil
	}

	// Neither driveID nor driveName is configured
	return Drive{}, "", fmt.Errorf("either drive_id or drive must be configured")
}

// ValidateTarget validates that a target configuration is valid.
func (r *targetResolver) ValidateTarget(driveID, driveName string) error {
	// Check if we can resolve the target
	_, _, err := r.ResolveTarget(driveID, driveName)
	return err
}

// ResolverError represents an error during target resolution.
type ResolverError struct {
	msg string
}

func (e *ResolverError) Error() string {
	return fmt.Sprintf("resolver error: %s", e.msg)
}

var (
	ErrAmbiguousDriveName = &ResolverError{msg: "ambiguous drive name - multiple drives match the name"}
	ErrInvalidTarget      = &ResolverError{msg: "invalid target configuration"}
)