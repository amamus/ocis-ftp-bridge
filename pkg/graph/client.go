// Package graph provides LibreGraph client for drive resolution in ocis-ftp-bridge.
//
// This file implements the concrete LibreGraph API client using the official
// owncloud/libre-graph-api-go SDK.
package graph

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	libregraph "github.com/owncloud/libre-graph-api-go"
)

// libregraphClient is the concrete implementation of Client using the official SDK.
type libregraphClient struct {
	apiClient *libregraph.APIClient
	baseURL   string
	username  string
	token     string
	httpClient *http.Client
}

// NewLibreGraphClient creates a new LibreGraph client using the official SDK.
// baseURL is the base URL for the LibreGraph API (e.g., "https://ocis.example.com/api/libregraph").
// username and token are used for authentication.
func NewLibreGraphClient(baseURL, username, token string) Client {
	return NewLibreGraphClientWithHTTP(baseURL, username, token, nil)
}

// NewLibreGraphClientWithHTTP creates a new LibreGraph client with a custom HTTP client.
// This allows for custom timeouts, transport configurations, etc.
func NewLibreGraphClientWithHTTP(baseURL, username, token string, httpClient *http.Client) Client {
	if httpClient == nil {
		// Use reasonable defaults for production use
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
		}
	}

	// Ensure baseURL ends with exactly one slash for proper joining
	baseURL = strings.TrimRight(baseURL, "/") + "/"

	// Parse and validate the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		// Return a client that will fail on first use with invalid URL error
		// Still create an API client, but it will fail on actual use
		config := &libregraph.Configuration{
			HTTPClient: httpClient,
			UserAgent:  "ocis-ftp-bridge/1.0",
			Debug:     false,
		}
		return &libregraphClient{
			apiClient:   libregraph.NewAPIClient(config),
			baseURL:     baseURL,
			username:    username,
			token:       token,
			httpClient: httpClient,
		}
	}

	// Configure the LibreGraph API client
	config := &libregraph.Configuration{
		Servers: libregraph.ServerConfigurations{
			{URL: baseURL},
		},
		HTTPClient: httpClient,
		UserAgent:  "ocis-ftp-bridge/1.0",
		Debug:     false,
	}

	apiClient := libregraph.NewAPIClient(config)

	return &libregraphClient{
		apiClient:   apiClient,
		baseURL:     baseURL,
		username:    username,
		token:       token,
		httpClient: httpClient,
	}
}

// ResolveDrive resolves a drive by its ID and returns detailed drive information.
func (c *libregraphClient) ResolveDrive(id string) (Drive, error) {
	if id == "" {
		return Drive{}, ErrInvalidDriveID
	}

	// Check if apiClient is properly initialized
	if c.apiClient == nil {
		return Drive{}, fmt.Errorf("graph client not properly initialized: %w", ErrGraphAPIError)
	}

	// Use the drives API to get a specific drive
	drive, resp, err := c.apiClient.DrivesApi.GetDrive(
		c.withAuth(context.Background()),
		id,
	).Execute()
	
	if err != nil {
		return Drive{}, c.handleError(resp, err, "failed to resolve drive")
	}

	if drive == nil {
		return Drive{}, ErrDriveNotFound
	}

	return c.convertDrive(drive), nil
}

// ListDrives lists all drives for the authenticated user.
func (c *libregraphClient) ListDrives(userID string) ([]Drive, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	// Check if apiClient is properly initialized
	if c.apiClient == nil {
		return nil, fmt.Errorf("graph client not properly initialized: %w", ErrGraphAPIError)
	}

	// Use the me/drives endpoint to get drives for the current user
	resp, httpResp, err := c.apiClient.MeDrivesApi.ListMyDrives(
		c.withAuth(context.Background()),
	).Execute()
	
	if err != nil {
		return nil, c.handleError(httpResp, err, "failed to list drives")
	}

	if resp == nil || resp.GetValue() == nil {
		return []Drive{}, nil
	}

	drives := make([]Drive, 0, len(resp.GetValue()))
	for _, d := range resp.GetValue() {
		drives = append(drives, c.convertDrive(&d))
	}

	return drives, nil
}

// ResolveSpace resolves a space by its ID.
func (c *libregraphClient) ResolveSpace(id string) (Space, error) {
	if id == "" {
		return Space{}, ErrInvalidSpaceID
	}

	// Note: In LibreGraph API, spaces are typically accessed via drives
	// For now, we'll return an error as spaces API might not be available
	// in the current version of the SDK
	return Space{}, ErrNotImplemented
}

// ListSpaces lists all spaces for the authenticated user.
func (c *libregraphClient) ListSpaces(userID string) ([]Space, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	// Note: Similar to ResolveSpace, spaces API might not be available
	return []Space{}, nil
}

// SearchDrives searches for drives by name for a specific user.
func (c *libregraphClient) SearchDrives(userID, name string) ([]Drive, error) {
	if userID == "" || name == "" {
		return nil, ErrInvalidParameters
	}

	// List all drives and filter by name
	drives, err := c.ListDrives(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list drives for search: %w", err)
	}

	var matches []Drive
	for _, drive := range drives {
		if strings.EqualFold(drive.Name, name) {
			matches = append(matches, drive)
		}
	}

	return matches, nil
}

// SearchSpaces searches for spaces by name.
func (c *libregraphClient) SearchSpaces(userID, name string) ([]Space, error) {
	if userID == "" || name == "" {
		return nil, ErrInvalidParameters
	}

	// Note: Spaces API not implemented yet
	return []Space{}, nil
}

// withAuth adds authentication to the context for LibreGraph API calls.
func (c *libregraphClient) withAuth(ctx context.Context) context.Context {
	// Use AccessToken authentication if username is empty (token-only)
	// Otherwise use BasicAuth with username and token
	if c.username == "" {
		return context.WithValue(
			ctx,
			libregraph.ContextAccessToken,
			c.token,
		)
	}

	// Use BasicAuth with username and token as password
	return context.WithValue(
		ctx,
		libregraph.ContextBasicAuth,
		libregraph.BasicAuth{
			UserName: c.username,
			Password: c.token,
		},
	)
}

// handleError converts LibreGraph API errors to our domain-specific errors.
func (c *libregraphClient) handleError(resp *http.Response, err error, context string) error {
	if err == nil {
		return nil
	}

	// Check for specific HTTP status codes
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return ErrDriveNotFound
		case http.StatusUnauthorized:
			return ErrUnauthorized
		case http.StatusForbidden:
			return ErrForbidden
		case http.StatusBadRequest:
			return ErrInvalidParameters
		}
	}

	// Wrap the error with context
	return fmt.Errorf("%s: %w", context, ErrGraphAPIError)
}

// convertDrive converts a LibreGraph Drive to our internal Drive representation.
func (c *libregraphClient) convertDrive(drive *libregraph.Drive) Drive {
	// Extract WebDAV URL from the drive's webUrl if available
	webDAVURL := ""
	if drive.WebUrl != nil && *drive.WebUrl != "" {
		// Convert web URL to WebDAV URL
		webURL, err := url.Parse(*drive.WebUrl)
		if err == nil {
			// Replace the path with /webdav
			webURL.Path = "/webdav"
			webDAVURL = webURL.String()
		}
	}

	// Extract owner information
	owner := Owner{}
	if drive.Owner != nil && drive.Owner.User != nil {
		if drive.Owner.User.Id != nil {
			owner.ID = *drive.Owner.User.Id
		}
		if drive.Owner.User.DisplayName != nil {
			owner.DisplayName = *drive.Owner.User.DisplayName
		}
	}

	// Extract root information
	root := Root{}
	if drive.Root != nil && drive.Root.Id != nil {
		root.ID = *drive.Root.Id
	}

	// Extract permissions (not directly available in Drive, would need separate API calls)
	var permissions []Permission

	// Extract basic fields safely
	name := ""
	if drive.Name != nil {
		name = *drive.Name
	}

	description := ""
	if drive.Description != nil {
		description = *drive.Description
	}

	return Drive{
		ID:          c.safeString(drive.Id),
		Name:        name,
		Description: description,
		Owner:       owner,
		Permissions: permissions,
		Root:        root,
		WebDAVURL:   webDAVURL,
	}
}

// safeString safely dereferences a string pointer, returning empty string if nil.
func (c *libregraphClient) safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ValidateConfiguration validates that the LibreGraph client can connect to the API.
// This can be used during startup to verify configuration.
func (c *libregraphClient) ValidateConfiguration() error {
	// Try to list drives to validate the connection
	_, err := c.ListDrives("")
	if err != nil {
		return fmt.Errorf("LibreGraph configuration validation failed: %w", err)
	}
	return nil
}