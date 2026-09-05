package graph

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLibreGraphClient_InvalidURL(t *testing.T) {
	t.Parallel()

	// Test with invalid URL
	client := NewLibreGraphClient("invalid-url", "user", "token")
	_, err := client.ListDrives("user1")
	require.Error(t, err)
}

func TestNewLibreGraphClient_EmptyCredentials(t *testing.T) {
	t.Parallel()

	// Test with empty credentials - should fail on authentication
	client := NewLibreGraphClient("http://localhost:9200/api/libregraph", "", "")
	_, err := client.ListDrives("user1")
	require.Error(t, err)
}

func TestLibreGraphClient_ResolveDrive_EmptyID(t *testing.T) {
	t.Parallel()

	client := NewLibreGraphClient("http://localhost:9200/api/libregraph", "user", "token")
	_, err := client.ResolveDrive("")
	require.Error(t, err)
	assert.Equal(t, ErrInvalidDriveID, err)
}

func TestLibreGraphClient_ListDrives_EmptyUserID(t *testing.T) {
	t.Parallel()

	client := NewLibreGraphClient("http://localhost:9200/api/libregraph", "user", "token")
	_, err := client.ListDrives("")
	require.Error(t, err)
	assert.Equal(t, ErrInvalidUserID, err)
}

func TestLibreGraphClient_SearchDrives_InvalidParameters(t *testing.T) {
	t.Parallel()

	client := NewLibreGraphClient("http://localhost:9200/api/libregraph", "user", "token")

	// Test with empty userID
	_, err := client.SearchDrives("", "test")
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)

	// Test with empty name
	_, err = client.SearchDrives("user1", "")
	require.Error(t, err)
	assert.Equal(t, ErrInvalidParameters, err)
}

func TestTargetResolver_ResolveTarget(t *testing.T) {
	t.Parallel()

	// Create a mock client for testing
	mockClient := &mockGraphClient{
		drives: []Drive{
			{ID: "drive1", Name: "Test Drive", WebDAVURL: "http://localhost/webdav"},
		},
	}

	resolver := NewTargetResolver(mockClient)

	// Test resolution by ID
	drive, webDAVURL, err := resolver.ResolveTarget("drive1", "")
	require.NoError(t, err)
	assert.Equal(t, "drive1", drive.ID)
	assert.Equal(t, "http://localhost/webdav", webDAVURL)

	// Test resolution by name
	mockClientWithName := &mockGraphClient{
		drives: []Drive{
			{ID: "drive2", Name: "Named Drive", WebDAVURL: "http://localhost/webdav"},
		},
	}
	resolverWithName := NewTargetResolver(mockClientWithName)

	drive, webDAVURL, err = resolverWithName.ResolveTarget("", "Named Drive")
	require.NoError(t, err)
	assert.Equal(t, "drive2", drive.ID)
	assert.Equal(t, "http://localhost/webdav", webDAVURL)
}

func TestTargetResolver_AmbiguousName(t *testing.T) {
	t.Parallel()

	// Create a mock client with multiple drives with the same name
	mockClient := &mockGraphClient{
		drives: []Drive{
			{ID: "drive1", Name: "Ambiguous Drive", WebDAVURL: "http://localhost/webdav1"},
			{ID: "drive2", Name: "Ambiguous Drive", WebDAVURL: "http://localhost/webdav2"},
		},
	}

	resolver := NewTargetResolver(mockClient)

	// Test ambiguous name resolution
	_, _, err := resolver.ResolveTarget("", "Ambiguous Drive")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous drive name")
}

func TestTargetResolver_DriveNotFound(t *testing.T) {
	t.Parallel()

	// Create a mock client with no matching drives
	mockClient := &mockGraphClient{
		drives: []Drive{
			{ID: "drive1", Name: "Different Drive", WebDAVURL: "http://localhost/webdav"},
		},
	}

	resolver := NewTargetResolver(mockClient)

	// Test non-existent drive ID
	_, _, err := resolver.ResolveTarget("nonexistent", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "drive not found")

	// Test non-existent drive name
	_, _, err = resolver.ResolveTarget("", "Non Existent Drive")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTargetResolver_NeitherConfigured(t *testing.T) {
	t.Parallel()

	mockClient := &mockGraphClient{}
	resolver := NewTargetResolver(mockClient)

	// Test with neither drive ID nor drive name configured
	_, _, err := resolver.ResolveTarget("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either drive_id or drive must be configured")
}

func TestTargetResolver_ValidateTarget(t *testing.T) {
	t.Parallel()

	mockClient := &mockGraphClient{
		drives: []Drive{
			{ID: "drive1", Name: "Test Drive", WebDAVURL: "http://localhost/webdav"},
		},
	}

	resolver := NewTargetResolver(mockClient)

	// Test valid target
	err := resolver.ValidateTarget("drive1", "")
	require.NoError(t, err)

	// Test invalid target
	err = resolver.ValidateTarget("nonexistent", "")
	require.Error(t, err)
}

// mockGraphClient is a mock implementation of Client for testing
type mockGraphClient struct {
	drives []Drive
}

func (m *mockGraphClient) ResolveDrive(id string) (Drive, error) {
	for _, drive := range m.drives {
		if drive.ID == id {
			return drive, nil
		}
	}
	return Drive{}, ErrDriveNotFound
}

func (m *mockGraphClient) ListDrives(userID string) ([]Drive, error) {
	return m.drives, nil
}

func (m *mockGraphClient) ResolveSpace(id string) (Space, error) {
	return Space{}, ErrNotImplemented
}

func (m *mockGraphClient) ListSpaces(userID string) ([]Space, error) {
	return []Space{}, nil
}

func (m *mockGraphClient) SearchDrives(userID, name string) ([]Drive, error) {
	var matches []Drive
	for _, drive := range m.drives {
		if drive.Name == name {
			matches = append(matches, drive)
		}
	}
	return matches, nil
}

func (m *mockGraphClient) SearchSpaces(userID, name string) ([]Space, error) {
	return []Space{}, nil
}

// Test with HTTP server mock
func TestLibreGraphClient_WithMockServer(t *testing.T) {
	t.Parallel()

	// Create a mock LibreGraph server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request for debugging
		t.Logf("Request: %s %s", r.Method, r.URL.Path)

		// Mock /api/libregraph/me/drives endpoint
		if strings.HasSuffix(r.URL.Path, "/me/drives") && r.Method == http.MethodGet {
			// Check authentication
			username, password, ok := r.BasicAuth()
			if !ok || username != "testuser" || password != "testtoken" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Return mock drive data
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"value": [
					{
						"id": "drive1",
						"name": "Test Drive",
						"webUrl": "http://localhost:9200"
					}
				]
				}`))
			return
		}

		// Mock /api/libregraph/drives/{id} endpoint
		if strings.HasSuffix(r.URL.Path, "/drives/drive1") && r.Method == http.MethodGet {
			// Check authentication
			username, password, ok := r.BasicAuth()
			if !ok || username != "testuser" || password != "testtoken" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Return mock drive data
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"id": "drive1",
				"name": "Test Drive",
				"webUrl": "http://localhost:9200"
				}`))
			return
		}

		// Return 404 for unknown endpoints
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client pointing to our mock server
	// Note: server.URL gives us the base URL, and we need to append the libregraph path
	client := NewLibreGraphClient(server.URL+"/api/libregraph", "testuser", "testtoken")

	// Test ListDrives
	drives, err := client.ListDrives("testuser")
	require.NoError(t, err)
	require.Len(t, drives, 1)
	assert.Equal(t, "drive1", drives[0].ID)
	assert.Equal(t, "Test Drive", drives[0].Name)
	// WebDAV URL should be derived from webUrl
	assert.Equal(t, "http://localhost:9200/webdav", drives[0].WebDAVURL)

	// Test ResolveDrive
	drive, err := client.ResolveDrive("drive1")
	require.NoError(t, err)
	assert.Equal(t, "drive1", drive.ID)
	assert.Equal(t, "Test Drive", drive.Name)
	assert.Equal(t, "http://localhost:9200/webdav", drive.WebDAVURL)
}

func TestLibreGraphClient_Unauthorized(t *testing.T) {
	t.Parallel()

	// Create a mock server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewLibreGraphClient(server.URL, "testuser", "wrongtoken")

	// Test ListDrives with wrong credentials
	_, err := client.ListDrives("testuser")
	require.Error(t, err)
	assert.Equal(t, ErrUnauthorized, err)
}

func TestLibreGraphClient_Forbidden(t *testing.T) {
	t.Parallel()

	// Create a mock server that returns 403
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewLibreGraphClient(server.URL, "testuser", "testtoken")

	// Test ListDrives with forbidden access
	_, err := client.ListDrives("testuser")
	require.Error(t, err)
	assert.Equal(t, ErrForbidden, err)
}

func TestLibreGraphClient_NotFound(t *testing.T) {
	t.Parallel()

	// Create a mock server that returns 404 for specific drive
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/drives/nonexistent" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewLibreGraphClient(server.URL, "testuser", "testtoken")

	// Test ResolveDrive with non-existent drive
	_, err := client.ResolveDrive("nonexistent")
	require.Error(t, err)
	assert.Equal(t, ErrDriveNotFound, err)
}