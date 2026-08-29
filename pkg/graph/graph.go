// Package graph provides LibreGraph client for drive resolution in ocis-ftp-bridge.
//
// It defines interfaces for interacting with the oCIS LibreGraph API
// to resolve and validate target drives/spaces.
package graph

import "fmt"

// Client is the interface for LibreGraph API operations.
type Client interface {
	// ResolveDrive resolves a drive ID to drive information.
	ResolveDrive(id string) (Drive, error)
	
	// ListDrives lists all drives for a user.
	ListDrives(userID string) ([]Drive, error)
	
	// ResolveSpace resolves a space ID to space information.
	ResolveSpace(id string) (Space, error)
	
	// ListSpaces lists all spaces for a user.
	ListSpaces(userID string) ([]Space, error)
	
	// SearchDrives searches drives by name.
	SearchDrives(userID, name string) ([]Drive, error)
	
	// SearchSpaces searches spaces by name.
	SearchSpaces(userID, name string) ([]Space, error)
}

// Drive represents an oCIS drive.
type Drive struct {
	// ID is the unique identifier for the drive.
	ID string `json:"id"`
	
	// Name is the display name of the drive.
	Name string `json:"name"`
	
	// Description is the description of the drive.
	Description string `json:"description,omitempty"`
	
	// Owner is the owner of the drive.
	Owner Owner `json:"owner"`
	
	// Permissions are the user permissions on this drive.
	Permissions []Permission `json:"permissions"`
	
	// Root is the root of the drive.
	Root Root `json:"root"`
}

// Space represents an oCIS space.
type Space struct {
	// ID is the unique identifier for the space.
	ID string `json:"id"`
	
	// Name is the display name of the space.
	Name string `json:"name"`
	
	// Description is the description of the space.
	Description string `json:"description,omitempty"`
	
	// Owner is the owner of the space.
	Owner Owner `json:"owner"`
	
	// Permissions are the user permissions on this space.
	Permissions []Permission `json:"permissions"`
	
	// Root is the root of the space.
	Root Root `json:"root"`
}

// Owner represents an owner of a drive or space.
type Owner struct {
	// ID is the unique identifier of the owner.
	ID string `json:"id"`
	
	// DisplayName is the display name of the owner.
	DisplayName string `json:"display_name"`
}

// Root represents the root of a drive or space.
type Root struct {
	// ID is the unique identifier of the root.
	ID string `json:"id"`
}

// Permission represents a permission on a drive or space.
type Permission struct {
	// ID is the unique identifier of the permission.
	ID string `json:"id"`
	
	// Roles are the roles granted by this permission.
	Roles []Role `json:"roles"`
}

// Role represents a role in oCIS.
type Role string

const (
	// RoleNone indicates no role.
	RoleNone Role = ""
	
	// RoleOwner indicates the owner role.
	RoleOwner Role = "owner"
	
	// RoleContributor indicates the contributor role.
	RoleContributor Role = "contributor"
	
	// RoleViewer indicates the viewer role.
	RoleViewer Role = "viewer"
)

// NewClient creates a new LibreGraph client.
func NewClient(baseURL, token string) Client {
	return &defaultClient{baseURL: baseURL, token: token}
}

// defaultClient is the default implementation of Client.
type defaultClient struct {
	baseURL string
	token   string
}

// ResolveDrive implements Client.ResolveDrive.
func (c *defaultClient) ResolveDrive(id string) (Drive, error) {
	if id == "" {
		return Drive{}, ErrInvalidDriveID
	}
	
	// Placeholder implementation - would call LibreGraph API in production
	return Drive{
		ID:          id,
		Name:        "Drive " + id,
		Description: "Placeholder drive",
		Owner: Owner{
			ID:          "owner-id",
			DisplayName: "Owner",
		},
		Permissions: []Permission{},
		Root: Root{
			ID: "root-id",
		},
	}, nil
}

// ListDrives implements Client.ListDrives.
func (c *defaultClient) ListDrives(userID string) ([]Drive, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	
	// Placeholder implementation
	return []Drive{}, nil
}

// ResolveSpace implements Client.ResolveSpace.
func (c *defaultClient) ResolveSpace(id string) (Space, error) {
	if id == "" {
		return Space{}, ErrInvalidSpaceID
	}
	
	// Placeholder implementation
	return Space{
		ID:          id,
		Name:        "Space " + id,
		Description: "Placeholder space",
		Owner: Owner{
			ID:          "owner-id",
			DisplayName: "Owner",
		},
		Permissions: []Permission{},
		Root: Root{
			ID: "root-id",
		},
	}, nil
}

// ListSpaces implements Client.ListSpaces.
func (c *defaultClient) ListSpaces(userID string) ([]Space, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	
	// Placeholder implementation
	return []Space{}, nil
}

// SearchDrives implements Client.SearchDrives.
func (c *defaultClient) SearchDrives(userID, name string) ([]Drive, error) {
	if userID == "" || name == "" {
		return nil, ErrInvalidParameters
	}
	
	// Placeholder implementation
	return []Drive{}, nil
}

// SearchSpaces implements Client.SearchSpaces.
func (c *defaultClient) SearchSpaces(userID, name string) ([]Space, error) {
	if userID == "" || name == "" {
		return nil, ErrInvalidParameters
	}
	
	// Placeholder implementation
	return []Space{}, nil
}

// Errors
type GraphError struct {
	msg string
}

func (e *GraphError) Error() string {
	return fmt.Sprintf("graph error: %s", e.msg)
}

var (
	ErrInvalidDriveID      = &GraphError{msg: "invalid drive ID"}
	ErrInvalidSpaceID      = &GraphError{msg: "invalid space ID"}
	ErrInvalidUserID       = &GraphError{msg: "invalid user ID"}
	ErrInvalidParameters   = &GraphError{msg: "invalid parameters"}
	ErrDriveNotFound       = &GraphError{msg: "drive not found"}
	ErrSpaceNotFound       = &GraphError{msg: "space not found"}
	ErrUnauthorized         = &GraphError{msg: "unauthorized"}
	ErrForbidden            = &GraphError{msg: "forbidden"}
	ErrGraphAPIError        = &GraphError{msg: "LibreGraph API error"}
)