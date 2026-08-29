// Package ftp provides the FTP server implementation for ocis-ftp-bridge.
//
// It defines interfaces and types for the FTP layer which can be
// implemented and tested independently of the actual FTP library.
package ftp

// Server is the interface that wraps the basic FTP server methods.
type Server interface {
	// Start starts the FTP server.
	Start() error
	
	// Stop stops the FTP server.
	Stop() error
	
	// ListenAndServe starts the FTP server and blocks until it's stopped.
	ListenAndServe() error
	
	// SetHandler sets the handler for FTP commands.
	SetHandler(Handler) error
}

// Handler is the interface that wraps the FTP command handling methods.
type Handler interface {
	// HandleSTOR handles the STOR (store) command to upload a file.
	HandleSTOR(user string, fileName string, data []byte) error
	
	// HandleUSER handles the USER command for authentication.
	HandleUSER(user string) error
	
	// HandlePASS handles the PASS command for authentication.
	HandlePASS(password string) error
	
	// HandleQUIT handles the QUIT command to end the session.
	HandleQUIT() error
	
	// HandlePASV handles the PASV command for passive mode.
	HandlePASV() (string, int, error)
	
	// HandlePORT handles the PORT command for active mode.
	HandlePORT(ip string, port int) error
	
	// HandleLIST handles the LIST command to list directory contents.
	HandleLIST(path string) ([]byte, error)
	
	// HandleCWD handles the CWD command to change working directory.
	HandleCWD(path string) error
	
	// HandlePWD handles the PWD command to get current directory.
	HandlePWD() (string, error)
	
	// HandleDELE handles the DELE command to delete a file.
	HandleDELE(path string) error
	
	// HandleRMD handles the RMD command to remove a directory.
	HandleRMD(path string) error
	
	// HandleMKD handles the MKD command to create a directory.
	HandleMKD(path string) error
	
	// HandleREST handles the REST command to restart a transfer.
	HandleREST(offset int64) error
}

// Authenticator is the interface for user authentication.
type Authenticator interface {
	// Authenticate validates FTP credentials.
	Authenticate(user, password string) (bool, error)
	
	// GetUserInfo returns information about an authenticated user.
	GetUserInfo(user string) (UserInfo, error)
}

// UserInfo contains information about an authenticated user.
type UserInfo struct {
	// UserID is the unique identifier for the user.
	UserID string
	
	// OCISSpaceID is the oCIS space ID the user has access to.
	OCISSpaceID string
	
	// Permissions are the user's permissions.
	Permissions []string
}

// NewAuthenticator creates a new Authenticator instance.
func NewAuthenticator(authConfig map[string]string) Authenticator {
	// In a real implementation, this would connect to the auth backend
	return &DefaultAuthenticator{config: authConfig}
}

// DefaultAuthenticator is the default implementation of Authenticator.
type DefaultAuthenticator struct {
	config map[string]string
}

// Authenticate implements Authenticator.Authenticate.
func (a *DefaultAuthenticator) Authenticate(user, password string) (bool, error) {
	// Placeholder implementation
	if user == "" || password == "" {
		return false, ErrInvalidCredentials
	}
	return true, nil
}

// GetUserInfo implements Authenticator.GetUserInfo.
func (a *DefaultAuthenticator) GetUserInfo(user string) (UserInfo, error) {
	// Placeholder implementation
	if user == "" {
		return UserInfo{}, ErrUserNotFound
	}
	return UserInfo{
		UserID:       user,
		OCISSpaceID:  "placeholder-space-id",
		Permissions:  []string{"read", "write"},
	}, nil
}

// Errors
type FTPError struct {
	msg string
}

func (e *FTPError) Error() string {
	return e.msg
}

var (
	ErrInvalidCredentials = &FTPError{msg: "invalid FTP credentials"}
	ErrUserNotFound       = &FTPError{msg: "user not found"}
	ErrUnauthorized       = &FTPError{msg: "access denied"}
	ErrNotImplemented      = &FTPError{msg: "command not implemented"}
	ErrSessionNotStarted  = &FTPError{msg: "FTP session not started"}
)