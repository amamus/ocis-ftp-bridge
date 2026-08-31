// Package ftp defines the bridge boundary around the selected FTP protocol library.
//
// FTP command parsing, control/data connection state, passive networking and FTPS
// are provided by github.com/fclairamb/ftpserverlib. This package intentionally
// does not mirror FTP commands with application-owned HandleUSER/HandleSTOR-style
// interfaces. The bridge owns account mapping, virtual-root isolation, spool
// semantics and downstream oCIS publication.
package ftp

import (
	"errors"

	ftpserver "github.com/fclairamb/ftpserverlib"
)

const (
	// ProtocolImplementation documents the selected FTP/FTPS protocol library.
	ProtocolImplementation = "github.com/fclairamb/ftpserverlib"

	// ProtocolVersion is pinned in go.mod and intentionally recorded here so
	// diagnostics can report the protocol implementation used by a build.
	ProtocolVersion = "v0.32.3"
)

// Server is the small lifecycle surface the application needs from ftpserverlib.
type Server interface {
	Listen() error
	ListenAndServe() error
	Stop() error
	Addr() string
}

// NewServer constructs the selected protocol server around a bridge MainDriver.
func NewServer(driver ftpserver.MainDriver) Server {
	return ftpserver.NewFtpServer(driver)
}

// Re-export only the extension points the bridge is expected to implement.
// These aliases keep our architecture explicit without recreating FTP protocol APIs.
type (
	MainDriver          = ftpserver.MainDriver
	ClientDriver        = ftpserver.ClientDriver
	ClientContext       = ftpserver.ClientContext
	FileTransfer        = ftpserver.FileTransfer
	FileTransferError   = ftpserver.FileTransferError
	Settings            = ftpserver.Settings
	PortRange           = ftpserver.PortRange
	TLSRequirement      = ftpserver.TLSRequirement
)

// Authenticator is a bridge-side credential abstraction. It is deliberately
// separate from FTP command handling and will be backed by configured accounts.
type Authenticator interface {
	Authenticate(user, password string) (bool, error)
	GetUserInfo(user string) (UserInfo, error)
}

// UserInfo is the minimal account information needed by the bridge.
type UserInfo struct {
	UserID      string
	OCISSpaceID string
	Permissions []string
}

// NewAuthenticator returns an explicit unimplemented authenticator until the
// account-mapping issue provides the real configured-account implementation.
// It must never silently accept credentials.
func NewAuthenticator(_ map[string]string) Authenticator {
	return unsupportedAuthenticator{}
}

type unsupportedAuthenticator struct{}

func (unsupportedAuthenticator) Authenticate(string, string) (bool, error) {
	return false, ErrNotImplemented
}

func (unsupportedAuthenticator) GetUserInfo(string) (UserInfo, error) {
	return UserInfo{}, ErrNotImplemented
}

var (
	ErrInvalidCredentials = errors.New("invalid FTP credentials")
	ErrUserNotFound        = errors.New("user not found")
	ErrUnauthorized        = errors.New("access denied")
	ErrNotImplemented      = errors.New("FTP account mapping not implemented")
)
