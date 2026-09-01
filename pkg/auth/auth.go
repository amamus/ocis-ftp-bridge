// Package auth provides authentication and account mapping for ocis-ftp-bridge.
//
// It bridges FTP credentials with oCIS user accounts and permissions.
package auth

import "github.com/amamus/ocis-ftp-bridge/pkg/ftp"

// AccountMapper maps FTP credentials to oCIS accounts.
type AccountMapper interface {
	// MapFTPToOCIS maps FTP credentials to an oCIS account.
	MapFTPToOCIS(user, password string) (OCISAccount, error)
	
	// ValidatePermissions validates that the user has access to the target space.
	ValidatePermissions(account OCISAccount, spaceID string) error
}

// OCISAccount represents an oCIS user account.
type OCISAccount struct {
	// ID is the unique identifier for the account.
	ID string
	
	// Username is the account username.
	Username string
	
	// Email is the account email address.
	Email string
	
	// Token is the OAuth2 access token for the account.
	Token string
	
	// Permissions are the account permissions.
	Permissions []string
}

// NewAccountMapper creates a new AccountMapper instance.
func NewAccountMapper(ftpClient ftp.Authenticator) AccountMapper {
	return &defaultAccountMapper{ftpClient: ftpClient}
}

// defaultAccountMapper is the default implementation of AccountMapper.
type defaultAccountMapper struct {
	ftpClient ftp.Authenticator
}

// MapFTPToOCIS implements AccountMapper.MapFTPToOCIS.
func (m *defaultAccountMapper) MapFTPToOCIS(user, password string) (OCISAccount, error) {
	// Authenticate with FTP backend
	if ok, err := m.ftpClient.Authenticate(user, password); err != nil {
		return OCISAccount{}, err
	} else if !ok {
		return OCISAccount{}, ErrInvalidCredentials
	}
	
	// Get user info
	userInfo, err := m.ftpClient.GetUserInfo(user)
	if err != nil {
		return OCISAccount{}, err
	}
	
	// Map to OCIS account (placeholder logic)
	return OCISAccount{
		ID:        userInfo.UserID,
		Username:  user,
		Email:     user + "@example.com",
		Token:     "placeholder-token",
		Permissions: userInfo.Permissions,
	}, nil
}

// ValidatePermissions implements AccountMapper.ValidatePermissions.
func (m *defaultAccountMapper) ValidatePermissions(account OCISAccount, spaceID string) error {
	// Validate that user has access to the space
	for _, perm := range account.Permissions {
		if perm == "write" || perm == "admin" {
			return nil
		}
	}
	
	return ErrInsufficientPermissions
}

// Errors
type AuthError struct {
	msg string
}

func (e *AuthError) Error() string {
	return e.msg
}

var (
	ErrInvalidCredentials       = &AuthError{msg: "invalid FTP credentials"}
	ErrUserNotFound            = &AuthError{msg: "user not found"}
	ErrInsufficientPermissions = &AuthError{msg: "insufficient permissions"}
	ErrMappingFailed          = &AuthError{msg: "failed to map FTP credentials to oCIS account"}
)