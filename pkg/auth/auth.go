// Package auth maps configured FTP accounts to oCIS service credentials.
package auth

import (
	"errors"
	"fmt"

	"github.com/amamus/ocis-ftp-bridge/pkg/config"
)

var ErrInvalidCredentials = errors.New("invalid FTP credentials")

type AccountMapping struct {
	FTPUsername     string
	OCISUsername    string
	AppToken        string
	DriveID         string
	Drive           string
	Root            string
	CollisionPolicy string
	MaxUploadSize   uint64
}

func (m AccountMapping) String() string {
	return fmt.Sprintf("AccountMapping{FTPUsername:%q OCISUsername:%q AppToken:<redacted> DriveID:%q Drive:%q Root:%q CollisionPolicy:%q MaxUploadSize:%d}",
		m.FTPUsername, m.OCISUsername, m.DriveID, m.Drive, m.Root, m.CollisionPolicy, m.MaxUploadSize)
}

type Mapper struct {
	accounts map[string]config.AccountConfig
}

func NewAccountMapper(accounts []config.AccountConfig) *Mapper {
	m := &Mapper{accounts: make(map[string]config.AccountConfig, len(accounts))}
	for _, account := range accounts {
		m.accounts[account.Username] = account
	}
	return m
}

func (m *Mapper) Authenticate(username, password string) (AccountMapping, error) {
	account, ok := m.accounts[username]
	if !ok {
		return AccountMapping{}, ErrInvalidCredentials
	}
	valid, err := config.VerifyPassword(account.PasswordHash, password)
	if err != nil || !valid {
		return AccountMapping{}, ErrInvalidCredentials
	}
	return AccountMapping{
		FTPUsername:     account.Username,
		OCISUsername:    account.OCIS.Username,
		AppToken:        account.AppToken,
		DriveID:         account.Target.DriveID,
		Drive:           account.Target.Drive,
		Root:            account.Target.Root,
		CollisionPolicy: account.Upload.CollisionPolicy,
		MaxUploadSize:   uint64(account.Upload.MaxSize),
	}, nil
}
