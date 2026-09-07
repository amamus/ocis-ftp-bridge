# Contributing to ocis-ftp-bridge

Thank you for your interest in contributing to the ocis-ftp-bridge project! This document provides guidelines for contributing to the project.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating in this community, you agree to abide by its terms.

In summary, we expect all contributors to:

- Be welcoming and inclusive
- Respect different viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the project and its users

Violations of the code of conduct may be reported via GitHub issues or discussions
and will be investigated promptly and fairly.

## Developer Certificate of Origin (DCO)

This project uses the Developer Certificate of Origin (DCO) as its contributor
license agreement. The DCO is a lightweight way for contributors to certify that
they have the right to submit the code they are contributing to the project.

### How to sign off

To certify that your contribution complies with the DCO, add a `Signed-off-by:`
line to your commit message:

```
This is my commit message

Signed-off-by: Your Name <your.email@example.com>
```

You can automatically add this line using `git commit -s` or `git commit -S`.

### Why DCO?

The DCO is a well-established standard in the Open Source community. It provides
legal protection for both contributors and maintainers while being much simpler
than traditional CLAs. The DCO ensures that:

1. You have the right to submit the contribution
2. The contribution is properly licensed
3. You accept responsibility for your contributions

### More information

- [DCO Website](https://developercertificate.org/)
- [DCO FAQ](https://github.com/probot/dco/blob/master/README.md)
- [Linux Foundation DCO](https://www.linuxfoundation.org/legal/dco/)

## Getting Started

### Prerequisites

- Go 1.27+ (recommended: latest stable version)
- Docker (for container builds and testing)
- Git
- Basic understanding of FTP protocol and oCIS/WebDAV

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/amamus/ocis-ftp-bridge.git
cd ocis-ftp-bridge

# Install dependencies
go mod download

# Build the project
go build ./...

# Run tests
go test ./...
```

### Project Structure

```
.
├── cmd/                  # Command-line entry points
│   └── ocis-ftp-bridge/  # Main application
│       └── main.go      # Application entry point
├── pkg/                  # Library packages
│   ├── auth/            # Authentication handling
│   ├── config/          # Configuration management
│   ├── ftp/             # FTP server implementation
│   ├── graph/           # LibreGraph API client
│   ├── http/            # HTTP operations server
│   ├── observability/   # Logging and metrics
│   ├── server/          # Service lifecycle
│   ├── spool/           # Upload spool management
│   ├── transfer/        # File transfer pipeline
│   └── webdav/          # WebDAV client
├── .github/             # GitHub specific files
│   └── workflows/       # GitHub Actions workflows
├── docs/                # Documentation
├── kubernetes/          # Kubernetes deployment files
├── Dockerfile           # Container build file
├── docker-compose.yaml  # Docker Compose example
├── go.mod              # Go module definition
├── go.sum              # Go dependency checksums
├── LICENSE             # License file
├── README.md           # Project readme
└── config.yaml.example # Example configuration
```

## Ways to Contribute

### Reporting Bugs

1. **Search existing issues**: Check if the bug has already been reported
2. **Create a minimal reproduction**: Provide steps to reproduce the bug
3. **Include relevant information**:
   - Version of ocis-ftp-bridge
   - Go version
   - Operating system
   - Configuration used
   - Log output (with sensitive information redacted)
   - Expected vs actual behavior

### Suggesting Enhancements

1. **Check existing issues**: See if the feature has already been requested
2. **Provide use case**: Explain why this feature would be valuable
3. **Describe the solution**: Include design considerations if applicable

### Contributing Code

1. **Fork the repository** on GitHub
2. **Create a feature branch** from the latest main branch
3. **Make your changes** following the coding guidelines
4. **Write tests** for new functionality
5. **Update documentation** as needed
6. **Submit a pull request** with a clear description

### Contributing Documentation

Documentation contributions are welcome! Please:

- Follow existing documentation style
- Keep documentation up to date with code changes
- Include examples and practical guidance

## Development Guidelines

### Coding Standards

- **Language**: Go (Golang)
- **Formatting**: Use `gofmt` - all code must be properly formatted
- **Imports**: Grouped and ordered (use `goimports`)
- **Naming**: Use meaningful, descriptive names
- **Comments**: Add comments for complex logic, exported types, and public APIs
- **Error Handling**: Always handle errors appropriately

### Code Quality

```bash
# Format code
go fmt ./...

# Check for issues
go vet ./...

# Run static analysis
go build ./...

# Run tests with race detector
go test -race ./...

# Check for lint issues
staticcheck ./...
```

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Limit first line to 50 characters
- Separate subject from body with a blank line
- Wrap body at 72 characters
- Include relevant issue references (e.g., "Fixes #123")

**Good Example:**
```
Add path traversal protection for FTP uploads

Implement strict path validation to prevent directory traversal attacks.
- Normalize all paths using filepath.Clean()
- Reject absolute paths
- Block parent directory references
- Add comprehensive test cases

Fixes #42
```

### Testing

**All code must have corresponding tests.**

- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test component interactions
- **Table Tests**: Use table-driven tests for similar test cases
- **Race Tests**: Use `-race` flag for concurrent code

**Test File Naming:**
- Unit tests: `*_test.go` in same package
- Integration tests: `*_integration_test.go`
- Mocks: `*_mock.go` or `testfixtures/`

**Test Examples:**
```go
// Simple test
func TestPathValidation(t *testing.T) {
    tests := []struct {
        name     string
        path     string
        wantErr  bool
    }{
        {"valid path", "uploads/file.txt", false},
        {"traversal", "../../etc/passwd", true},
        {"absolute", "/etc/passwd", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validatePath(tt.path)
            if (err != nil) != tt.wantErr {
                t.Errorf("validatePath() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Documentation

- **Code Comments**: Use Go doc comments for exported types and functions
- **Package Documentation**: Include package-level documentation
- **Examples**: Include usage examples where helpful

**Example Documentation:**
```go
// Package ftp implements the FTP server for ocis-ftp-bridge.
// It provides FTP/FTPS protocol support using ftpserverlib.
package ftp

// Server represents an FTP server instance.
type Server interface {
    // ListenAndServe starts the FTP server on the configured address.
    // It blocks until the server is stopped.
    ListenAndServe() error
    
    // Stop shuts down the FTP server.
    Stop() error
}
```

## Pull Request Process

### Before Submitting

1. **Rebase your branch** on the latest main branch
2. **Run all tests**: `go test ./...`
3. **Run race detector**: `go test -race ./...`
4. **Check formatting**: `go fmt ./...`
5. **Verify no lint issues**: `staticcheck ./...`
6. **Update documentation** if needed

### Pull Request Requirements

1. **Clear Title**: Describe what the PR does
2. **Detailed Description**: Explain the changes and their purpose
3. **Linked Issues**: Reference any related issues
4. **Tests Included**: All new functionality must have tests
5. **Documentation Updated**: Update docs as needed
6. **Changelog Entry**: Include entry in CHANGELOG.md if applicable

### Review Process

1. **Initial Review**: Maintainers review for completeness and quality
2. **CI Checks**: All tests must pass in CI
3. **Security Review**: Security-sensitive changes get additional review
4. **Approvals**: Requires at least one maintainer approval
5. **Merge**: Once approved and CI passes, PR is merged

## Release Process

### Versioning

This project uses **Semantic Versioning 2.0.0**:

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible new functionality
- **PATCH**: Backwards-compatible bug fixes

### Release Checklist

- [ ] All planned features for the release are complete
- [ ] All critical bugs are fixed
- [ ] All tests pass
- [ ] Documentation is up to date
- [ ] CHANGELOG.md updated with all changes
- [ ] Version updated in all relevant files
- [ ] Container images built and tested
- [ ] GitHub release created with notes
- [ ] Announcement sent (if applicable)

### Creating a Release

1. **Update version** in relevant files
2. **Update CHANGELOG.md**
3. **Create Git tag**: `git tag v1.0.0`
4. **Push tag**: `git push origin v1.0.0`
5. **Create GitHub release** with release notes
6. **Build and publish artifacts**
7. **Update dependencies** if needed

## Local Development

### Running the Bridge Locally

```bash
# Build the binary
go build -o ocis-ftp-bridge ./cmd/ocis-ftp-bridge

# Create a configuration file
cp config.yaml.example config.yaml
# Edit config.yaml with your settings

# Run the bridge
./ocis-ftp-bridge -config config.yaml
```

### Testing with Local oCIS

1. Start oCIS locally or use a test instance
2. Configure bridge to connect to oCIS
3. Test FTP uploads and verify files appear in oCIS

### Debugging

```bash
# Enable debug logging
./ocis-ftp-bridge -config config.yaml -log-level=debug

# Check version
./ocis-ftp-bridge -version

# Run with race detector
go run -race ./cmd/ocis-ftp-bridge
```

## Security Considerations

**DO NOT** commit:

- Secrets (passwords, tokens, keys)
- Sensitive configuration data
- Credentials or authentication information
- Personal data

**Always:**

- Use environment variables for secrets in tests
- Redact sensitive information in logs and error messages
- Follow the security guidelines in SECURITY.md

## Maintainers

Current maintainers:

- [@amamus](https://github.com/amamus) - David Walter

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Questions?

- **General Questions**: Open a GitHub discussion
- **Bug Reports**: Open a GitHub issue
- **Security Issues**: Follow the process in SECURITY.md
- **Contributions**: Open a pull request

---

*Thank you for contributing to ocis-ftp-bridge!*

*Last updated: September 2026*