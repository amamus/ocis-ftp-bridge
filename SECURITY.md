# Security Policy

## Supported Versions

Security updates and vulnerability fixes are provided for the following versions:

| Version | Supported          | EOL Date |
|---------|------------------|-----------|
| v1.x    | :white_check_mark: | TBD      |
| v0.x    | :x:               | N/A      |

**Note**: Only the latest major version (v1.x) receives security updates.

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities through public GitHub issues, discussions, or email lists.

Instead, please report security vulnerabilities privately via email:

- **Email**: security@amamus.net
- **Subject**: Security Vulnerability Report - ocis-ftp-bridge
- **Encryption**: Optional but preferred - use PGP key if available

### What to Include

Please include the following information in your vulnerability report:

1. **Vulnerability Details**
   - Type of vulnerability (e.g., path traversal, authentication bypass, DoS)
   - Affected component(s)
   - Affected version(s)

2. **Steps to Reproduce**
   - Detailed steps to reproduce the vulnerability
   - Proof of concept code or exploit (if available)
   - Configuration used for testing

3. **Impact**
   - Security impact (CVSS score if known)
   - Data exposure risk
   - System compromise potential

4. **Mitigation**
   - Suggested fixes or workarounds
   - Immediate mitigation steps

5. **Contact Information**
   - Your name/organization (optional)
   - Preferred contact method

### What to Expect

1. **Acknowledgment**: You will receive an acknowledgment within 24 hours
2. **Triage**: Initial assessment within 48 hours
3. **Investigation**: Detailed investigation and root cause analysis
4. **Fix Development**: Security patch development and testing
5. **Disclosure**: Coordinated vulnerability disclosure
6. **Notification**: Users notified of security updates

## Vulnerability Disclosure

We follow a **coordinated vulnerability disclosure** process:

### Timeline

1. **Day 0**: Vulnerability reported
2. **Day 1**: Initial acknowledgment
3. **Day 1-7**: Triage and investigation
4. **Day 7-14**: Fix development and testing
5. **Day 14-21**: Internal review and QA
6. **Day 21-30**: Public disclosure and patch release

**Total Time**: Maximum 30 days from report to public disclosure

### Disclosure Steps

1. **Private Notification**: Reporter notified of patch availability
2. **Public Advisory**: Security advisory published
3. **Patch Release**: Fixed version released
4. **CVE Assignment**: CVE assigned if applicable
5. **Public Acknowledgment**: Reporter credited (if desired)

### CVE Assignment

We work with [CVE.org](https://cve.org) and [GitHub Advisory Database](https://github.com/advisories) for CVE assignment.

- CVEs assigned for high/medium severity vulnerabilities
- Reporter credited in CVE records (if desired)
- CVE IDs published in release notes

## Security Update Process

### Patch Classification

| Severity | Response Time | Patch Type | Notification |
|----------|---------------|-----------|-------------|
| Critical | 24-48 hours | Hotfix | Email, GitHub, Announcements |
| High | 7 days | Patch release | GitHub, Announcements |
| Medium | 14 days | Minor release | Release notes |
| Low | 30 days | Major release | Release notes |

### Update Distribution

Security updates are distributed via:

1. **GitHub Releases**: Official releases with security advisories
2. **Container Images**: Updated Docker images with security patches
3. **Package Managers**: Updates to package repositories (if applicable)
4. **Mailing List**: Security announcements to subscribers

### Verification

Always verify security updates:

```bash
# Check version
docker run ocis-ftp-bridge:latest --version

# Verify checksums (if provided)
sha256sum ocis-ftp-bridge-v1.0.1-linux-amd64.tar.gz

# Check for known vulnerabilities
govulncheck ./...
```

## Security Best Practices

### For Users

1. **Stay Updated**: Always use the latest version
2. **Monitor Announcements**: Watch for security advisories
3. **Network Isolation**: Never expose plain FTP to untrusted networks
4. **TLS Configuration**: Always use FTPS in production
5. **Regular Audits**: Review logs and monitor for suspicious activity
6. **Backup Configuration**: Regularly backup configuration files

### For Operators

1. **Network Security**: Implement firewall rules and network segmentation
2. **Access Controls**: Restrict bridge access to authorized printers only
3. **Monitoring**: Set up alerts for failed login attempts and errors
4. **Resource Limits**: Configure appropriate limits for your environment
5. **Certificate Management**: Monitor certificate validity and rotate regularly
6. **Incident Response**: Have a plan for security incidents

### For Developers

1. **Security Review**: All changes undergo security review
2. **Dependency Scanning**: Regular vulnerability scanning of dependencies
3. **Static Analysis**: Use static analysis tools for code review
4. **Fuzzing**: Test with malformed inputs and edge cases
5. **Secure Defaults**: Always choose secure defaults for configuration
6. **Error Handling**: Never leak sensitive information in errors or logs

## Security Advisories

All security advisories are published in the [GitHub Security Advisories](https://github.com/amamus/ocis-ftp-bridge/security/advisories) section.

### Advisory Format

Each advisory includes:

- **Summary**: Brief description of the vulnerability
- **Severity**: Critical, High, Medium, or Low
- **CVSS Score**: If available
- **CVE ID**: If assigned
- **Affected Versions**: Range of affected versions
- **Fixed Versions**: Versions containing the fix
- **Impact**: Description of the vulnerability impact
- **Mitigation**: Workarounds or immediate actions
- **Credit**: Reporter acknowledgment (if desired)
- **Timeline**: Disclosure timeline
- **References**: Related links and resources

## FAQ

### Q: How do I report a security vulnerability?
A: Email security@amamus.net with details. Do not use public channels.

### Q: Will I be credited for reporting a vulnerability?
A: Yes, if you desire credit. We follow responsible disclosure practices.

### Q: How quickly will my vulnerability be fixed?
A: Response time depends on severity. Critical: 24-48h, High: 7d, Medium: 14d, Low: 30d.

### Q: Are there bug bounties?
A: Currently no formal bug bounty program. We appreciate all security reports.

### Q: Can I test for vulnerabilities on my own deployment?
A: Yes, but please do not test on production systems without authorization.

### Q: What if I accidentally discover a vulnerability while testing?
A: Report it immediately following the vulnerability reporting process above.

### Q: How do I verify I'm running a secure version?
A: Check the [Security Advisories](https://github.com/amamus/ocis-ftp-bridge/security/advisories) and compare with your version.

### Q: What should I do if I find a vulnerability in production?
A: Immediately isolate affected systems, then report the vulnerability following the process above.

## Security Contacts

- **Primary**: security@amamus.net
- **Secondary**: d@amamus.net (for urgent issues)
- **GPG Key**: [To be added]
- **GitHub**: @amamus (for non-security issues)

## Acknowledgments

We would like to acknowledge the following security researchers for their contributions:

*(None yet - be the first!)*

---

*Last updated: September 2026*
*Document version: v1.0*