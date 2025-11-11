# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-11-11

### Added
- Initial public release
- Multi-account AWS support via role assumption, profiles, and direct credentials
- User authentication with JWT tokens
- Admin panel for user management
- File browsing, upload, download, and deletion
- Dark/light theme support
- Virtual scrolling for large file lists
- Account lockout after failed login attempts
- Granular bucket access control
- Web-based configuration interface
- Support for custom S3-compatible endpoints (e.g., MinIO) via `endpoint_url`, `use_ssl`, `verify_ssl`, and path-style addressing in role configuration

### Security
- Password hashing with bcrypt
- JWT token-based authentication
- CSRF protection
- Login attempt rate limiting

[Unreleased]: https://github.com/kruchenburger/another-s3-manager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kruchenburger/another-s3-manager/releases/tag/v0.1.0

