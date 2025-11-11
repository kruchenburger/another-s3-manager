# Publishing Guide

This guide explains how to publish new releases of Another S3 Manager.

## Prerequisites

- GitHub repository with Actions enabled
- Write access to the repository
- Docker installed (for local testing)

## Release Process

### 1. Update Version Information

Before creating a release, update the version in:
- `CHANGELOG.md` - Add new version section with changes
- Consider updating version in code if you have version tracking

### 2. Create a Git Tag

Create a new tag following semantic versioning (e.g., `v0.1.0`):

```bash
# Make sure you're on the main branch and up to date
git checkout main
git pull origin main

# Create and push the tag
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0
```

### 3. Automatic Release

When you push a tag starting with `v`, the GitHub Actions workflow will:
1. Build Docker images for multiple platforms (amd64, arm64)
2. Push images to GitHub Container Registry (ghcr.io)
3. Create a GitHub Release with changelog

The workflow is defined in `.github/workflows/docker-build.yml` and `.github/workflows/release.yml`.

### 4. Verify Release

After the workflow completes:
1. Check GitHub Actions: https://github.com/kruchenburger/another-s3-manager/actions
2. Verify Docker image: https://github.com/kruchenburger/another-s3-manager/pkgs/container/another-s3-manager
3. Check Release: https://github.com/kruchenburger/another-s3-manager/releases

### 5. Test the Release

Test the published Docker image:

```bash
docker pull ghcr.io/kruchenburger/another-s3-manager:v0.1.0
docker run -p 8080:8080 \
  -e JWT_SECRET_KEY=test-secret \
  ghcr.io/kruchenburger/another-s3-manager:v0.1.0
```

## Docker Image Tags

The workflow automatically creates the following tags:
- `v0.1.0` - Specific version
- `v0.1` - Major.minor version
- `v0` - Major version
- `latest` - Latest release (only for default branch)
- `main` - Latest commit from main branch
- `main-<sha>` - Specific commit from main branch

## Manual Release (Alternative)

If you need to create a release manually:

1. Go to https://github.com/kruchenburger/another-s3-manager/releases
2. Click "Draft a new release"
3. Choose a tag (or create a new one)
4. Fill in release title and description (copy from CHANGELOG.md)
5. Publish the release

## Updating CHANGELOG

Follow the [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [0.1.0] - 2025-01-15

### Added
- New feature description

### Changed
- Change description

### Fixed
- Bug fix description
```

## Best Practices

- Always test locally before releasing
- Update CHANGELOG.md before creating a tag
- Use semantic versioning (MAJOR.MINOR.PATCH)
- Write clear release notes
- Test the Docker image after publishing

