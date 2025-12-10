# Releasing k8stun

This document describes how to create a new release of k8stun.

## Making a Release

### 1. Use Conventional Commits

Ensure your commits follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat: add UDP support
fix: resolve DNS timeout issue
docs: update installation guide
perf: optimize connection pooling
refactor: restructure networking module
```

### 2. Trigger the Release Workflow

1. Go to the [Actions tab](https://github.com/tsroka/k8stun/actions)
2. Select the "Release" workflow from the left sidebar
3. Click "Run workflow"
4. Enter the version number (e.g., `1.0.0` or `1.0.0-beta.1`)
5. Click "Run workflow"

### What Happens Automatically

The release workflow will:

1. **Validate** the version format
2. **Generate** a changelog from conventional commits using git-cliff
3. **Build** binaries for:
   - macOS ARM64 (Apple Silicon)
   - Linux x64 (amd64)
   - Linux ARM64
4. **Package** Linux builds as `.deb` files
5. **Create** SHA256 checksums
6. **Update** `CHANGELOG.md` in the repository
7. **Update** the version in `Cargo.toml`
8. **Commit** and push the changes
9. **Create** a git tag (e.g., `v1.0.0`)
10. **Publish** a GitHub release with all artifacts
11. **Trigger** the Homebrew tap update

## Release Artifacts

Each release includes:

| Artifact | Description |
|----------|-------------|
| `k8stun-X.Y.Z-aarch64-apple-darwin.tar.gz` | macOS ARM64 binary |
| `k8stun-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | Linux x64 binary |
| `k8stun-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 binary |
| `k8stun_X.Y.Z_amd64.deb` | Debian package for x64 |
| `k8stun_X.Y.Z_arm64.deb` | Debian package for ARM64 |
| `SHA256SUMS.txt` | Checksums for all artifacts |

## Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (1.0.0 → 1.1.0): New features, backward compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes, backward compatible

Pre-release versions are also supported: `1.0.0-alpha.1`, `1.0.0-beta.2`, `1.0.0-rc.1`

## Troubleshooting

### Build Fails for Cross-Compilation

If the Linux ARM64 build fails, it may be due to missing cross-compilation dependencies. The workflow installs `gcc-aarch64-linux-gnu`, but some crates may require additional libraries.

### Homebrew Tap Not Updated

1. Verify `HOMEBREW_TAP_TOKEN` secret is correctly set
2. Check the homebrew-k8stun repository's Actions tab for errors
3. Ensure the token has `repo` scope

### Changelog Not Generating

Ensure your commits follow conventional commit format. Non-conventional commits are filtered out by git-cliff.


