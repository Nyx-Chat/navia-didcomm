# Contributing to navia-didcomm

## Commit Message Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for automatic versioning and release notes generation.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: A new feature (triggers MINOR version bump)
- **fix**: A bug fix (triggers PATCH version bump)
- **docs**: Documentation only changes
- **style**: Changes that don't affect code meaning (white-space, formatting, etc)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Performance improvement (triggers PATCH version bump)
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes to build system or external dependencies
- **ci**: Changes to CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit (triggers PATCH version bump)

### Breaking Changes

For breaking changes, add `!` after the type or include `BREAKING CHANGE:` in the footer:

```
feat!: remove deprecated API endpoints

BREAKING CHANGE: The /api/v1/* endpoints have been removed in favor of /api/v2/*
```

This triggers a MAJOR version bump.

### Examples

#### Feature
```
feat(encryption): add support for P-521 curve

Added support for P-521 elliptic curve for enhanced security requirements.
```

#### Bug Fix
```
fix(unpack): handle edge case in message decryption

Fixed an issue where messages with empty headers would cause a panic.
```

#### Breaking Change
```
feat(api)!: change pack_encrypted signature

BREAKING CHANGE: pack_encrypted now requires PackEncryptedOptions parameter
instead of individual boolean flags.
```

### Scope

The scope is optional but recommended. Common scopes in this project:

- **encryption**: Encryption/decryption functionality
- **signing**: Message signing and verification
- **routing**: Message routing features
- **did**: DID resolution and management
- **api**: Public API changes
- **tests**: Test infrastructure
- **docs**: Documentation
- **deps**: Dependencies

## Automated Release Process

When you merge to `main`:

1. The semantic-release workflow analyzes commit messages
2. Determines the next version based on commit types
3. Updates `Cargo.toml` with the new version
4. Generates a CHANGELOG entry
5. Creates a GitHub release with release notes
6. Publishes the package to GitHub Package Registry

### Version Bumping Rules

- `fix:`, `perf:`, `revert:` → PATCH (1.0.0 → 1.0.1)
- `feat:` → MINOR (1.0.0 → 1.1.0)
- Breaking changes → MAJOR (1.0.0 → 2.0.0)
- `docs:`, `style:`, `refactor:`, `test:`, `build:`, `ci:`, `chore:` → No version change

## Pull Request Process

1. Ensure all commits follow the conventional commits format
2. The PR title should also follow the format: `<type>(<scope>): <description>`
3. All tests must pass
4. Code must be formatted with `cargo fmt`
5. No clippy warnings allowed

## Local Validation

To validate your commit messages locally before pushing:

```bash
# Install commitlint
npm install -g @commitlint/cli @commitlint/config-conventional

# Validate last commit
echo "$(git log -1 --pretty=%B)" | npx commitlint

# Or use a git hook (recommended)
npx husky add .husky/commit-msg 'npx commitlint --edit $1'
```