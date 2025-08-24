# Using navia-didcomm from GitHub Package Registry

This guide explains how to use the `navia-didcomm` library in your private repository through GitHub Package Registry.

## Setup in Your Repository

### Method 1: Using GitHub Package Registry (Recommended for private repos)

1. **Add the dependency to your `Cargo.toml`:**

```toml
[dependencies]
navia-didcomm = { version = "1.0.3", registry = "github" }
```

2. **Configure cargo authentication locally:**

Create or update `~/.cargo/config.toml`:

```toml
[registries.github]
index = "https://github.com/rust-lang/_placeholder"
token = "YOUR_GITHUB_PERSONAL_ACCESS_TOKEN"

[registry]
default = "github"
```

3. **Generate a GitHub Personal Access Token:**
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate a new token with `read:packages` scope (and `write:packages` if you need to publish)
   - Replace `YOUR_GITHUB_PERSONAL_ACCESS_TOKEN` in the config above

### Method 2: Using Git dependency with authentication

If you prefer using git dependencies directly:

```toml
[dependencies]
navia-didcomm = { git = "https://github.com/Nyx-Chat/navia-didcomm.git", tag = "v1.0.3" }
```

For private repository access, configure git to use your token:

```bash
git config --global url."https://YOUR_GITHUB_TOKEN@github.com/".insteadOf "https://github.com/"
```

## CI/CD Configuration

### GitHub Actions

Add this to your workflow to authenticate with GitHub Package Registry:

```yaml
- name: Configure cargo for GitHub Package Registry
  run: |
    mkdir -p ~/.cargo
    cat >> ~/.cargo/config.toml << EOF
    [registries.github]
    index = "https://github.com/rust-lang/_placeholder"
    token = "${{ secrets.GITHUB_TOKEN }}"
    
    [registry]
    default = "github"
    EOF
    
    # For git dependencies
    git config --global url."https://${{ secrets.GITHUB_TOKEN }}@github.com/".insteadOf "https://github.com/"
```

### Environment Variables Method

Alternatively, you can use environment variables:

```yaml
env:
  CARGO_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Publishing New Versions

To publish a new version of `navia-didcomm` to GitHub Package Registry:

1. **Automatic publishing on tag:**
   - Create and push a new tag: `git tag v1.0.4 && git push origin v1.0.4`
   - The GitHub Action will automatically publish to the package registry

2. **Manual publishing:**
   - Go to Actions tab in the repository
   - Select "Publish to GitHub Package Registry" workflow
   - Click "Run workflow"
   - Optionally specify a version to publish

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:

1. Verify your token has the correct scopes (`read:packages` for consuming, `write:packages` for publishing)
2. Ensure the token is not expired
3. Check that the repository visibility matches your token permissions

### Package Not Found

If the package cannot be found:

1. Ensure the package has been published (check the Packages tab in the GitHub repository)
2. Verify the registry configuration in your `Cargo.toml`
3. Try clearing cargo's cache: `cargo clean && rm -rf ~/.cargo/registry/cache`

### Using in Docker

When building Docker images that need to access the private package:

```dockerfile
# Pass the token as a build argument
ARG GITHUB_TOKEN

# Configure cargo authentication
RUN mkdir -p ~/.cargo && \
    echo "[registries.github]" >> ~/.cargo/config.toml && \
    echo "index = \"https://github.com/rust-lang/_placeholder\"" >> ~/.cargo/config.toml && \
    echo "token = \"${GITHUB_TOKEN}\"" >> ~/.cargo/config.toml

# Build your application
COPY . .
RUN cargo build --release
```

Build with: `docker build --build-arg GITHUB_TOKEN=$GITHUB_TOKEN .`

## Features

The library supports the following optional features:

- `uniffi` - Enable UniFFI bindings
- `testvectors` - Enable test vectors support
- `tracing` - Enable tracing/logging support

To use with features:

```toml
[dependencies]
navia-didcomm = { version = "1.0.3", registry = "github", features = ["tracing"] }
```

## Support

For issues or questions about using this package, please open an issue in the [navia-didcomm repository](https://github.com/Nyx-Chat/navia-didcomm/issues).