# Deployment Guide

This document provides comprehensive instructions for deploying the FastAPI Roles Auth package using automated CI/CD pipelines with GitHub Actions and uv.

## Overview

The deployment pipeline includes:
- **Continuous Integration**: Automated testing, linting, and security checks
- **Continuous Deployment**: Automated publishing to PyPI and Docker Hub
- **Quality Assurance**: Pre-commit hooks and comprehensive code analysis

## Prerequisites

### GitHub Secrets Configuration

Configure the following secrets in your GitHub repository settings:

#### PyPI Deployment
- `PYPI_API_TOKEN`: Your PyPI API token for production releases
- `TEST_PYPI_API_TOKEN`: Your Test PyPI API token for development releases

#### Docker Hub Deployment (Optional)
- `DOCKERHUB_USERNAME`: Your Docker Hub username
- `DOCKERHUB_TOKEN`: Your Docker Hub access token

### Environment Setup

Create GitHub environments for deployment protection:

1. **test-pypi**: For Test PyPI deployments (develop branch)
2. **production**: For PyPI deployments (releases)

## CI/CD Pipeline

### Workflow Triggers

The pipeline is triggered by:
- **Push to main/develop**: Runs tests and security checks
- **Pull requests to main**: Runs full test suite
- **Release published**: Deploys to production PyPI and Docker Hub

### Pipeline Jobs

#### 1. Test Job
- **Python versions**: 3.12
- **Tools**: Ruff (linting/formatting), MyPy (type checking), Pytest (testing)
- **Coverage**: Uploads to Codecov
- **Matrix strategy**: Supports multiple Python versions

#### 2. Security Job
- **Safety**: Checks for known security vulnerabilities
- **Bandit**: Static security analysis for Python code
- **Dependency scanning**: Automated vulnerability detection

#### 3. Build Job
- **Package building**: Uses `uv build` for wheel and source distribution
- **Artifact storage**: Uploads build artifacts for deployment jobs

#### 4. Deployment Jobs

##### Test PyPI (develop branch)
- **Trigger**: Push to develop branch
- **Target**: Test PyPI repository
- **Purpose**: Validate package before production release

##### Production PyPI (releases)
- **Trigger**: GitHub release published
- **Target**: Official PyPI repository
- **Purpose**: Public package distribution

##### Docker Hub (releases)
- **Trigger**: GitHub release published
- **Target**: Docker Hub registry
- **Features**: Multi-platform builds, caching, semantic versioning

## Local Development Setup

### Install uv

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Project Setup

```bash
# Clone repository
git clone <repository-url>
cd fastapi-roles-auth

# Install dependencies
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install
```

### Development Commands

```bash
# Run tests
uv run pytest

# Lint and format code
uv run ruff check --fix
uv run ruff format

# Type checking
uv run mypy fastauth

# Security scan
uv run bandit -r fastauth

# Build package
uv build

# Run pre-commit on all files
uv run pre-commit run --all-files
```

## Release Process

### Version Management

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md` with release notes
3. Commit changes to develop branch
4. Create pull request to main branch
5. Merge after CI passes

### Creating a Release

1. **Create GitHub Release**:
   ```bash
   # Tag the release
   git tag v0.1.3
   git push origin v0.1.3
   
   # Create release through GitHub UI or CLI
   gh release create v0.1.3 --title "Release v0.1.3" --notes "Release notes here"
   ```

2. **Automated Deployment**:
   - GitHub Actions automatically builds and deploys
   - Package published to PyPI
   - Docker image pushed to Docker Hub
   - Release artifacts attached to GitHub release

### Manual Deployment

If needed, you can deploy manually:

```bash
# Build package
uv build

# Upload to Test PyPI
uv run twine upload --repository testpypi dist/*

# Upload to PyPI
uv run twine upload dist/*
```

## Docker Deployment

### Building Docker Image

```bash
# Build image
docker build -t fastapi-roles-auth:latest .

# Run container
docker run -p 8000:8000 fastapi-roles-auth:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  app:
    image: fastapi-roles-auth:latest
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///./app.db
    volumes:
      - ./data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Configuration

### Environment Variables

- `DATABASE_URL`: Database connection string
- `SECRET_KEY`: JWT secret key
- `DEBUG`: Enable debug mode (development only)
- `CORS_ORIGINS`: Allowed CORS origins

### Production Considerations

1. **Security**:
   - Use strong secret keys
   - Enable HTTPS
   - Configure CORS properly
   - Regular security updates

2. **Performance**:
   - Use production ASGI server (Gunicorn + Uvicorn)
   - Configure database connection pooling
   - Enable caching where appropriate

3. **Monitoring**:
   - Set up health checks
   - Configure logging
   - Monitor performance metrics

## Troubleshooting

### Common Issues

1. **Build Failures**:
   - Check Python version compatibility
   - Verify all dependencies are available
   - Review test failures in CI logs

2. **Deployment Issues**:
   - Verify GitHub secrets are configured
   - Check PyPI token permissions
   - Ensure version number is incremented

3. **Docker Issues**:
   - Verify Dockerfile syntax
   - Check base image availability
   - Review container logs

### Getting Help

- Check GitHub Actions logs for detailed error messages
- Review the [uv documentation](https://docs.astral.sh/uv/)
- Open an issue in the repository for support

## Security Best Practices

1. **Secrets Management**:
   - Never commit secrets to repository
   - Use GitHub secrets for sensitive data
   - Rotate tokens regularly

2. **Dependency Management**:
   - Regular dependency updates
   - Security vulnerability scanning
   - Pin dependency versions

3. **Code Quality**:
   - Mandatory code reviews
   - Automated testing
   - Static analysis tools

## Monitoring and Maintenance

### Automated Monitoring

- **Dependabot**: Automated dependency updates
- **CodeQL**: Security vulnerability scanning
- **Codecov**: Test coverage monitoring

### Manual Maintenance

- Regular security audits
- Performance optimization
- Documentation updates
- Community feedback integration
