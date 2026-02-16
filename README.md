# common

Shared infrastructure and configuration for [mu88](https://github.com/mu88)'s GitHub repositories.

This repository serves as a central place for reusable dev containers, CI/CD workflows, GitHub Actions, and dependency management configuration — keeping things consistent and DRY across projects.

## Dev Containers

Pre-built [dev container](https://containers.dev/) definitions for various development environments, published as container images to the GitHub Container Registry (`ghcr.io`):

- **.NET** — A full-featured .NET development environment with Docker-in-Docker, PowerShell, and common VS Code extensions.
- **.NET + Playwright** — Extends the .NET dev container with Playwright browser automation support (Chromium).
- **Jekyll** — A Ruby/Jekyll environment for static site development.
- **Node / devcontainers-cli** — A Node.js/TypeScript environment with the Dev Containers CLI pre-installed.

Dev container images are automatically built and pushed via GitHub Actions on every commit to the default branch.

## Reusable CI/CD Workflow

A comprehensive [reusable GitHub Actions workflow](.github/workflows/ci-cd.yml) tailored for .NET projects. It provides an opinionated, batteries-included pipeline covering:

- Building and testing (.NET unit, integration, and performance tests)
- Code quality analysis via SonarQube
- Docker image publishing using .NET SDK Container Building Tools
- Release management with semantic versioning and release notes generation
- Supply chain security (build provenance attestation and SBOM generation)

Other repositories call this workflow via `workflow_call`, passing in project-specific parameters.

## Reusable GitHub Actions

- **build-dev-container** — Composite action to build and push a dev container image to GHCR.
- **attest-provenance-sbom** — Composite action to generate an SBOM and attest build provenance for release artifacts.

## Renovate Configuration

A shared [Renovate](https://docs.renovatebot.com/) preset (`renovate/default.json5`) that other repositories extend. Key policies include:

- Grouping all dependency updates into a single PR
- Auto-merging non-major updates after a minimum release age
- Extended waiting periods for .NET SDK/runtime updates to allow dev machines to catch up
- Disabling automatic major .NET updates (handled manually)
- Custom managers for detecting .NET SDK versions in `devcontainer.json`, `.csproj`, Docker images, and more

## License

[Do No Harm License](LICENSE.MD)
