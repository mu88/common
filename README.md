# common

![Build Dev Containers](https://github.com/mu88/common/actions/workflows/_internal-build-devcontainers.yml/badge.svg)

Shared infrastructure and configuration for [mu88](https://github.com/mu88)'s GitHub repositories.

This repository serves as a central place for reusable dev containers, CI/CD workflows, GitHub Actions, and dependency management configuration — keeping things consistent and DRY across projects.

## Dev Containers

Pre-built [dev container](https://containers.dev/) definitions for various development environments, published as container images to the GitHub Container Registry (`ghcr.io`):

| Name | Image | Description |
|------|-------|-------------|
| **.NET** | `ghcr.io/mu88/devcontainers-dotnet` | Full-featured .NET development environment with Docker-in-Docker, PowerShell, and common VS Code extensions. |
| **.NET + Playwright** | `ghcr.io/mu88/devcontainers-dotnet-playwright` | Extends the .NET dev container with Playwright browser automation support (Chromium). |
| **Jekyll** | `ghcr.io/mu88/devcontainers-jekyll` | Ruby/Jekyll environment for static site development. |
| **Node / devcontainers-cli** | `ghcr.io/mu88/devcontainers-node-devcontainer-cli` | Node.js/TypeScript environment with the Dev Containers CLI pre-installed. |

The .NET-based images are tagged with `latest` and `sdk-<version>` (e.g. `sdk-10.0.201`).

Dev container images are automatically built and pushed via GitHub Actions on every commit to the default branch.

### Using a Dev Container

In your own repository's `.devcontainer/devcontainer.json`, reference one of the published images:

```json
{
  "image": "ghcr.io/mu88/devcontainers-dotnet:sdk-10.0.201"
}
```

## Reusable CI/CD Workflow

A comprehensive [reusable GitHub Actions workflow](.github/workflows/ci-cd.yml) tailored for .NET projects. It provides an opinionated, batteries-included pipeline covering:

- Building and testing (.NET unit, integration, and performance tests)
- Code quality analysis via SonarQube
- Docker image publishing using .NET SDK Container Building Tools
- Release management with semantic versioning and release notes generation
- Supply chain security (build provenance attestation and SBOM generation)

Other repositories call this workflow via `workflow_call`, passing in project-specific parameters:

```yaml
jobs:
  shared_ci_cd:
    permissions:
      attestations: write
      contents: read
      id-token: write
      packages: write
    uses: mu88/common/.github/workflows/ci-cd.yml@main
    with:
      docker-publish-project: src/MyApp/MyApp.csproj
      sonar-key: mu88_MyProject
    secrets:
      sonar-token: ${{ secrets.SONAR_TOKEN }}
```

### Outputs

The workflow exposes several outputs that can be consumed by subsequent jobs:

| Output | Description |
|--------|-------------|
| `is_release` | `true` when the commit message starts with `chore(release):` |
| `version` | The determined version (release or pre-release) |
| `release_version` | The release version (if a release) |
| `pre_release_version` | The pre-release version (if not a release) |
| `release_notes` | Generated release notes (if a release) |

## Reusable GitHub Actions

### `build-dev-container`

Composite action to build and push a dev container image to GHCR. Used internally by the
[`_internal-build-devcontainers.yml`](.github/workflows/_internal-build-devcontainers.yml) workflow.

### `attest-provenance-sbom`

Composite action to generate an SBOM and attest build provenance for **non-Docker release artifacts**
(e.g. a ZIP or single-file executable). Consuming repos call this action after building their own
release artifacts:

```yaml
- name: Generate SBOM and attest build provenance and SBOM
  uses: mu88/common/.github/actions/attest-provenance-sbom@main
  with:
    is-release: ${{ needs.shared_ci_cd.outputs.is_release }}
    sbom-file: sbom.json
    sbom-path: .
    subject-path: ${{ runner.temp }}/Release/MyApp*.zip
```

> **Note:** Docker image attestation is handled separately and automatically by the `ci-cd.yml`
> reusable workflow itself — no need to call this action for Docker images.

## Renovate Configuration

A shared [Renovate](https://docs.renovatebot.com/) preset (`renovate/default.json5`) that other repositories extend. Key policies include:

- Grouping all dependency updates into a single PR
- Auto-merging non-major updates after a minimum release age
- Extended waiting periods for .NET SDK/runtime updates to allow dev machines to catch up
- Disabling automatic major .NET updates (handled manually)
- Custom managers for detecting .NET SDK versions in `devcontainer.json`, `.csproj`, Docker images, and more

Extend it from any repo's `renovate.json5`:

```json5
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "github>mu88/common//renovate/default.json5"
  ]
}
```

## License

[Do No Harm License](LICENSE.MD)
