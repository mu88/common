# common — Repo Context

## This Is a Pure GitHub Infrastructure Repository
- No .NET code exists — `dotnet build/test/run` are not applicable. The entire repo consists of GitHub Actions reusable workflows, composite actions, and Renovate configuration.
- Do not apply .NET conventions here.

## Shared CI/CD Workflow (`ci-cd.yml`) — Breaking Change Risk
- `ci-cd.yml` is consumed by all mu88 repos via SHA-pinned references. Its `inputs` and `outputs` are a stable contract — any change to them requires coordinated updates in all consumer repos.
- Renovate automatically bumps the SHA pin in every consumer repo via PRs — never manually change it in consumers.

## Sonar `sonar-additional-params` Quirk
- Repos without a `SonarQube.Analysis.xml` file pass `sonar-additional-params: ' '` (a single space) — an empty string `''` does not work and breaks the Sonar step. Keep this as-is.
