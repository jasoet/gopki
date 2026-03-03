# Podman Migration Design

## Context

The project uses `testcontainers-go` for integration tests that run OpenBao in a container. Previously this required Docker. We are migrating to Podman as the container runtime.

## Decision

Use Podman in rootful mode with `testcontainers.ProviderPodman` hardcoded. Container tests are local-development only (CI runs non-container tests).

## Local Setup (one-time)

1. Podman installed via Homebrew (`5.8.0`)
2. Podman machine configured as rootful: `podman machine set --rootful`
3. `podman-mac-helper` installed for `/var/run/docker.sock` compatibility
4. `~/.testcontainers.properties` includes `ryuk.container.privileged=true`

## Code Changes

### 1. `bao/testcontainer/container.go`

Add `ProviderType: testcontainers.ProviderPodman` to the `GenericContainerRequest` in the `Start()` function.

### 2. `Taskfile.yml`

Update task descriptions from "Docker" to "Podman":
- `test:integration` description
- `test:compatibility:bao` description

## Scope

- 2 files changed
- 3 lines modified
- No new dependencies
- No changes to integration test files (they all go through `bao/testcontainer/container.go`)

## Verification

1. `task test` — non-container tests still pass
2. `task test:integration` — OpenBao integration tests work with Podman
3. `task test:compatibility:bao` — OpenBao compatibility tests work with Podman
