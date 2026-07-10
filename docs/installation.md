# Installation

Repository Trust Doctor v1.0 ships as self-contained command-line archives and as a packaged .NET tool. The React workbench remains a source-based local application in v1.0.

## Self-Contained CLI

Download the archive for your operating system from the [latest GitHub release](https://github.com/Wezylnia/repo-trust-doctor/releases/latest):

- `repo-trust-doctor-1.0.0-win-x64.tar.gz`
- `repo-trust-doctor-1.0.0-linux-x64.tar.gz`
- `repo-trust-doctor-1.0.0-linux-arm64.tar.gz`
- `repo-trust-doctor-1.0.0-osx-x64.tar.gz`
- `repo-trust-doctor-1.0.0-osx-arm64.tar.gz`

Verify the archive against `SHA256SUMS`, extract it, and place the executable on your `PATH`. The archives include the .NET runtime.

Linux and macOS may require the executable bit after extracting:

```text
chmod +x repo-trust-doctor
./repo-trust-doctor --version
```

On Windows:

```text
.\repo-trust-doctor.exe --version
```

## Packaged .NET Tool

Download `RepoTrustDoctor.Tool.1.0.0.nupkg` and install it from its containing directory:

```text
dotnet tool install --global RepoTrustDoctor.Tool --version 1.0.0 --add-source <download-folder>
repo-trust-doctor --version
```

This option requires a compatible .NET 10 runtime or SDK.

## Build From Source

Requirements:

- .NET SDK version from `global.json`,
- Git,
- Node.js 22 or newer only when running the React workbench.

```text
git clone https://github.com/Wezylnia/repo-trust-doctor.git
cd repo-trust-doctor
dotnet restore RepoTrustDoctor.slnx --locked-mode
dotnet build RepoTrustDoctor.slnx --configuration Release --no-restore
dotnet run --project src/Apps/RepoTrustDoctor.Cli -- --version
```

See the [README](../README.md) for scan examples and the [web UI guide](web-ui.md) for the local workbench.
