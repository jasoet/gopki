{
  description = "GoPKI development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.golangci-lint
            pkgs.gotools # goimports
            pkgs.openssl
            pkgs.bun

            # Container CLIs (daemon is system-level)
            pkgs.podman
            pkgs.docker-client
          ];

          shellHook = ''
            export GOPATH="$HOME/go"
            export PATH="$GOPATH/bin:$PATH"
            echo "GoPKI dev environment ready — Go $(go version | awk '{print $3}')"
          '';
        };
      });
}
