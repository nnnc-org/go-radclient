{
  description = "RADIUS client with JSON metrics output, for use as a monitoring probe";

  inputs = {
    # go.mod requires go 1.26, which is new enough that only unstable has it.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
          }
        );

      # Mirrors what the Makefile stamps via git describe, so that
      # probe.version in the JSON output identifies the build instead of
      # reporting "(devel)".
      version = self.shortRev or self.dirtyShortRev or "dirty";
    in
    {
      packages = forAllSystems (
        { pkgs, ... }:
        rec {
          default = radius-client;

          radius-client = pkgs.buildGoModule {
            pname = "radius-client";
            inherit version;
            src = self;

            vendorHash = "sha256-6H/Jiddg7SPEPd2Itd4viqn4mSYDcZ3nNLHAj9jAxOk=";

            # The module is named go-radclient, so the toolchain names the
            # binary after it. Every doc and example calls the command
            # radius-client, so keep that name.
            postInstall = ''
              mv "$out/bin/go-radclient" "$out/bin/radius-client"
            '';

            ldflags = [
              "-s"
              "-w"
              "-X github.com/nnnc-org/go-radclient/cmd.version=${version}"
            ];

            # buildGoModule runs go test ./... in checkPhase. The suite binds
            # listeners on loopback, which the build sandbox permits.
            doCheck = true;

            meta = {
              description = "RADIUS client with JSON metrics output for monitoring probes";
              homepage = "https://github.com/nnnc-org/go-radclient";
              license = nixpkgs.lib.licenses.mit;
              mainProgram = "radius-client";
              inherit (nixpkgs.lib.platforms) unix;
            };
          };
        }
      );

      apps = forAllSystems (
        { system, ... }:
        rec {
          default = radius-client;
          radius-client = {
            type = "app";
            program = "${self.packages.${system}.radius-client}/bin/radius-client";
            meta.description = "Run the RADIUS client";
          };
        }
      );

      devShells = forAllSystems (
        { pkgs, ... }:
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.gotools
              # CI gates on this, so having it here beats discovering a lint
              # failure after pushing.
              pkgs.golangci-lint
              pkgs.gnumake
              # go test -race needs cgo, which needs a C compiler.
              pkgs.gcc
              # For reading the --json output and for generating test
              # certificates by hand.
              pkgs.jq
              pkgs.openssl
            ];

            shellHook = ''
              echo "go-radclient dev shell -- $(go version)"
              echo "  make          build ./bin/radius-client"
              echo "  make test     go test -race ./..."
              echo "  make checks   fmt, vet, tidy, lint, test"
            '';
          };
        }
      );

      # nix flake check builds the package, which runs the test suite.
      checks = forAllSystems (
        { system, ... }:
        {
          radius-client = self.packages.${system}.radius-client;
        }
      );

      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixfmt-tree);
    };
}
