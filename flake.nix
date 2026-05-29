{
  description = "Cross-platform filesystem driver mounting a Synology FileStation share as a local directory";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
    }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          inherit (pkgs) lib;
          isLinux = pkgs.stdenv.hostPlatform.isLinux;
          isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

          # Pinned stable toolchain. rust-src/clippy/rustfmt are bundled so the
          # dev shell and `cargo clippy --workspace` (per CLAUDE.md) work as-is.
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "clippy"
              "rustfmt"
            ];
          };

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          # The crate sources. We keep the full workspace in scope (the CLI
          # depends on the path-dep core crate) but build only the CLI package.
          src = craneLib.cleanCargoSource ./.;

          # The root Cargo.toml is a bare workspace with no [package], so read
          # pname/version from the CLI crate's own manifest. Without this crane
          # falls back to a "cargo-package-0.0.1" placeholder.
          crateName = craneLib.crateNameFromCargoToml {
            cargoToml = ./rust/synology-filestation-fuse/Cargo.toml;
          };

          # pkg-config locates libfuse3 on Linux. The FUSE backend (fuser 0.17)
          # is cfg-gated to target_os = "linux"; macOS uses the dav-server
          # WebDAV backend, which needs no extra system library.
          nativeBuildInputs = [ pkgs.pkg-config ];

          buildInputs =
            lib.optionals isLinux [ pkgs.fuse3 ]
            ++ lib.optionals isDarwin [
              # reqwest's rustls-tls path avoids OpenSSL; libiconv + the
              # SystemConfiguration framework cover the common darwin link needs.
              pkgs.libiconv
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];

          commonArgs = {
            inherit (crateName) pname version;
            inherit src nativeBuildInputs buildInputs;
            strictDeps = true;

            # Scope every cargo invocation to the CLI crate so the PyO3 cdylib
            # crate (python/synology_filestation) is never built here — that
            # belongs to the maturin/uv path, not this Nix derivation.
            cargoExtraArgs = "--package synology-filestation-fuse";
          };

          # Dependency-only build, cached independently of the source so source
          # edits don't rebuild the dependency graph.
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          synology-filestation-fuse = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false; # tests hit a live NAS / wiremock; run via dev shell
              meta = {
                description = "Mount a Synology FileStation share as a local directory";
                homepage = "https://github.com/UCSD-E4E/synology-filestation";
                license = lib.licenses.mit;
                mainProgram = "synology-filestation-fuse";
                platforms = lib.platforms.linux ++ lib.platforms.darwin;
              };
            }
          );

          # ── Native FFI library (C ABI consumed by the GUI) ────────────────
          # Built as a cdylib; crane installs it to $out/lib. The GUI loads it
          # at runtime via SYNOFS_NATIVE_DIR (see the wrapper below).
          ffiArgs = commonArgs // {
            pname = "synology-filestation-ffi";
            cargoExtraArgs = "--package synology-filestation-ffi";
          };
          synology-filestation-ffi = craneLib.buildPackage (
            ffiArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
              meta = {
                description = "C ABI bindings for the Synology FileStation client and mount driver";
                homepage = "https://github.com/UCSD-E4E/synology-filestation";
                license = lib.licenses.mit;
                platforms = lib.platforms.linux ++ lib.platforms.darwin;
              };
            }
          );

          # ── .NET 10 GUI (Avalonia) ────────────────────────────────────────
          dotnet = pkgs.dotnetCorePackages.sdk_10_0;

          # Avalonia needs these shared libraries at runtime on Linux; the
          # buildDotnetModule wrapper bakes them into the launcher's
          # LD_LIBRARY_PATH. Harmless/ignored on darwin, so we gate the list.
          guiRuntimeDeps = lib.optionals isLinux (
            with pkgs;
            [
              fontconfig
              libGL
              libxkbcommon
              libx11
              libice
              libsm
              libxi
              libxext
              libxrandr
              libxcursor
              libxrender
            ]
          );

          synologyfuse-gui = pkgs.buildDotnetModule {
            pname = "synologyfuse-gui";
            inherit (crateName) version;

            src = ./.;

            projectFile = "SynologyFuse.Gui/SynologyFuse.Gui.csproj";
            testProjectFile = "SynologyFuse.Tests/SynologyFuse.Tests.csproj";

            # Regenerate with: nix build .#synologyfuse-gui.fetch-deps
            # then run the resulting script (writes to ./nix/deps.json).
            nugetDeps = ./nix/deps.json;

            dotnet-sdk = dotnet;
            dotnet-runtime = pkgs.dotnetCorePackages.runtime_10_0;

            executables = [ "SynologyFuse.Gui" ];
            selfContainedBuild = true;
            runtimeDeps = guiRuntimeDeps;

            # The GUI calls the Rust core directly through the native FFI
            # library (no subprocess). The resolver in NativeMethods.cs honours
            # SYNOFS_NATIVE_DIR, so point it at the cdylib's output dir to make
            # `nix run .#gui` self-sufficient. The CLI is also placed on PATH for
            # users who want the standalone terminal tool.
            makeWrapperArgs = [
              "--set SYNOFS_NATIVE_DIR ${synology-filestation-ffi}/lib"
              "--prefix PATH : ${lib.makeBinPath [ synology-filestation-fuse ]}"
            ];

            meta = {
              description = "Desktop GUI for the Synology FileStation filesystem driver";
              homepage = "https://github.com/UCSD-E4E/synology-filestation";
              license = lib.licenses.mit;
              mainProgram = "SynologyFuse.Gui";
              platforms = lib.platforms.linux ++ lib.platforms.darwin;
            };
          };
        in
        {
          packages = {
            inherit synology-filestation-fuse synology-filestation-ffi synologyfuse-gui;
            default = synology-filestation-fuse;
          };

          apps = {
            default = flake-utils.lib.mkApp {
              drv = synology-filestation-fuse;
            };
            gui = flake-utils.lib.mkApp {
              drv = synologyfuse-gui;
              name = "SynologyFuse.Gui";
            };
          };

          checks = {
            inherit synology-filestation-fuse synology-filestation-ffi synologyfuse-gui;

            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                # Lint the FFI crate alongside the CLI + core.
                cargoClippyExtraArgs =
                  "--package synology-filestation-fuse --package synology-filestation-ffi --all-targets -- -D warnings";
              }
            );

            fmt = craneLib.cargoFmt { inherit (crateName) pname version; inherit src; };
          };

          devShells.default = craneLib.devShell {
            inputsFrom = [ synology-filestation-fuse ];

            packages =
              [
                # Python-bindings toolchain (python/synology_filestation).
                pkgs.uv
                pkgs.maturin
                pkgs.python3

                # .NET 10 GUI (SynologyFuse.Gui).
                dotnet
              ]
              ++ lib.optionals isLinux [
                # Handy for mounting/unmounting during manual testing.
                pkgs.fuse3
              ];

            env = {
              DOTNET_ROOT = "${dotnet}";
              DOTNET_CLI_TELEMETRY_OPTOUT = "1";
              DOTNET_NOLOGO = "1";
            }
            // lib.optionalAttrs isLinux {
              # uv/maturin build the PyO3 extension against a real interpreter;
              # some crates' build scripts look for libfuse via pkg-config.
              PKG_CONFIG_PATH = "${pkgs.fuse3.dev}/lib/pkgconfig";
            };
          };

          formatter = pkgs.nixfmt;
        }
      );
}
