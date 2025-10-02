{
    inputs = {
        nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

        rust-overlay = {
            url = "github:oxalica/rust-overlay";
            inputs.nixpkgs.follows = "nixpkgs";
        };
    };

    outputs = { nixpkgs, rust-overlay, ... }:
    let
        forAllSystems = f: nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed f;
    in {
        devShells = forAllSystems (system: {
            default = nixpkgs.legacyPackages.${system}.mkShell (
            let
                pkgs = import nixpkgs {
                    localSystem = "x86_64-linux";
                    overlays = [ rust-overlay.overlays.rust-overlay ];
                };
            in {
                packages = [
                    (pkgs.rust-bin.stable.latest.default.override {
                        extensions = [ "rust-src" ];
                        targets = [ "riscv32imac-unknown-none-elf" ];
                    })
                    pkgs.probe-rs
                ];
            });
        });
    };
}
