{
  description = "DzmingLi/rapidhash — a faithful MoonBit port of rapidhash V3";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    moonbit-overlay = {
      url = "github:moonbit-community/moonbit-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, moonbit-overlay, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          # Latest MoonBit toolchain with a bundled core (`moon bundle`'d), so
          # `moon`/`moonc` find `core.core` via `-std-path`.
          moonbit = moonbit-overlay.packages.${system}.moonbit_latest;
        in
        {
          default = pkgs.mkShell {
            packages = [
              moonbit
              pkgs.gcc # native-backend tests
              pkgs.git # `moon publish` packaging
              pkgs.curl # `moon login` / mooncakes.io
            ];
            # On NixOS moon's bundled tcc can't find crt/libc (FHS paths); MOON_CC
            # makes moon drive the real cc-wrapper instead, so native debug tests work.
            MOON_CC = "${pkgs.stdenv.cc}/bin/cc";
            shellHook = ''
              echo "rapidhash dev shell"
              echo "  moon: $(moon version 2>/dev/null || echo 'not found')"
            '';
          };
        });
    };
}
