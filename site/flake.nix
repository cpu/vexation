{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-parts, }:
    flake-parts.lib.mkFlake { inherit self; } {
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" ];

      perSystem = { pkgs, self', ... }: {
        packages = {
          mini = pkgs.runCommand "mini" {
            src = pkgs.fetchFromGitHub {
              repo = "hugo-theme-mini";
              owner = "nodejh";
              rev = "7f6f395052486d8cc52f768c1519dbe1c93afcd0";
              hash = "sha256-TDS7V/cHxTybDT7YcX5Eazq1+P7+hCgQ7SJvzciGsC0=";
            };
          } ''
            cp -ra $src $out
          '';

          themes = pkgs.linkFarmFromDrvs "themes" [ self'.packages.mini ];

          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "vexation-site";
            version = builtins.substring 0 8 self.lastModifiedDate;
            src = self;
            nativeBuildInputs = [ pkgs.hugo ];
            HUGO_THEMESDIR = self'.packages.themes;
            buildPhase = ''
              runHook preBuild
              mkdir -p $out
              cd site
              hugo --minify --destination $out
              runHook postBuild
            '';
            dontInstall = true;
          };

          serve = pkgs.writeShellScriptBin "serve" ''
            ${pkgs.ran}/bin/ran -r ${self'.packages.default}
          '';
        };

        devShells.default = pkgs.mkShellNoCC {
          name = "vexation-site";
          inputsFrom = [ self'.packages.default ];
          HUGO_THEMESDIR = self'.packages.themes;
        };
      };
    };
}
