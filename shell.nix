let
  # Pinned version of pkgs
  pkgs = import (fetchTarball("https://github.com/NixOS/nixpkgs/archive/08dc90729fc8b4ab072607cf7257900a9cacb1f6.tar.gz")) {};
  # Uncomment if you want to try a more recent nixpkgs checkout instead
  #pkgs = import (fetchTarball("channel:nixpkgs-unstable")) {};
in
pkgs.mkShell {
  name = "nyantec-cert-auth-dev-shell";
  buildInputs = with pkgs; [
    cargo rustc
    openssl
    pkg-config
  ];
}
