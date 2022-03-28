let
  pkgs = import (fetchTarball("channel:nixpkgs-unstable")) {};
in
pkgs.mkShell {
  name = "nyantec-cert-auth-dev-shell";
  buildInputs = with pkgs; [
    cargo rustc
    openssl
    pkg-config
  ];
}
