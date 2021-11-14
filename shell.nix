{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = [
	  pkgs.zeromq
    pkgs.pkg-config
    pkgs.alsa-lib
  ];
}
