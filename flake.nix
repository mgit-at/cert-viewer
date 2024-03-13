{
  description = "Admin tool to view and inspect multiple x509 Certificates";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system);
    in
    {
      overlays.default = final: prev: {
        cert-viewer = prev.callPackage ./. {};
      };

      packages = forAllSystems (system:
        let
          pkgs = (import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default ];
          });
        in
        {
          inherit (pkgs) cert-viewer;
          default = pkgs.cert-viewer;
        }
      );
    };
}
