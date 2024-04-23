{ buildGoModule
, lib
, installShellFiles
}:

buildGoModule rec {
  pname = "cert-viewer";
  # get version from BUILD.bazel
  version = with builtins; elemAt (match ".*version = \"([0-9.]*)\".*" (readFile ./BUILD.bazel)) 0;

  src = ./.;

  vendorHash = "sha256-jNT04bYH5L/Zcfvel673zr2UJLayCO443tvBGZjrBZk=";

  nativeBuildInputs = [
    installShellFiles
  ];

  postInstall = ''
    $out/bin/cert-viewer --help-man > cert-viewer.1
    installManPage cert-viewer.1
  '';

  meta = {
    description = "Admin tool to view and inspect multiple x509 Certificates";
    homepage = "https://github.com/mgit-at/cert-viewer";
    license = lib.licenses.asl20;
    maintainers = [ lib.maintainers.mkg20001 ];
    mainProgram = "cert-viewer";
  };
}
