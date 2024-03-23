{ buildGoModule
, lib
}:

buildGoModule rec {
  pname = "cert-viewer";
  # get version from BUILD.bazel
  version = with builtins; elemAt (match ".*version = \"([0-9.]*)\".*" (readFile ./BUILD.bazel)) 0;

  src = ./.;

  vendorHash = "sha256-55zDUAe5s+03/OnDcK1DqmMUpFO2sBaVjEk6vbrHgzY=";

  meta = {
    description = "Admin tool to view and inspect multiple x509 Certificates";
    homepage = "https://github.com/mgit-at/cert-viewer";
    license = lib.licenses.apsl20;
    maintainers = with lib.maintainers; [ mkg20001 ];
    mainProgram = "cert-viewer";
  };
}
