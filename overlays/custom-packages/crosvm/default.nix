{ prev }:
prev.crosvm.overrideAttrs (
  finalAttrs: _prevAttrs: rec {
    pname = "crosvm-r138";
    version = "r138";
    src = prev.fetchgit {
      url = "https://chromium.googlesource.com/chromiumos/platform/crosvm";
      rev = "92eb448365fe1822e3b8bb2471ef4bd85df398b4";
      hash = "sha256-RKqjt9ykmGk9rZcl8tIUqtVvwDEhAmb4OMCGQ+oyhFw=";
      fetchSubmodules = true;
    };
    cargoHash = "sha256-3NcQQZCsR3ekPBbe/ai8ke3MxBy0ONg1TJO9qLSH7jM=";
    cargoDeps = prev.rustPlatform.fetchCargoVendor {
      inherit (finalAttrs) pname src version;
      hash = finalAttrs.cargoHash;
    };
  }
)
