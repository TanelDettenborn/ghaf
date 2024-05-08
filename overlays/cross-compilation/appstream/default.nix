# Copyright 2024 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Appstream cross compile fix
{prev}:
prev.appstream.overrideAttrs (
  _finalAttrs: prevAttrs: {
    # https://github.com/NixOS/nixpkgs/pull/305241
    nativeBuildInputs = prevAttrs.nativeBuildInputs ++ [prev.appstream];
  }
)
