# Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# papirus-icon-theme cross-compilation fixes (removing qt dependency)
#
# TODO: check if we should be using the qt6 version of the theme
# kdePackages.breeze-icons and not the deprecated qt5 version
{ prev }:
prev.papirus-icon-theme.overrideAttrs (old: {
  propagatedBuildInputs = prev.lib.lists.remove prev.libsForQt5.breeze-icons old.propagatedBuildInputs;
})
