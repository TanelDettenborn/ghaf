# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
#
# SPDX-License-Identifier: Apache-2.0
_:
(
  {
    pkgs,
    config,
    lib,
    ...
  }:
  let
    pkcs11-tool-optee = pkgs.writeShellScriptBin "pkcs11-tool-optee" ''
      exec "${pkgs.opensc}/bin/pkcs11-tool" --module "${pkgs.nvidia-jetpack.opteeClient}/lib/libckteec.so" $@
    '';
    optee-hello-example-host = pkgs.stdenv.mkDerivation {
      name = "opteehelloexamplehost";
      src = ./optee-ta-example;
      PACKAGES_PATH = [ "${pkgs.nvidia-jetpack.opteeClient}" ];
      buildCommand = ''
           $CC "$src"/host/main.c -o ca-hello-example -I ${pkgs.nvidia-jetpack.opteeClient}/include/ -I "$src"/ta/include -lteec -L ${pkgs.nvidia-jetpack.opteeClient}/lib
           install -D ca-hello-example "$out/bin/optee-hello-example"
      '';
    };

    optee-hello-example-ta = pkgs.stdenv.mkDerivation {
      name = "opteehelloexampleta";
      src = ./optee-ta-example/ta;
      nativeBuildInputs = [(pkgs.buildPackages.python3.withPackages (p: [p.cryptography]))];
      makeFlags = [
        "CROSS_COMPILE=${pkgs.stdenv.cc.targetPrefix}"
        "TA_DEV_KIT_DIR=${pkgs.nvidia-jetpack.taDevKit}/export-ta_arm64"
        "O=$(PWD)/out"
      ];
      installPhase = ''
         runHook preInstall
         install -Dm755 -t $out out/11223344-1122-1122-1122334455667788.ta
         runHook postInstall
      '';
    };
  in
  {
    hardware.nvidia-jetpack.firmware.optee.pkcs11Support =
      config.ghaf.hardware.nvidia.orin.optee.pkcs11.enable;
    hardware.nvidia-jetpack.firmware.optee.extraMakeFlags =
      (lib.optionals config.ghaf.hardware.nvidia.orin.optee.pkcs11.enable [
        "CFG_PKCS11_TA_TOKEN_COUNT=${toString config.ghaf.hardware.nvidia.orin.optee.pkcs11.tokenCount}"
        "CFG_PKCS11_TA_HEAP_SIZE=${toString config.ghaf.hardware.nvidia.orin.optee.pkcs11.heapSize}"
        "CFG_PKCS11_TA_AUTH_TEE_IDENTITY=${
          if config.ghaf.hardware.nvidia.orin.optee.pkcs11.authTeeIdentity then "y" else "n"
        }"
      ])
      ++ lib.optionals config.ghaf.hardware.nvidia.orin.optee.pkcs11.lockPinAfterFailedLoginAttempts [
        "CFG_PKCS11_TA_LOCK_PIN_AFTER_FAILED_LOGIN_ATTEMPTS=${
          if config.ghaf.hardware.nvidia.orin.optee.pkcs11.lockPinAfterFailedLoginAttempts then "y" else "n"
        }"
      ];
    hardware.nvidia-jetpack.firmware.optee.patches =
      lib.optional config.ghaf.hardware.nvidia.orin.optee.pkcs11.lockPinAfterFailedLoginAttempts ./0001-ta-pkcs11-Build-time-option-for-controlling-pin-lock.patch;

    hardware.nvidia-jetpack.firmware.optee.xtest = config.ghaf.hardware.nvidia.orin.optee.xtest;

    hardware.nvidia-jetpack.firmware.optee.supplicant.trustedApplications = [ optee-hello-example-ta ];
    
    environment.systemPackages = [ optee-hello-example-host ] ++ lib.optional config.ghaf.hardware.nvidia.orin.optee.pkcs11-tool pkcs11-tool-optee;
  }
)
