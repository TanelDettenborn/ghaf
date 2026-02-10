# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Module which provides partition template for NVIDIA Jetson AGX Orin
# flash-script
{
  pkgs,
  config,
  lib,
  ...
}:
let
  # Using the same config for all orin boards (for now)
  # TODO should this be changed when NX added
  cfg = config.ghaf.hardware.nvidia.orin;

  images = config.system.build.${config.formatAttr};
  partitionsEmmc = pkgs.writeText "sdmmc.xml" ''
    <partition name="master_boot_record" type="protective_master_boot_record">
      <allocation_policy> sequential </allocation_policy>
      <filesystem_type> basic </filesystem_type>
      <size> 512 </size>
      <file_system_attribute> 0 </file_system_attribute>
      <allocation_attribute> 8 </allocation_attribute>
      <percent_reserved> 0 </percent_reserved>
    </partition>
    <partition name="primary_gpt" type="primary_gpt">
      <allocation_policy> sequential </allocation_policy>
      <filesystem_type> basic </filesystem_type>
      <size> 19968 </size>
      <file_system_attribute> 0 </file_system_attribute>
      <allocation_attribute> 8 </allocation_attribute>
      <percent_reserved> 0 </percent_reserved>
    </partition>
    <partition name="esp" id="2" type="data">
      <allocation_policy> sequential </allocation_policy>
      <filesystem_type> basic </filesystem_type>
      <size> ESP_SIZE </size>
      <file_system_attribute> 0 </file_system_attribute>
      <allocation_attribute> 0x8 </allocation_attribute>
      <percent_reserved> 0 </percent_reserved>
      <filename> bootloader/esp.img </filename>
      <partition_type_guid> C12A7328-F81F-11D2-BA4B-00A0C93EC93B </partition_type_guid>
      <description> EFI system partition with systemd-boot. </description>
    </partition>
    <partition name="APP" id="1" type="data">
      <allocation_policy> sequential </allocation_policy>
      <filesystem_type> basic </filesystem_type>
      <size> ROOT_SIZE </size>
      <file_system_attribute> 0 </file_system_attribute>
      <allocation_attribute> 0x8 </allocation_attribute>
      <align_boundary> 16384 </align_boundary>
      <percent_reserved> 0x808 </percent_reserved>
      <unique_guid> APPUUID </unique_guid>
      <filename> root.img </filename>
      <description> **Required.** Contains the rootfs. This partition must be assigned
        the "1" for id as it is physically put to the end of the device, so that it
        can be accessed as the fixed known special device `/dev/mmcblk0p1`. </description>
    </partition>
    <partition name="secondary_gpt" type="secondary_gpt">
      <allocation_policy> sequential </allocation_policy>
      <filesystem_type> basic </filesystem_type>
      <size> 0xFFFFFFFFFFFFFFFF </size>
      <file_system_attribute> 0 </file_system_attribute>
      <allocation_attribute> 8 </allocation_attribute>
      <percent_reserved> 0 </percent_reserved>
    </partition>
  '';
  # When updating jetpack-nixos version, if the flash_t234_qspi_sdmmc.xml
  # changes (usually if the underlying BSP-version changes), you might need to
  # update the magical numbers to match the latest flash_t234_qspi_sdmmc.xml if
  # it has changed. The point is to replace content between
  # `partitionTemplateReplaceRange.firstLineCount` first lines and
  # `partitionTemplateReplaceRange.lastLineCount` last lines (i.e. the content
  # of the <device type="sdmmc_user" ...> </device> XML-tag), from the
  # NVIDIA-supplied flash_t234_qspi_sdmmc.xml, with the partitions specified in
  # the above partitionsEmmc variable.
  # Orin AGX Industrial has a slightly different flash XML template, so we
  # need to handle that separately.
  # it uses flash_t234_qspi_sdmmc_industrial.xml as a base and the sdmmc section
  # starts and ends at different lines.
  partitionTemplateReplaceRange =
    if (config.hardware.nvidia-jetpack.som == "orin-agx-industrial") then
      if (!cfg.flashScriptOverrides.onlyQSPI) then
        {
          firstLineCount = 631;
          lastLineCount = 2;
        }
      else
        {
          # If we don't flash anything to eMMC, then we don't need to have the
          # <device type="sdmmc_user" ...> </device> XML-tag at all.
          firstLineCount = 630;
          lastLineCount = 1;
        }
    else if !cfg.flashScriptOverrides.onlyQSPI then
      {
        firstLineCount = 618;
        lastLineCount = 2;
      }
    else
      {
        # If we don't flash anything to eMMC, then we don't need to have the
        # <device type="sdmmc_user" ...> </device> XML-tag at all.
        firstLineCount = 617;
        lastLineCount = 1;
      };
  partitionTemplate = pkgs.runCommand "flash.xml" { } (
    lib.optionalString (config.hardware.nvidia-jetpack.som != "orin-agx-industrial") ''
      head -n ${toString partitionTemplateReplaceRange.firstLineCount} ${pkgs.nvidia-jetpack.bspSrc}/bootloader/generic/cfg/flash_t234_qspi_sdmmc.xml >"$out"

    ''
    + lib.optionalString (config.hardware.nvidia-jetpack.som == "orin-agx-industrial") ''
      head -n ${toString partitionTemplateReplaceRange.firstLineCount} ${pkgs.nvidia-jetpack.bspSrc}/bootloader/generic/cfg/flash_t234_qspi_sdmmc_industrial.xml >"$out"

    ''
    + lib.optionalString (!cfg.flashScriptOverrides.onlyQSPI) ''

      # Replace the section for sdmmc-device with our own section
      cat ${partitionsEmmc} >>"$out"

    ''
    + lib.optionalString (config.hardware.nvidia-jetpack.som != "orin-agx-industrial") ''

      tail -n ${toString partitionTemplateReplaceRange.lastLineCount} ${pkgs.nvidia-jetpack.bspSrc}/bootloader/generic/cfg/flash_t234_qspi_sdmmc.xml >>"$out"
    ''
    + lib.optionalString (config.hardware.nvidia-jetpack.som == "orin-agx-industrial") ''

      tail -n ${toString partitionTemplateReplaceRange.lastLineCount} ${pkgs.nvidia-jetpack.bspSrc}/bootloader/generic/cfg/flash_t234_qspi_sdmmc_industrial.xml >>"$out"
    ''
  );
in
{
  config = lib.mkIf cfg.enable {
    hardware.nvidia-jetpack.flashScriptOverrides.partitionTemplate = partitionTemplate;
    hardware.nvidia-jetpack.flashScriptOverrides.preFlashCommands = ''
      echo "============================================================"
      echo "ghaf flashing script"
      echo "============================================================"
      echo "ghaf version: ${config.ghaf.version}"
      echo "som: ${config.hardware.nvidia-jetpack.som}"
      echo "carrierBoard: ${config.hardware.nvidia-jetpack.carrierBoard}"
      echo "============================================================"
      echo ""
      echo "Working dir: $WORKDIR"
      echo "Removing bootlodaer/esp.img if it exists ..."
      rm -fv "$WORKDIR/bootloader/esp.img"
      mkdir -pv "$WORKDIR/bootloader"

      # See https://developer.download.nvidia.com/embedded/L4T/r35_Release_v4.1/docs/Jetson_Linux_Release_Notes_r35.4.1.pdf
      # and https://developer.download.nvidia.com/embedded/L4T/r35_Release_v5.0/docs/Jetson_Linux_Release_Notes_r35.5.0.pdf
      #
      # In Section: Adaptation to the Carrier Board with HDMI for the Orin
      #             NX/Nano Modules
      #"${pkgs.pkgsBuildBuild.patch}/bin/patch" -p0 < ${./tegra2-mb2-bct-scr.patch}
    ''
    + lib.optionalString (!cfg.flashScriptOverrides.onlyQSPI) ''
      ESP_OFFSET=$(cat "${images}/esp.offset")
      ESP_SIZE=$(cat "${images}/esp.size")
      ROOT_OFFSET=$(cat "${images}/root.offset")
      ROOT_SIZE=$(cat "${images}/root.size")

      img="${images}/sd-image/${config.image.fileName}"
      echo "Extracting ESP partition to $WORKDIR/bootloader/esp.img ..."
      dd if=<("${pkgs.pkgsBuildBuild.zstd}/bin/pzstd" -d "$img" -c) of="$WORKDIR/bootloader/esp.img" bs=512 iseek="$ESP_OFFSET" count="$ESP_SIZE"
      ROOT_IMAGE_PATH="$WORKDIR/bootloader/root.img"
      ${lib.optionalString cfg.diskEncryption.enable ''
        ROOT_IMAGE_PATH="$WORKDIR/bootloader/root.enc.img"
      ''}
      echo "Extracting root partition to $ROOT_IMAGE_PATH ..."
      dd if=<("${pkgs.pkgsBuildBuild.zstd}/bin/pzstd" -d "$img" -c) of="$ROOT_IMAGE_PATH" bs=512 iseek="$ROOT_OFFSET" count="$ROOT_SIZE"

      ${lib.optionalString cfg.diskEncryption.enable ''
        echo ""
        echo "Generic LUKS rootfs encryption is enabled."
        GHAF_SKIP_LUKS_ENCRYPTION=0
        if [ -n "''${GHAF_LUKS_PASSPHRASE-}" ]; then
          GHAF_LUKS_PASSPHRASE_CONFIRM="$GHAF_LUKS_PASSPHRASE"
        elif [ -t 0 ] && [ -t 1 ]; then
          while true; do
            read -r -s -p "Enter shared LUKS passphrase: " GHAF_LUKS_PASSPHRASE
            echo ""
            read -r -s -p "Confirm shared LUKS passphrase: " GHAF_LUKS_PASSPHRASE_CONFIRM
            echo ""

            if [ -z "$GHAF_LUKS_PASSPHRASE" ]; then
              echo "Passphrase cannot be empty."
              continue
            fi

            if [ "$GHAF_LUKS_PASSPHRASE" != "$GHAF_LUKS_PASSPHRASE_CONFIRM" ]; then
              echo "Passphrases do not match. Try again."
              continue
            fi

            break
          done
        else
          GHAF_SKIP_LUKS_ENCRYPTION=1
          echo "Non-interactive environment without GHAF_LUKS_PASSPHRASE; skipping root image encryption."
        fi

        if [ "$GHAF_SKIP_LUKS_ENCRYPTION" -eq 0 ]; then
          GHAF_LUKS_PASSPHRASE_FILE=$(mktemp "$WORKDIR/.luks-passphrase.XXXXXX")
          chmod 600 "$GHAF_LUKS_PASSPHRASE_FILE"
          printf '%s' "$GHAF_LUKS_PASSPHRASE" > "$GHAF_LUKS_PASSPHRASE_FILE"
          unset GHAF_LUKS_PASSPHRASE GHAF_LUKS_PASSPHRASE_CONFIRM

          echo "Encrypting extracted root image with LUKS2 ..."
          "${pkgs.pkgsBuildBuild.cryptsetup}/bin/cryptsetup" reencrypt \
            --encrypt \
            --type luks2 \
            --batch-mode \
            --reduce-device-size $((16 * 1024 * 1024)) \
            --key-file "$GHAF_LUKS_PASSPHRASE_FILE" \
            "$ROOT_IMAGE_PATH"

          rm -f "$GHAF_LUKS_PASSPHRASE_FILE"
        fi
      ''}

      echo "Patching flash.xml with absolute paths to esp.img and root.img ..."
      "${pkgs.pkgsBuildBuild.gnused}/bin/sed" -i \
        -e "s#bootloader/esp.img#$WORKDIR/bootloader/esp.img#" \
        -e "s#root.img#$ROOT_IMAGE_PATH#" \
        -e "s#ESP_SIZE#$((ESP_SIZE * 512))#" \
        -e "s#ROOT_SIZE#$((ROOT_SIZE * 512))#" \
        flash.xml

    ''
    + lib.optionalString cfg.flashScriptOverrides.onlyQSPI ''
      echo "Flashing QSPI only, boot and root images not included."
    ''
    + ''
      echo "Ready to flash!"
      echo "============================================================"
      echo ""
    '';
  };
}
