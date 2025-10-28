# Copyright 2022-2024 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{ inputs }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  pkvmKernel = pkgs.linuxManualConfig {
    src = pkgs.fetchgit {
      url = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";
      rev = "2eaf5c0d81911ba05bace3a722cbcd708fdbbcba";
      hash = "sha256-iSfdZfnazAvZXR4w2+hvfLJc9/jg3BlSGnpMo7oyqIc=";
    };
    version = "6.6.41";
    configfile = ./pkvm_guest_defconfig;
    inherit (pkgs) stdenv;
    kernelPatches = [
      {
        name = "0001-firmware-smccc-Call-arch-specific-hook-on-discoverin.patch";
        patch = ./pkvmpatches/0001-firmware-smccc-Call-arch-specific-hook-on-discoverin.patch;
      }
      {
        name = "0002-arm64-mm-Implement-memory-encryption-API-using-KVM-s.patch";
        patch = ./pkvmpatches/0002-arm64-mm-Implement-memory-encryption-API-using-KVM-s.patch;
      }
      {
        name = "0003-mm-vmalloc-Add-arch-specific-callbacks-to-track-io-r.patch";
        patch = ./pkvmpatches/0003-mm-vmalloc-Add-arch-specific-callbacks-to-track-io-r.patch;
      }
      {
        name = "0004-arm64-Implement-ioremap-iounmap-hooks-calling-into-K.patch";
        patch = ./pkvmpatches/0004-arm64-Implement-ioremap-iounmap-hooks-calling-into-K.patch;
      }
      {
        name = "0005-guest_defconfig-Create-a-new-defconfig-for-the-guest.patch";
        patch = ./pkvmpatches/0005-guest_defconfig-Create-a-new-defconfig-for-the-guest.patch;
      }
    ];
  };

  configHost = config;
  vmName = "pkvmtestvm";

  pkvmTestVmBaseConfiguration = {
    imports = [
      inputs.preservation.nixosModules.preservation
      inputs.self.nixosModules.givc
      inputs.self.nixosModules.vm-modules
      inputs.self.nixosModules.profiles
      (
        { lib, ... }:
        {
          services.getty.autologinUser = "root";
          networking.firewall.checkReversePath = "loose";

          ghaf = {
            #networking.firewall.checkReversePath = "loose";
            type = "system-vm";
            systemd = {
              enable = true;
              withName = "pkvmtestvm-systemd";
              withAudio = false;
              withBluetooth = false;
              withNss = false;
              withResolved = false;
              withTimesyncd = false;
              withDebug = configHost.ghaf.profiles.debug.enable;
              withHardenedConfigs = false;
            };

            profiles.debug.enable = lib.mkDefault configHost.ghaf.profiles.debug.enable;
            development = {
              # NOTE: SSH port also becomes accessible on the network interface
              #       that has been passed through to NetVM
              ssh.daemon.enable = lib.mkDefault configHost.ghaf.development.ssh.daemon.enable;
              debug.tools.enable = lib.mkDefault configHost.ghaf.development.debug.tools.enable;
              nix-setup.enable = lib.mkDefault configHost.ghaf.development.nix-setup.enable;
            };

            virtualization.microvm.vm-networking = {
              enable = true;
              inherit vmName;
            };
          };

          nixpkgs = {
            buildPlatform.system = configHost.nixpkgs.buildPlatform.system;
            hostPlatform.system = configHost.nixpkgs.hostPlatform.system;
          };

          boot.initrd.kernelModules = [
            "virtio_mmio"
            "virtio_pci"
            "virtio_blk"
            "9pnet_virtio"
            "9p"
            "virtiofs"
          ];
          boot.initrd.allowMissingModules = true;
          boot.kernelPackages = pkgs.linuxPackagesFor pkvmKernel;

          microvm = {
            #storeDiskType = "squashfs";
            optimize.enable = false;
            hypervisor = "crosvm";
            shares = [
              {
                tag = "ro-store";
                source = "/nix/store";
                mountPoint = "/nix/.ro-store";
                #proto = "virtiofs";
              }
            ];
            crosvm = {
              extraArgs = [
                # "--log-level=debug"
                "--no-balloon"
                "--no-rng"
                "--unmap-guest-memory-on-fork"
                "--protected-vm-without-firmware"
                "--disable-sandbox"
              ];
            };
          };
        }
      )
    ];
  };
  cfg = config.ghaf.virtualization.microvm.pkvmtestvm;
in
{
  options.ghaf.virtualization.microvm.pkvmtestvm = {
    enable = lib.mkEnableOption "pkvmtestvm";

    extraModules = lib.mkOption {
      description = ''
        List of additional modules to be imported and evaluated as part of
        pkvmtestVM's NixOS configuration.
      '';
      default = [ ];
    };

    extraNetworking = lib.mkOption {
      type = lib.types.networking;
      description = "Extra Networking option";
      default = { };
    };
  };

  config = lib.mkIf cfg.enable {
    ghaf.common.extraNetworking.hosts.${vmName} = cfg.extraNetworking;

    microvm.vms."${vmName}" = {
      autostart = false;
      restartIfChanged = false;
      inherit (inputs) nixpkgs;
      specialArgs = { inherit lib; };

      config = pkvmTestVmBaseConfiguration // {
        imports = pkvmTestVmBaseConfiguration.imports ++ cfg.extraModules;
      };
    };
  };
}
