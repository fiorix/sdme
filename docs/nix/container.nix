{ pkgs ? import <nixpkgs> {} }:

let
  # Build a NixOS system for use as a systemd-nspawn container.
  nixos = import "${pkgs.path}/nixos" {
    configuration = { config, lib, pkgs, ... }: {
      # Boot / init
      boot.isContainer = true;

      # Systemd + dbus are pulled in automatically when boot.isContainer = true,
      # but we list them explicitly so there's no ambiguity.
      services.dbus.enable = true;

      # Give the container a root password so we can log in.
      users.users.root.initialHashedPassword = "";

      # Networking: let the host handle it via systemd-nspawn --network-veth or
      # the default --network-namespace path.
      networking.useNetworkd = true;

      # Minimal set of useful packages inside the container.
      environment.systemPackages = with pkgs; [
        bashInteractive
        coreutils
        util-linux
        iproute2
        less
        procps
        findutils
        gnugrep
        gnused
        nano
      ];

      # Don't try to mount anything fancy.
      fileSystems."/" = {
        device = "none";
        fsType = "tmpfs";
      };

      # No bootloader.
      boot.loader.grub.enable = false;

      # Explicitly disable resolved — it conflicts with container mode's
      # host resolv.conf.
      services.resolved.enable = false;

      # Allow root login on the console.
      services.getty.autologinUser = "root";

      system.stateVersion = "24.11";
    };
  };
in
  # The toplevel derivation is the full system closure.
  # We use the system's toplevel, which gives us the /nix/store paths plus
  # a ready-to-boot /init symlink.
  nixos.config.system.build.toplevel
