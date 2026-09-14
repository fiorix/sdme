{ pkgs ? import <nixpkgs> {} }:
let
  nixos = import "${pkgs.path}/nixos" {
    configuration = { config, lib, pkgs, ... }: {
      boot.isContainer = true;
      services.dbus.enable = true;
      users.users.root.initialHashedPassword = "";
      networking.useNetworkd = true;
      environment.systemPackages = with pkgs; [
        bashInteractive coreutils util-linux iproute2
        less procps findutils gnugrep gnused curl
      ];
      fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
      boot.loader.grub.enable = false;
      services.resolved.enable = false;
      services.getty.autologinUser = "root";
      # Disable pam_lastlog2 for machinectl shell (container-shell PAM service)
      # and login: the module has linkage issues in nspawn containers.
      security.pam.services.login.rules.session.lastlog.enable = lib.mkForce false;
      security.pam.services.container-shell.rules.session.lastlog.enable = lib.mkForce false;
      system.stateVersion = lib.trivial.release;
      nix.nixPath = [ "nixpkgs=${pkgs.path}" ];
    };
  };
in nixos.config.system.build.toplevel
