{ pkgs ? import <nixpkgs> {} }:

# Usage:
#   nix-shell          — enter the dev environment
#   nix-shell --run 'sudo python3 howler.py --help'
#
# Note: masscan and nmap need root. Inside nix-shell, run:
#   sudo $(which masscan) ...   (uses the nix-store binary, not /usr/bin)
#
# Tools NOT in nixpkgs (skip or install separately):
#   joomscan       — no nix package; grab from GitHub
#   smtp-user-enum — no nix package; use python venv inside this shell

let
  # Python with the two required library deps baked in.
  # This replaces both "pip install pyyaml rich" and the --install-prereqs flag.
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    pyyaml
    rich
  ]);

in pkgs.mkShell {
  name = "howler";

  packages = with pkgs; [
    # ── Python runtime ─────────────────────────────────────────────────
    pythonEnv

    # ── Core (required) ────────────────────────────────────────────────
    masscan
    nmap

    # ── HTTP ───────────────────────────────────────────────────────────
    nikto
    whatweb
    python3Packages.wafw00f
    wpscan
    gowitness
    ffuf

    # ── SSL/TLS ────────────────────────────────────────────────────────
    testssl          # testssl.sh — installed as `testssl` in nixpkgs

    # ── SSH ────────────────────────────────────────────────────────────
    ssh-audit

    # ── DNS ────────────────────────────────────────────────────────────
    dnsrecon

    # ── SMB ────────────────────────────────────────────────────────────
    enum4linux-ng

    # ── SMTP ───────────────────────────────────────────────────────────
    # smtp-user-enum is not in nixpkgs.
    # Workaround inside this shell:
    #   python3 -m venv /tmp/howler-extras && \
    #   /tmp/howler-extras/bin/pip install smtp-user-enum && \
    #   export PATH="/tmp/howler-extras/bin:$PATH"

    # ── IKE ────────────────────────────────────────────────────────────
    ike-scan

    # ── NFS ────────────────────────────────────────────────────────────
    nfs-utils        # provides showmount

    # ── Brute force (--brute) ──────────────────────────────────────────
    thc-hydra        # installed as `hydra` on other distros; binary name stays `hydra`

    # ── Metasploit (optional — large, comment out if not needed) ───────
    # metasploit
  ];

  shellHook = ''
    echo ""
    echo "  Howler nix-shell ready."
    echo "  python3 --version: $(python3 --version)"
    echo "  Run: sudo python3 howler.py <target> [flags]"
    echo ""
  '';
}
