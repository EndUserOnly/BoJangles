# BoJangles 0.2.0-1 Debian package

For Ubuntu 24.04-compatible Linux amd64, including Pop!_OS 24.04. Download bojangles_0.2.0-1_amd64.deb and verify it against DEB-0.2.0-1-SHA256SUMS.txt from the published release. Install using APT so prerequisites are resolved:

```sh
sudo apt install ./bojangles_0.2.0-1_amd64.deb
/usr/bin/bojangles open
```

Save work and close BoJangles before upgrading. APT shows proposed changes before confirmation. The package installs the complete application and qualified stable WPE WebKit 2.54.2 engine under /usr/lib/bojangles/releases/public-release-20261109-update-choices-local. /usr/bin/bojangles directly selects that command; the system desktop entry uses it and includes the application icon. The already-compiled application supports system release authority; application and engine bytes are reused unchanged from the qualified November 9 update-choice build. No new compile is claimed or needed for this packaging revision.

Existing private installations and user data are preserved. ~/.local/bin/bojangles can take precedence for the bare command, and a private desktop entry can shadow the system entry. Use /usr/bin/bojangles explicitly to select the Debian package. Packaging does not change a private launcher or profile. No maintainer scripts, services, timers or persistent workers are installed. Installation does not launch the application. Models and GTK preview remain optional; Cameras remains in development.

Debian package updates/removal use APT. The signed archive-update channel remains separate and must not be used to overwrite the root-owned system installation. Removal leaves profiles, recordings, downloads, models and private installations intact.

The complete matching source is BoJangles-0.2.0-1-deb-source.tar.gz. The package retains the exact application/engine source already qualified for public-release-20261109-update-choices-local; this source distribution adds the corrected packaging recipe and current Debian instructions. GitHub-generated source archives contain the control/source-overlay repository only. See BUILDING.md for application/engine build inputs.

To reproduce packaging from a verified complete archive, run scripts/build-deb.py with --release, --release-manifest-sha256, --stage and --output. The source root supplies version, prerequisite declarations, notices and these instructions. Use new output paths outside source. The recipe authenticates the whole input inventory, derives the pinned release identity, preserves compiled bytes, seals the system package inventory and records application_recompiled=false and engine_recompiled=false. No compiler is invoked.
