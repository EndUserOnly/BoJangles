# Debian package (Ubuntu 24.04-compatible amd64)

Download bojangles_0.1.0-2_amd64.deb and verify it against DEB-SHA256SUMS.txt from the release. Install using APT so declared prerequisites are resolved:

    sudo apt install ./bojangles_0.1.0-2_amd64.deb

APT displays its proposed package changes before asking for confirmation. This package targets Ubuntu 24.04-compatible systems, including Pop!_OS 24.04, rather than arbitrary Debian versions.

Use the BoJangles desktop entry, or run /usr/bin/bojangles. An existing ~/.local/bin/bojangles can take precedence when typing the bare command; the Debian package does not change private installations or user profiles.

The package installs the complete application and pinned engine under /usr/lib/bojangles/releases/public-release-20261102-media-crawler-local, plus a direct executable symlink in /usr/bin and a desktop entry. Code executing from that package tree uses its root-owned engine authority and selection; tar-based installations retain their private release selection. The native engine manifest and its authenticated contents are unchanged. The package reuses the November 2 qualified application binary, which already supports the system package layout. No application or engine compile is performed for this packaging revision.

No maintainer scripts, services, timers or persistent workers are installed. Package installation does not launch the app. GTK4 preview and translation/transcription models remain optional. Updates and removal use APT; user recordings, profiles and private installations are not package-owned files.

The matching BoJangles-0.1.0-2-deb-source.tar.gz contains complete corresponding source and packaging scripts. Build the standalone application with the documented four-job procedure, build its wheel, then invoke scripts/build-deb.py with explicit --release (verified corrected tar release), --bundle (complete rebuilt Nuitka .dist), --wheel, --report (Nuitka compilation report), --stage (new directory outside source) and --output (new .deb path outside source). Never build into canonical source. The Debian package recipe intentionally retains the engine identity pinned by the application.
