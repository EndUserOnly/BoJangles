# BoJangles Debian 0.1.0-2 validation

Built November 2, 2026 for Ubuntu 24.04-compatible amd64. Package assembly uses the exact qualified public-release-20261102-media-crawler-local standalone application, wheel and authenticated WPE engine. No application/engine compile, host installation, launcher change or browser restart was performed for this publication.

- 177 application source files match the qualified compile's recorded SHA-256 values; 29 maintained engine inputs match the recipe. Uncompiled diagnostic staging and rejected crawler-accuracy work are excluded.
- Command SHA-256: d1238b6db77f9d4a0a037a98231a0b8037689c1f0ad6916869878b9e3a8ec962.
- 12 focused source/package regressions passed in isolated HOME/XDG stores.
- Host release audit: all 128 ELF files resolve libraries, with no undeclared providers.
- Disposable Ubuntu 24.04 runtime container: APT installed the package and fetched missing declared prerequisites from configured Ubuntu repositories. The package declares 140 prerequisites. An initial offline attempt correctly reported unavailable prerequisite archives; the connected APT run passed.
- Seven non-root compiled commands passed: help, version, status, search help, advertising rules, media status and maintenance. Maintenance reports 144 blocking probes, no failures/errors.
- Installed-container audit: all 128 ELF files resolve libraries with no undeclared providers. Direct libmpv2/libimagequant loading passed.
- dpkg file verification, APT reinstall, second file verification, removal and user-data sentinel preservation passed. The host installation and personal profiles were not mounted into the container.

This is installer/runtime qualification on an existing Ubuntu 24.04 test image, not a fresh empty operating-system certification or universal website/media/upload compatibility claim. The approved feature build's prior compiled/native acceptance remains historical evidence; this publication performs focused packaging qualification. The signed archive-update feed is separate and is not changed by this Debian release. No services, maintainer scripts, timers, profiles, credentials or models are installed by the package.

See accompanying JSON records for exact commands and results. Verify the release checksums before installation. Complete corresponding source, build scripts and component notices are in BoJangles-0.1.0-2-deb-source.tar.gz.
