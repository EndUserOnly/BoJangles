# BoJangles

## Latest stable release — BoJangles 0.2.0

**[Download BoJangles 0.2.0](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.2.0)** — published November 9, 2026 for Ubuntu 24.04-compatible Linux x86_64. Build: `public-release-20261109-update-choices-local`. Includes the redesigned Media Center, qualified recording work and date-free signed update release choices with the newest release prominently Recommended.

The release provides the complete application archive, complete corresponding application/engine source, SHA-256 checksums and qualification records. Verify the files before installation and follow the release instructions. **No new 0.2.0 Debian package is supplied.**

[Update-channel migration](updates/MIGRATION.md) · [Release process and stable-only WPE policy](RELEASE-PROCESS.md). The named complete source release asset is authoritative; GitHub-generated archives contain this control/source-overlay repository. The old automatic build/publish workflow remains archived.

![BoJangles Home and browser controls](bojangles-home.png)

## Command control sheet

[Download the approved BoJangles Command Control Sheet](BoJangles-Final-Command-Sheet-2026-10-28.docx)

BoJangles is a Linux Internet browsing suite with a native browser, crawler, independently controlled media windows and Media Center Library. Media workflows include recording, translation and transcription; optional models are obtained separately.

## Previous Debian and archive release — November 2, 2026

[Download BoJangles 0.1.0-2](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.1.0-deb.20261102): `bojangles_0.1.0-2_amd64.deb`, complete corresponding `BoJangles-0.1.0-2-deb-source.tar.gz`, checksums and validation. Verify `DEB-20261102-SHA256SUMS.txt`, then install with `sudo apt install ./bojangles_0.1.0-2_amd64.deb`.

This newly assembled Debian package contains the qualified November 2 application and November 1 resource/upload engine, including header/bookmark visibility, explicit media playback and crawler timeout/progress fixes. It reuses the qualified compiled payload; no new application/engine compile was needed. Uncompiled diagnostic staging and the withdrawn crawler proposal are excluded.

Ubuntu 24.04-compatible amd64. APT resolves 140 declared prerequisites. Qualification passed isolated APT install/reinstall/remove with user-data preservation, seven non-root commands, 144 maintenance probes, all 128 ELF checks and 12 focused source/package regressions. See `DEBIAN.md` and `DEB-20261102-VALIDATION.md`. Existing private installations can take command precedence; `/usr/bin/bojangles` selects the Debian installation. The signed archive update feed remains separate. Complete application/engine source is the named release asset; GitHub-generated source archives contain this control repository.

### Linux x86_64 archive

The same [previous release](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.1.0-deb.20261102) also provides `BoJangles-0.1.0-20261102-linux-x86_64.tar.gz`. Verify it against `X86_64-20261102-SHA256SUMS.txt`, extract with `tar -xzf BoJangles-0.1.0-20261102-linux-x86_64.tar.gz`, then run:

```sh
python3 public-release-20261102-media-crawler-local/runtime_dependencies.py public-release-20261102-media-crawler-local
python3 public-release-20261102-media-crawler-local/install-public-release.py public-release-20261102-media-crawler-local --sha256 72f8fa8223ba869686b675c3057b10e5e10352affd7be595acd6ec492fc9417c
bojangles open
```

The archive installer uses the private release store and retains the predecessor. Satisfy any missing system prerequisites before installation; the archive does not install APT packages. The already-published `BoJangles-0.1.0-2-deb-source.tar.gz` is the complete matching application/engine source for both packages. Both contain the same qualified command and engine; neither includes uncompiled diagnostic or rejected crawler work. See the attached x86_64 validation records. Existing private and system installations remain separate.

## Native updates and webpage snapshots

[Download the qualified update release](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.1.0-updates.20261030). Its complete application, matching source and checksums are separate release assets. The original first release remains below.

Use [the signed update channel](updates/README.md) to configure the trusted publisher. Automatic checks run while BoJangles is open; downloads and installation require your approval. No new dependency, service or launch wrapper is added. WPE remains the default.

For a fresh private installation, verify the archive using the release's GITHUB-UPDATES-SHA256SUMS.txt, extract it, then run:

```sh
python3 public-release-20261030-github-updates/install-public-release.py public-release-20261030-github-updates --sha256 37fd875f0d7e76a02399f5f4b56a3fb217da55f3bd26353d7dc1bf09c54968a3
bojangles open
```

Webpage-only Save Snapshot offers full-page PNG, PDF, MHTML and HTML + Resources ZIP. PNG is one file; the extracted HTML ZIP includes its resources folder. Capture uses the current WPE page. See the release notes for limits and qualification.

## First release

[Download release v0.1.0](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.1.0)

- [Linux x86-64 package](https://github.com/EndUserOnly/BoJangles/releases/download/v0.1.0/BoJangles-0.1.0-linux-x86_64.tar.gz)
- [Complete corresponding source and build instructions](https://github.com/EndUserOnly/BoJangles/releases/download/v0.1.0/BoJangles-0.1.0-source.tar.gz)
- [SHA-256 checksums](SHA256SUMS.txt)

Use the **BoJangles-0.1.0-source.tar.gz** release asset for the complete application, maintained engine source, build scripts and notices. GitHub's automatically generated source archives contain this control repository, not that complete source distribution.

The qualified platform is Ubuntu 24.04-compatible Linux x86-64 with maintained WPE WebKit 2.54.2. Tk is the default frontend; GTK remains a preview. HTML5 profile is LIMITED. Preserve the complete application and matching engine bundle. No developer home, private profiles, credentials, recordings or models are included.

## Install

Verify the downloaded archives against SHA256SUMS.txt, then extract the Linux package and run:

```sh
python3 public-release-20261028/install-public-release.py public-release-20261028 --sha256 2490e5d9daf89396a566fea2ddb4f69487e98de48ea65a4ce202c04f144de0cf
bojangles open
```

The installer verifies the whole inventory, retains the predecessor, and does not start services or restart existing sessions. Open a fresh instance to use newly installed code.

## Verification

The owner cleared this exact compile for publication. Four-job compilation completed; 113 qualification executions, two installer checks and five production/native policy checks passed. The installed maintenance check passed 144 blocking probes with no failures. Actual compiled Library rename/error/retry/content-preservation checks passed. The complete reconstructed engine source has 26 authenticated maintained inputs and no unexplained differences against 39,104 retained source inputs apart from the declared override.

Executable SHA-256: `f502f0faf405fe9ad41f237057f08886e152ae0daa84c9849bdef8a4f0580764`.

The unchanged qualified WebKit library is retained; no fresh whole-WebKit or byte-reproducible clean-machine engine compilation is claimed. This is scoped technical qualification, not a universal website/media/printer or unknown-vulnerability guarantee. Build-time pending-owner status in the archive is superseded by the owner's subsequent publication approval recorded with the release.

## License

Original BoJangles code is **GPL-3.0-or-later**. See [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md). Third-party components retain their own licenses and notices.

Brought to you from the creators of torrent-get:

- Teop Versant — Design Engineer
- Ness — Design and coding
