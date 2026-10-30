# BoJangles signed update channel

This directory contains release metadata, not executable code. GitHub hosts it;
the locally pinned Ed25519 publisher key authorizes an update.

In BoJangles, open **Updates** and enter these values in its inline settings:

- Publisher HTTPS feed: `https://raw.githubusercontent.com/EndUserOnly/BoJangles/main/updates/stable.json`
- Publisher public key (Base64): `gFDsD9ed7SjCJchRi0QaQDfzSZolsTEKbwMdEwbVT4o=`
- Public key SHA-256 fingerprint: `47124e39d5ac236de15fb0d72a3b1516b55fd9b92c3856655a0af303f777045a`

Obtain and verify the key through a publisher channel you already trust before
pinning it. A key supplied only by an unverified feed does not authenticate it.
The publisher's private signing seed is not in this repository or release assets.

Automatic checks run at most daily while the main browser is open. No updater
service, permanent worker or new dependency is installed. **Check for updates**
checks immediately. **Download update** verifies the signature, file size,
SHA-256, safe archive layout, complete inventory and runtime requirements.
**Install when BoJangles closes** queues the release; the last browser to close
applies it. The previous application is retained for rollback.

A single manual check on the current release reports no new update. **Preview
notification** is explicitly an example and cannot install. Full update tests
use a separate temporary profile and the real signed GitHub release.

Feed metadata expires at most seven days after signing. The publisher must
re-sign and republish it before expiry even when the release is unchanged.
Clients reject expired metadata; offline/expired checks do not authorize an
installation. There is no automatic signing service in this repository.

For a new release, publish the complete qualified Linux archive, corresponding
source and checksums first. Sign metadata only after its public asset hashes and
sizes match the qualified local artifacts. Increment the release sequence for
every changed archive. Refreshing the same release preserves its sequence,
identity and archive digest. The existing `scripts/sign-update-feed.py` tool in
the full source archive signs metadata using an owner-only 0600 seed file.
Commit the new signed envelope to `updates/stable.json` last. Never commit the
private seed. Key rotation requires an authenticated out-of-band client settings
change; replacing this public key file alone does not change client trust.

The public Linux release and complete source are at
[the update release](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.1.0-updates.20261030).
The original v0.1.0 assets remain available. This channel does not modify the
system Debian package automatically; it uses BoJangles' existing private release
installer. WPE and the canonical engine selection syntax remain unchanged.
