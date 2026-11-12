# BoJangles signed update channels

## 0.2.0 stable release — date-free channel active

Follow [the verified migration instructions](MIGRATION.md). The compatible build is `public-release-20261109-update-choices-local`, version 0.2.0. Other builds can share the version number without supporting the new release chooser. [BoJangles 0.2.0 is published](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.2.0). All five public assets matched their verified originals; the signed feed, safe extraction, complete inventory and runtime checks passed in isolated storage.

| Endpoint | Format and status |
| --- | --- |
| `stable.json` | Legacy schema 1; existing announcement is expired. Preserved for older clients. |
| `stable-v2.json` | Active schema 2; no calendar expiration; sequence 2026110901. |

Existing clients reject schema 2. Bootstrap through the published complete verified installer; do not overwrite the legacy endpoint with an incompatible format. Expiration affects the old announcement, not installed software or canonical source. The old weekly renewal automation remains paused.

## Publisher trust

- Public verification key (Base64): `gFDsD9ed7SjCJchRi0QaQDfzSZolsTEKbwMdEwbVT4o=`
- SHA-256 fingerprint: `47124e39d5ac236de15fb0d72a3b1516b55fd9b92c3856655a0af303f777045a`

Verify this key through a publisher channel you already trust. A key supplied only by an unverified feed does not authenticate it. The private signing seed remains local and is never a repository or release asset. No key rotation is required for migration.

## Update behavior

Automatic checks run at most daily while BoJangles is open. Check for updates runs immediately. No permanent updater service is installed. Signatures, HTTPS, archive size and SHA-256, safe extraction, full publication inventory and runtime prerequisites remain required. Downloads and installation require separate explicit actions; installation waits until all browser windows close and retains the predecessor.

The schema 2 client shows the most recent release prominently as Recommended and selects it by default. Older signed choices show their own notes and do not download on selection. Offer only compatibility-qualified alternatives. Selecting an older release does not lower the publisher sequence high-water mark.

Schema 2 has no calendar expiry. Legacy schema 1 retains its original maximum seven-day validity and rejects expired metadata. Never disable validation or reset replay state to force a migration. A client that has never seen a newer announcement cannot detect withholding of a valid older announcement.

## Publication order

Publish the qualified complete application, matching complete source, checksums and qualification record first. Verify downloaded public bytes, then sign and publish the new feed last. Bind each increasing sequence to the exact release identity and digests. The schema 2 signer must write to `stable-v2.json`, not the legacy endpoint. Sign when the approved catalogue changes; do not resume the former weekly expiry-renewal instructions. See [release intake and publication](../RELEASE-PROCESS.md).

The historical [October update release](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.1.0-updates.20261030) remains available. This private archive updater does not upgrade a system Debian package automatically. [The 0.2.0-1 Debian package](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.2.0) is available separately with complete matching source and checksums. Its updates and removal use APT; this signed archive channel does not overwrite the root-owned system package.

For compatible clients, configure `https://raw.githubusercontent.com/EndUserOnly/BoJangles/main/updates/stable-v2.json` with the unchanged public key above. The initial catalogue offers the latest qualified build only; older alternatives will be added only after installation/restore compatibility is qualified.
