# Release intake and publication

## Current preparation status — 9 November 2026

BoJangles 0.2.0 is compiled, qualified and installed on the owner’s system. Build identity: `public-release-20261109-update-choices-local`; maintained stable engine: WPE WebKit 2.54.2. This is a preparation record, not a public download announcement. The published November 2 packages remain 0.1.0-2. No 0.2.0 Debian package is claimed.

The obsolete October 0.1.0 workflow is preserved in `.github/legacy-workflows/build-update.yml`, outside GitHub’s active workflow directory. Do not restore or run it against current work. Its old baseline, publication target and 90-minute cutoff do not implement this process.

## Canonical rules

- Local source remains canonical. Completed, verified work waits for the owner’s explicit compile decision. Repository updates do not authorize compilation, installation, launcher changes or publication.
- Authorized compiles use four jobs. Do not impose an arbitrary cutoff on a progressing compile.
- Browser verification precedes further publication automation. Repository preparation must not trigger a build or publish a feed.
- BoJangles follows stable WPE releases only. Assess the complete upstream changes, security advisories, maintained patches, dependencies, compatibility and regressions before integration. No development, beta, RC or nightly engine releases.
- Include all applicable available security updates in the engine, bundled components and required external runtime dependencies. Unresolved applicable security fixes block promotion.

## Intake gates, in order

1. Freeze the exact qualified application source and maintained engine inputs. Review the public snapshot for private profiles, credentials, owner notes, recordings, caches and optional downloaded models. Exclude them.
2. Reconcile repository source, scripts, tests and public documentation with that qualified snapshot. Preserve historical release records as historical. Do not label the existing overlay tree as the full 0.2.0 source.
3. Assemble and verify complete corresponding source, including the matching upstream engine source, maintained changes, build instructions, dependency records and license notices. GitHub-generated source archives and application wheels alone are insufficient.
4. Prepare a draft release with a unique version/build tag referring to the reviewed source commit. Attach the complete application archive, complete corresponding source, SHA-256 checksums, inventory/manifest and qualification summary. Do not substitute transient Actions artifacts for release assets.
5. Download the draft assets and verify archive size, hashes, manifest identity, inventory, extraction and documented installation instructions. Keep the predecessor and preserve user data. Record limitations accurately.
6. Obtain the owner’s publication decision. Publish the verified assets first. Never replace an existing asset with different bytes under the same release identity.
7. Verify public download URLs, then sign and publish the update feed last. Record source commit/tag, release asset identities, hashes, feed sequence and publication checks. Keep the signing seed private and local.

## Update feed contract and migration

The qualified 0.2.0 client supports a signed schema 2 stable catalogue. Its envelope remains base64 `payload` plus an Ed25519 `signature`. The decoded payload contains `schema: 2`, `channel: "stable"`, a newest `release`, and optional older `releases`. Schema 2 has no `issued` or `expires` deadline. Publication dates remain informational.

Each entry binds its release identity, increasing sequence, version, date, notes, HTTPS archive URL, byte size, archive SHA-256 and publication-manifest SHA-256. Older choices have unique lower sequences. Signature, integrity and replay protections remain enforced. The newest release is prominent, recommended and selected by default; choosing an older release shows that release’s notes and requires an explicit download/install action.

Legacy schema 1 retains its original expiry checks. Older public clients do not accept schema 2. Do not silently replace the legacy feed before documenting and verifying the migration/install path. The current legacy feed has not been renewed or converted by this preparation. The former weekly expiry-renewal automation remains paused.

## Remaining 0.2.0 publication blockers

- Sanitized source reconciliation and complete corresponding-source archive.
- Draft release assets, public installation instructions and download verification.
- Explicit migration plan for legacy clients before switching the live feed.
- Owner publication decision after review.

No new engine build is required merely to publish the already qualified application. Before the next engine upgrade, reconcile the engine packaging/build-type checks with the production build configuration and complete the full stable-release/security assessment.
