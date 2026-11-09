# Migrating to the date-free BoJangles update channel

Status, November 9, 2026: **BoJangles 0.2.0 is published and the date-free update channel is active.** [Download the verified stable release](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.2.0). Its five uploaded assets were downloaded publicly and matched the qualified originals. Use the exact build below; version alone is insufficient.

## Supported transition

Keep `updates/stable.json` as the legacy schema 1 endpoint. Use `updates/stable-v2.json` for the active date-free schema 2 channel. Its signed contents and public download assets have been verified. This avoids sending a format that existing clients reject to their configured endpoint.

The legacy announcement is expired. Expiration applies to the announcement, not the source code or an installed application. Do not change the clock, suppress validation, or revive the obsolete weekly renewal automation. This migration uses the complete verified installer to bootstrap compatible clients; it does not require a renewed legacy announcement.

## Identify the compatible build

The migration target is **0.2.0**, build **`public-release-20261109-update-choices-local`**, using maintained stable WPE WebKit 2.54.2.

| Artifact | Required value |
| --- | --- |
| Application archive | `BoJangles-0.2.0-20261109-update-choices-compiled.tar.gz` |
| Archive bytes | `330108900` |
| Archive SHA-256 | `8274b9d93771bcbd3d10815045bd5cdc7d584027d5a5c088e70c3c3692696d0f` |
| Publication-manifest SHA-256 | `08d8d866cc273c58cdef75fa7219cb27db6c7b4b0b16f5446b4a8e75843f01a6` |

The earlier `public-release-20261109-source-reconciled-local` build also reports 0.2.0 but is not this update-choice build. Version alone is insufficient. No new 0.2.0 Debian package is supplied by this procedure.

## Manual bootstrap

1. Download the exact archive above, its published checksum record and the complete corresponding-source archive from the verified 0.2.0 GitHub release. [Open the published release](https://github.com/EndUserOnly/BoJangles/releases/tag/v0.2.0).
2. Verify the archive before extraction:

```sh
printf '%s  %s\n' '8274b9d93771bcbd3d10815045bd5cdc7d584027d5a5c088e70c3c3692696d0f' 'BoJangles-0.2.0-20261109-update-choices-compiled.tar.gz' | sha256sum --check -
tar -xzf BoJangles-0.2.0-20261109-update-choices-compiled.tar.gz
```

3. From that extraction directory, check the complete inventory and runtime prerequisites:

```sh
python3 -B public-release-20261109-update-choices-local/install-public-release.py public-release-20261109-update-choices-local --sha256 08d8d866cc273c58cdef75fa7219cb27db6c7b4b0b16f5446b4a8e75843f01a6 --check
python3 -B public-release-20261109-update-choices-local/install-public-release.py public-release-20261109-update-choices-local --sha256 08d8d866cc273c58cdef75fa7219cb27db6c7b4b0b16f5446b4a8e75843f01a6 --check-runtime
```

Resolve any reported system prerequisites using the included runtime documentation. Save work and close BoJangles before switching the installation.

4. Install as your ordinary user, without `sudo`:

```sh
python3 -B public-release-20261109-update-choices-local/install-public-release.py public-release-20261109-update-choices-local --sha256 08d8d866cc273c58cdef75fa7219cb27db6c7b4b0b16f5446b4a8e75843f01a6
"$HOME/.local/bin/bojangles" open
```

The installer changes the private command and retains its predecessor. It refuses to overwrite an existing release identity. If this exact build is already installed, verify that installation rather than deleting it or reinstalling over it. On systems with both Debian and private installations, launch the private command above; `/usr/bin/bojangles` still selects the Debian installation. A desktop launcher must select the private command to use this release.

## Configure the active date-free channel

Open **Updates** in a fresh instance. Its Installed identity must be `public-release-20261109-update-choices-local`.

Enter the following in the inline publisher controls:

- Publisher HTTPS feed: `https://raw.githubusercontent.com/EndUserOnly/BoJangles/main/updates/stable-v2.json`
- Publisher public key (Base64): `gFDsD9ed7SjCJchRi0QaQDfzSZolsTEKbwMdEwbVT4o=`

Keep the existing publisher key; do not rotate or relocate its private signing seed. Select **Save settings**, then **Check for updates**. The most recent release must appear prominently as Recommended and be selected by default. Choosing another signed release shows its notes; it does not download or install it. Download and installation require separate actions. If the recommended build is already installed, a disabled download action is expected.

Only include older choices after their actual installation/restore compatibility is qualified. The initial catalogue may contain just the latest release. Do not offer an older schema 1-only client as an alternative without documenting how it returns to a compatible channel.

Schema 2 removes calendar expiration while retaining signature, HTTPS, archive size/hash, inventory and learned-sequence replay checks. Do not clear replay state to force an older announcement to pass. A machine that has never seen a newer announcement still cannot detect withholding of a valid older announcement.

## Publisher activation gates

1. Reconcile the public source snapshot with this exact build and verify the complete corresponding-source package, licenses and build instructions.
2. Prepare and verify the draft release assets. Download them again and compare their bytes and digests. Publish the reviewed release with owner authorization.
3. Use the verified public application URL and values above to create a schema 2 catalogue, with a new sequence greater than the existing legacy head `2026103001`. Keep one sequence bound to one exact release identity and digests.
4. Sign locally with the existing publisher key; publish only the signed envelope at `updates/stable-v2.json`. Never upload the signing seed. Leave the legacy endpoint intact.
5. Fetch the public new endpoint and verify its signature, schema, sequence and advertised archive. Exercise download and extraction in isolated HOME/XDG storage. Only then mark this guide activated and direct users to configure the new URL.

Activation record: stable release `v0.2.0` published at repository commit `531be9daee36481a8574dde56684654c0a460031`; signed schema 2 sequence `2026110901`. All five public assets match their local digests. The existing publisher key signed the new announcement locally; its private seed was not uploaded. No new compile, owner installation, launcher switch or owner-profile migration was performed during publication. The source archive retains its preparation-time documentation; this repository guide supplies the current channel status.
