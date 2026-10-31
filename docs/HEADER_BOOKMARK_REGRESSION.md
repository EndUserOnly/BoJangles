# Bounded response headers and bookmark visibility

The requested YouTube watch page returned valid HTTP 200 metadata that exceeded
the shared 16 KiB header budget. The actual BoJangles request reproduced the
failure with 33 headers totaling approximately 19 KiB. Several independent
reporting-policy fields accounted for most of the size.

Responses now have a separate 32 KiB aggregate limit in the trusted sanitizer,
both document/resource response senders and both native receivers. Requests
retain 16 KiB. Header count, individual value limits, injection rejection,
cookie authority, sealed body descriptors and CONTROL/RESOURCE isolation remain
unchanged. Policies are preserved without truncation or site-specific behavior.

A successful bookmark save could leave another browser's already-visible list
stale. Visible lists now refresh after a save and on window focus when the
persistent store has changed. Unchanged stores preserve row identity and
selection. Page navigation remains independent. No polling worker is added.

Source qualification covered exact response-budget acceptance, one-byte-over
rejection, unchanged request limits, malformed headers, sealed response metadata,
GET/POST fidelity, cookies, file-descriptor ownership, bookmark folder/CLI
behavior, primary/secondary save dialogs, fresh-process persistence, focus
refresh, and same-window/nested double-click navigation. Tests use temporary
HOME and XDG roots through scripts/run-isolated-tests.py. Personal bookmark
bytes were verified unchanged.

Anonymous live checks rendered visible content and expected titles at the
requested YouTube URL, 1984.hosting and WordPress.org. The YouTube player was
still loading; playback, authentication and WordPress administration are not
certified. Source qualification against the published baseline passed 22 checks.
GitHub reruns source/native checks, compiles with four jobs, audits the runtime,
checks the compiled commands and uses the native updater's archive verifier.

The build workflow reconstructs the full build tree from the checksum-pinned
published source distribution and the directly maintained source files in this
repository. It builds a complete native application and broker; the qualified
WebKit engine is retained. No application patch bundle or launch wrapper is used.

Updates are delivered through the existing signed GitHub feed. Assets are
published only after qualification; the feed is signed separately after the
published archive's size and checksums have been verified. The private signing
key is never supplied to GitHub Actions. Installation remains an explicit user
operation through BoJangles Updates and retains the prior release for rollback.
