"""BoJangles command-line control surface."""
from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import sys
from urllib.parse import urlsplit

from .bookmarks.html_store import Bookmark, BookmarkFolder, SandboxBookmarkStore
from .config import (
    DEFAULT_PATH,
    ConfigError,
    load,
    reset_crawler,
    reset_filter,
    save,
    update_crawler,
    update_filter,
)
from .crawler.config import CrawlerConfigError
from .crawler.index import AgeIndex


class _ChawanEngineAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not getattr(namespace, "target", None):
            parser.error("put the website before --engine chawan")
        if getattr(namespace, self.dest, None) is not None:
            parser.error("choose --engine only once")
        setattr(namespace, self.dest, values)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bojangles",
        description="BoJangles lightweight browser and age-qualified crawler",
    )

    sub = p.add_subparsers(dest="command")
    from .maintenance.cli import add_parser as add_maint_parser
    add_maint_parser(sub)

    from .media.center import add_parser as add_media_parser
    add_media_parser(sub)

    popups = sub.add_parser("popup", help="per-site popup window policy")
    popup_sub = popups.add_subparsers(dest="popup_action", required=True)
    for action in ("show", "mode", "reset"):
        item = popup_sub.add_parser(action)
        item.add_argument("site", help="source page HTTP or HTTPS origin")
        if action == "mode":
            item.add_argument("mode", choices=("balanced", "strict"))

    rules = sub.add_parser("popup-rules", help="trusted persistent site blocking rules")
    rules.add_argument("action", choices=("list", "add", "remove", "clear"))
    rules.add_argument("site")
    rules.add_argument("selector", nargs="?")

    ads = sub.add_parser("advertising", help="Balanced advertising preferences; Strict unavailable")
    ads.add_argument("action", choices=("show", "rules", "mode", "allow", "remove", "reset"))
    ads.add_argument("site", nargs="?")
    ads.add_argument("value", nargs="?")
    sub.add_parser("status")
    sub.add_parser("init-config")

    open_p = sub.add_parser(
        "open",
        help="open the BoJangles landing page or an HTTP/HTTPS destination",
    )
    open_p.add_argument("target", nargs="?", help="website to open directly (omit for the landing page)")
    open_p.add_argument("--engine", choices=("chawan",), default=None,
                        action=_ChawanEngineAction,
                        help="select the independent Chawan development pipe after the website")
    open_p.add_argument("--diag", action="store_true",
                        help="record a bounded redacted network diagnostic ledger")
    open_p.add_argument("--frontend", choices=("tk", "gtk"), default="tk", help="window frontend (GTK preview)")
    open_p.add_argument("--wpe-windows", action="store_true", help="use WPE with BoJangles multiple-window media chrome")
    open_p.add_argument("--chawan-step22", action="store_true", help="run the opt-in multiple-window candidate")
    open_p.add_argument("--chawan-step21", action="store_true", help="run the opt-in native media window candidate")
    open_p.add_argument("--chawan-step20", action="store_true", help="run the opt-in media candidate broker")
    open_p.add_argument("--chawan-step19", action="store_true", help="run the opt-in BoJangles surface and input candidate")
    open_p.add_argument("--input-candidate-v3", action="store_true", help="run the corrected nonproduction input candidate")
    open_p.add_argument("--input-candidate-v2", action="store_true",
                        help="run the nonproduction single-reader input candidate")

    bookmarks = sub.add_parser(
        "bookmarks",
        help="list and manage trusted bookmarks",
    )
    bookmarks_sub = bookmarks.add_subparsers(dest="bookmarks_command")
    bookmarks_list = bookmarks_sub.add_parser("list", help="list numbered bookmarks and unnumbered folders")
    bookmarks_list.add_argument("--page", type=int, default=1, help="999-bookmark page (default: 1)")

    bookmarks_add = bookmarks_sub.add_parser("add", help="add or update one HTTP/HTTPS bookmark")
    bookmarks_add.add_argument("url")
    bookmarks_add.add_argument("--title", help="bookmark title (default: hostname)")
    bookmarks_add.add_argument("--folder", default="", help="existing folder path, e.g. News/Local")

    bookmarks_show = bookmarks_sub.add_parser("show", help="show one bookmark by current list number")
    bookmarks_show.add_argument("number", type=int)
    bookmarks_show.add_argument("--page", type=int, default=1, help="bookmark list page (default: 1)")

    bookmarks_remove = bookmarks_sub.add_parser("remove", help="remove one bookmark by current list number")
    bookmarks_remove.add_argument("number", type=int)
    bookmarks_remove.add_argument("--page", type=int, default=1, help="bookmark list page (default: 1)")

    bookmarks_folder = bookmarks_sub.add_parser("folder", help="manage bookmark folders")
    folder_sub = bookmarks_folder.add_subparsers(dest="bookmark_folder_command", required=True)
    folder_add = folder_sub.add_parser("add", help="create a folder path")
    folder_add.add_argument("path")
    folder_remove = folder_sub.add_parser("remove", help="remove an empty folder path")
    folder_remove.add_argument("path")
    folder_remove.add_argument("--recursive", action="store_true",
                               help="remove a non-empty folder and all of its contents")

    bookmarks_import = bookmarks_sub.add_parser(
        "import",
        help="import bookmarks from an external HTML file",
    )
    bookmarks_import.add_argument("file", type=Path)

    passwords = sub.add_parser(
        "passwords",
        help="manage the trusted encrypted website password vault",
    )
    passwords_sub = passwords.add_subparsers(dest="passwords_command", required=True)
    passwords_add = passwords_sub.add_parser("add", help="add or replace one HTTPS login")
    passwords_add.add_argument("origin", help="HTTPS URL or bare hostname")
    passwords_sub.add_parser("list", help="list saved HTTPS origins without exposing credentials")

    sub.add_parser("version")
    sub.add_parser("help")

    diag = sub.add_parser("diag", help="capture and analyze BoJangles diagnostic ledgers")
    diag_sub = diag.add_subparsers(dest="diag_command", required=True)
    diag_sub.add_parser("open", parents=[open_p], add_help=False,
                        help="open the browser and capture diagnostics until it closes")
    diag_analyze = diag_sub.add_parser("analyze", help="analyze the latest redacted network ledger")
    diag_analyze.add_argument("--ledger", type=Path, help="analyze a specific JSONL ledger")

    upgrade = sub.add_parser("upgrade", help="inspect and stage one verified BoJangles release")
    upgrade_sub = upgrade.add_subparsers(dest="upgrade_command", required=True)
    upgrade_sub.add_parser("status", help="show the active selection and local candidate")
    upgrade_sub.add_parser("check", help="check the pinned local candidate manifest")
    verify_upgrade = upgrade_sub.add_parser("verify", help="verify every candidate package file")
    verify_upgrade.add_argument("--staged", action="store_true", help="verify the copied user release")
    upgrade_sub.add_parser("stage", help="copy the verified candidate without activating it")
    activate = upgrade_sub.add_parser("activate", help="select a verified release for new sessions")
    activate.add_argument("release_id", help="exact staged release identifier")
    activate.add_argument("--confirm", action="store_true", help="confirm the installed selection change")
    upgrade_sub.add_parser("apply-pending", help="apply an operator-queued update after browser exit")
    upgrade_sub.add_parser("rollback", help="restore the verified previous release for new sessions")

    search = sub.add_parser("search", help="bounded first-hand spider crawl in BoJangles")
    search.add_argument("query", nargs="+", help="text and/or media filename patterns to match")
    search.add_argument("--site", default="", help="seed and restrict the spider to a site")
    search.add_argument("--domain", default="", help="seed and restrict the spider to a domain and subdomains")
    search.add_argument("--path", default="", help="restrict result URL paths by prefix")
    search.add_argument("--seed", action="append", default=[], help="add an explicit live crawl seed URL")
    search.add_argument("--depth", type=int, default=2, help="spider link depth (0..8; default 2)")
    search.add_argument("--max-pages", type=int, default=30, help="maximum first-hand pages fetched (1..200)")
    search.add_argument("--recent", type=int, help="only return results with a usable date within the last N days")
    search.add_argument("--pdf", action="store_true", help="include AGE-qualified PDF results")
    search.add_argument("--exact", action="store_true", help="require the exact query text in returned content")
    search.add_argument("--contains", action="append", default=[], help="require text in returned content")
    search.add_argument("--exclude", action="append", default=[], help="exclude returned content containing text")
    search.add_argument("--same-site", action="store_true", help="follow only same-site links")
    search.add_argument("--outbound", action="store_true", help="allow followed links to leave a seed site")

    transcribe = sub.add_parser("transcribe", help="transcribe a local audio/video file to original-language text")
    from .transcription.cli import add_arguments
    add_arguments(transcribe)

    crawler_search = sub.add_parser(
        "crawler-search",
        help="search the local age-qualified crawler index",
    )
    crawler_search.add_argument("query", nargs="*", help="local crawler-index search terms")
    crawler_search.add_argument("--index", type=Path, help="crawler SQLite index (defaults to configured storage)")
    crawler_search.add_argument("--limit", type=int, default=20)
    crawler_search.add_argument("--text", action="store_true", help="print results without the graphical chooser")

    config = sub.add_parser("config")
    config_sub = config.add_subparsers(
        dest="config_command",
        required=True,
    )
    config_sub.add_parser("path")
    config_sub.add_parser("show")

    crawler = config_sub.add_parser("crawler")
    crawler_sub = crawler.add_subparsers(
        dest="crawler_command",
        required=True,
    )
    crawler_sub.add_parser("show")

    set_p = crawler_sub.add_parser("set")
    set_p.add_argument(
        "field",
        choices=(
            "backend",
            "max-depth",
            "concurrency",
            "obey-robots",
            "scope",
            "storage-dir",
        ),
    )
    set_p.add_argument("value")
    crawler_sub.add_parser("reset")

    filt = config_sub.add_parser("filter")
    filt_sub = filt.add_subparsers(
        dest="filter_command",
        required=True,
    )
    filt_sub.add_parser("show")

    filt_set = filt_sub.add_parser("set")
    filt_set.add_argument(
        "level",
        choices=("permissive", "balanced", "strict"),
    )
    filt_sub.add_parser("reset")


    return p


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _status() -> int:
    config = load(DEFAULT_PATH)

    _print_json(
        {
            "project": "BoJangles",
            "renderer_default": config.renderer.default_backend,
            "crawler_backend": config.crawler.backend,
            "crawler_config": "persistent",
            "content_filter": config.filter.level,
            "persistent_history": False,
            "daemon": False,
            "age_gate": "required",
        }
    )
    return 0


def _open(target: str | None, *, input_candidate_v2: bool = False, input_candidate_v3: bool = False, frontend: str = "tk", chawan_step19: bool = False, chawan_step20: bool = False, chawan_step21: bool = False, chawan_step22: bool = False, wpe_windows: bool = False, engine: str | None = None) -> int:
    if engine is not None:
        if engine != "chawan" or not target:
            raise ValueError("use bojangles open <website> --engine chawan")
        if any((wpe_windows, chawan_step19, chawan_step20, chawan_step21,
                chawan_step22, input_candidate_v2, input_candidate_v3)):
            raise ValueError("--engine cannot be combined with renderer candidate flags")
        if frontend != "tk":
            raise ValueError("Chawan video currently requires the Tk frontend")
        from .frontend.chawan_video import run_windowed as run_chawan
        return run_chawan(target)
    if (wpe_windows or chawan_step21 or chawan_step22) and frontend == "gtk":
        raise ValueError("Native media windows currently require the Tk frontend")
    if frontend == "gtk":
        try:
            from .frontend.gtk_session import run_windowed
        except (ImportError, ValueError) as exc:
            raise RuntimeError("GTK frontend requires PyGObject and GTK 4 in the Python environment") from exc
    else:
        from .frontend.window_session import run_windowed
    if wpe_windows:
        if chawan_step22 or chawan_step21 or chawan_step20 or chawan_step19 or input_candidate_v2 or input_candidate_v3:
            raise ValueError("choose only one opt-in window or renderer candidate")
        print("BoJangles: WPE with multiple-window media chrome.", flush=True)
        return run_windowed(target, multi_window=True)
    if chawan_step22:
        if chawan_step21 or chawan_step20 or chawan_step19 or input_candidate_v2 or input_candidate_v3:
            raise ValueError("choose only one opt-in renderer candidate")
        from .renderer.installed import chawan_step20_factory
        print("BoJangles: opt-in multiple-window candidate; foreground session only.", flush=True)
        return run_windowed(target, renderer_factories={"chawan": chawan_step20_factory()},
                            renderer_name="chawan", multi_window=True)
    if chawan_step21:
        if chawan_step20 or chawan_step19 or input_candidate_v2 or input_candidate_v3:
            raise ValueError("choose only one opt-in renderer candidate")
        from .renderer.installed import chawan_step20_factory
        print("BoJangles: opt-in native media windows; foreground session only.", flush=True)
        return run_windowed(target, renderer_factories={"chawan": chawan_step20_factory()}, renderer_name="chawan")
    if chawan_step20:
        if chawan_step19 or input_candidate_v2 or input_candidate_v3:
            raise ValueError("choose only one opt-in renderer candidate")
        from .renderer.installed import chawan_step20_factory
        print("BoJangles: opt-in media candidate broker; foreground session only.", flush=True)
        return run_windowed(target, renderer_factories={"chawan": chawan_step20_factory()}, renderer_name="chawan")
    if chawan_step19:
        if input_candidate_v2 or input_candidate_v3:
            raise ValueError("choose only one opt-in renderer candidate")
        from .renderer.installed import chawan_step19_factory
        print("BoJangles: opt-in surface/input candidate; foreground session only.", flush=True)
        return run_windowed(target, renderer_factories={"chawan": chawan_step19_factory()}, renderer_name="chawan")
    if input_candidate_v2 or input_candidate_v3:
        from .renderer.installed import installed_renderer_factories
        print("BoJangles: nonproduction input candidate; foreground session only.", flush=True)
        return run_windowed(target, renderer_factories=installed_renderer_factories(
            input_candidate_v2=input_candidate_v2, input_candidate_v3=input_candidate_v3,
        ))
    return run_windowed(target)


def _print_bookmark_page(store: SandboxBookmarkStore, page: int, total: int) -> int:
    if page < 1:
        raise ValueError("bookmark page must be 1 or greater")
    pages = max(1, (total + 998) // 999)
    if total and page > pages:
        raise ValueError(f"bookmark page not found: {page} (last page is {pages})")
    items = store.numbered(page=page)
    if total > 999:
        print(f"Page {page} of {pages}")
        print()
    previous_path = None
    for number, folder_path, bookmark in items:
        if folder_path != previous_path:
            if folder_path:
                print(" / ".join(folder_path))
            elif previous_path is not None:
                print("(root)")
            previous_path = folder_path
        indent = "    " if folder_path else ""
        print(f"{indent}{number:>3}. {bookmark.title}")
        print(f"{indent}     {bookmark.url}")
    return len(items)


def _bookmark_url(value: str) -> str:
    from .frontend.open_target import plan_open_target
    return plan_open_target(value).primary_url


def _bookmarks(args: argparse.Namespace) -> int:
    store = SandboxBookmarkStore()
    command = args.bookmarks_command

    if command == "import":
        count = store.import_html(args.file)
        print(f"Imported {count} bookmark(s).")
        print(f"Authority: {store.path}")
        return 0

    if command == "add":
        url = _bookmark_url(args.url)
        title = str(args.title or "").strip()
        if not title:
            title = urlsplit(url).hostname or url
        store.add_to_folder(Bookmark(title, url), args.folder)
        folder = str(args.folder or "").strip() or "(root)"
        print(f"Bookmark saved: {title}")
        print(f"URL: {url}")
        print(f"Folder: {folder}")
        return 0

    if command == "show":
        folder_parts, bookmark = store.show(args.number, page=args.page)
        print(f"Number: {args.number}")
        if args.page != 1:
            print(f"Page: {args.page}")
        print(f"Title: {bookmark.title}")
        print(f"URL: {bookmark.url}")
        print(f"Folder: {'/'.join(folder_parts) if folder_parts else '(root)'}")
        return 0

    if command == "remove":
        _folder_parts, bookmark = store.show(args.number, page=args.page)
        removed = store.remove(args.number, page=args.page)
        location = f" on page {args.page}" if args.page != 1 else ""
        print(f"Removed bookmark {args.number}{location}: {removed.title}")
        print(f"URL: {bookmark.url}")
        return 0

    if command == "folder":
        if args.bookmark_folder_command == "add":
            store.add_folder(args.path)
            print(f"Folder created: {args.path}")
            return 0
        if args.bookmark_folder_command == "remove":
            store.remove_folder(args.path, recursive=args.recursive)
            print(f"Folder removed: {args.path}")
            return 0

    tree = store.load_tree()
    count = len(store.load())
    if not count:
        print("No bookmarks.")
        print(f"Authority: {store.path}")
        return 0
    page = getattr(args, "page", 1)
    listed = _print_bookmark_page(store, page, count)
    if listed == 0:
        print("No bookmarks on this page.")
    print()
    print(f"Authority: {store.path}")
    return 0


def _search(args: argparse.Namespace) -> int:
    """Run one bounded, session-only first-hand spider crawl."""
    from .crawler.live import LiveCrawlOptions, LiveWebCrawler
    from .frontend.search_handoff import canonical_result_url, launch_search_result
    from .frontend.search_surface import SearchHit, SearchSurface

    query = " ".join(args.query).strip()
    options = LiveCrawlOptions(
        site=args.site, domain=args.domain, path=args.path,
        seeds=tuple(args.seed), depth=args.depth, max_pages=args.max_pages,
        recent_days=args.recent, include_pdf=args.pdf, exact=args.exact,
        contains=tuple(args.contains), exclude=tuple(args.exclude),
        same_site=args.same_site, outbound=args.outbound,
    )
    print("Searching; waiting for the site…", file=sys.stderr, flush=True)
    report = LiveWebCrawler(
        progress=lambda message: print(message, file=sys.stderr, flush=True),
    ).search(query, options)
    hits = [
        SearchHit(
            url=canonical_result_url(result.url), title=result.title,
            content_date=result.content_date, age_days=result.age_days,
            evidence=result.evidence, snippet=result.snippet,
            source=result.source, media=getattr(result, "media", "Unknown"),
            size_bytes=getattr(result, "size_bytes", None), size_note=getattr(result, "size_note", ""),
        )
        for result in report.results
    ]
    try:
        surface_options = {"notice": report.notice} if getattr(report, "notice", "") else {}
        SearchSurface(query, hits, **surface_options).show(open_url=launch_search_result)
    except Exception as exc:
        raise RuntimeError("trusted live-search window could not open") from exc
    return 0


def _transcribe(args: argparse.Namespace) -> int:
    """CLI-only speech recognition in a separate offline process."""
    from .transcription.cli import run
    return run(args)


def _crawler_search(args: argparse.Namespace) -> int:
    """Search only the local AGE-qualified crawler index."""
    from .frontend.search_handoff import canonical_result_url, launch_search_result
    from .crawler.media import media_from_url

    index_path = args.index or (load(DEFAULT_PATH).crawler.storage_path / "index.sqlite3")
    if not index_path.is_file():
        raise ValueError(f"crawler index does not exist: {index_path}")
    query = " ".join(args.query)
    results = AgeIndex(index_path).search(query, limit=args.limit)
    if args.text:
        print("\n\n".join(result.display_text() for result in results))
        return 0

    from .frontend.search_surface import SearchHit, SearchSurface

    hits = []
    for result in results:
        try:
            url = canonical_result_url(result.url)
        except ValueError:
            continue
        hits.append(SearchHit(
            url=url, title=result.title, content_date=result.content_date,
            age_days=result.age_days, evidence=result.date_qualifier.value
            + " · " + result.date_source,
            snippet=result.snippet,
            source=result.crawl_origin or urlsplit(url).hostname or "",
            media=media_from_url(url) or "Unknown",
        ))
    try:
        SearchSurface(query, hits).show(open_url=launch_search_result)
    except Exception as exc:
        raise RuntimeError("trusted crawler-search window could not open") from exc
    return 0


def _upgrade(args: argparse.Namespace) -> int:
    from . import upgrade

    project_root = Path(__file__).resolve().parents[2]
    if args.upgrade_command == "apply-pending":
        from .update_notifications import apply_queued
        result = apply_queued()
    elif args.upgrade_command == "status":
        result = upgrade.status(project_root)
    elif args.upgrade_command == "check":
        result = upgrade.check(project_root)
    elif args.upgrade_command == "verify":
        result = upgrade.verify(project_root, staged=args.staged)
    elif args.upgrade_command == "stage":
        result = upgrade.stage(project_root)
    elif args.upgrade_command == "activate":
        if not args.confirm:
            raise ValueError("activation requires --confirm and the exact release identifier")
        result = upgrade.activate(project_root, release_id=args.release_id)
    elif args.upgrade_command == "rollback":
        result = upgrade.rollback(project_root)
    else:
        raise ValueError("unknown upgrade command")
    _print_json(result)
    return 0


def _diag(args: argparse.Namespace) -> int:
    from .diagnostics import analyze_ledger, analyze_latest, format_analysis

    result = analyze_ledger(args.ledger) if args.ledger else analyze_latest()
    print(format_analysis(result))
    return 0 if result["terminal_outcome_accounted"] else 1


def _passwords(args: argparse.Namespace) -> int:
    from getpass import getpass
    from .passwords import PasswordVault

    vault = PasswordVault()
    if args.passwords_command == "list":
        for origin in vault.origins():
            print(origin)
        return 0

    master = getpass("Master password: ")
    username = input("Username: ").strip()
    site_password = getpass("Site password: ")
    origin = vault.add(args.origin, username, site_password, master)
    print(f"Saved login for {origin}")
    return 0


def _version() -> int:
    try:
        project_version = version("bojangles")
    except PackageNotFoundError:
        project_version = "0.1.0"

    from .upgrade import status as release_status
    active = release_status(Path(__file__).resolve().parents[2])["active"]
    print(f"BoJangles {project_version}")
    print(f"Renderer: WPE WebKit {active['version']} — installed")
    print("HTML5 profile: LIMITED (profile_pass=false)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "maint":
            from .maintenance.cli import run
            return run(args)
        if args.command == "popup":
            from .popup_policy import snapshot, update
            try:
                result = snapshot(args.site) if args.popup_action == "show" else update(
                    args.site, getattr(args, "mode", None), reset=args.popup_action == "reset")
                _print_json(result)
                return 0
            except (ValueError, OSError) as exc:
                print(f"Popups: {exc}", file=sys.stderr)
                return 2
        if args.command == "media":
            from .media.center import run_cli
            return run_cli(args)
        if args.command == "advertising":
            from bojangles.filter.advertising import load, update, origin, RULES, RuleError
            try:
                if args.action == "rules":
                    if args.site or args.value: raise RuleError("rules takes no site")
                    _print_json([{"id":r.id,"hosts":r.hosts,"path":r.path,"types":sorted(r.types),"provenance":r.provenance} for r in RULES])
                elif args.action == "show":
                    if args.value: raise RuleError("show takes no value")
                    raw=load()
                    _print_json(raw if not args.site else raw["sites"].get(origin(args.site),{"mode":"balanced","allow":[]}))
                else:
                    if not args.site: raise RuleError("site required")
                    if args.action != "reset" and not args.value: raise RuleError("value required")
                    if args.action == "reset" and args.value: raise RuleError("reset takes no value")
                    options={args.action:args.value} if args.action in {"mode","allow","remove"} else {"reset":True}
                    _print_json(update(args.site,**options))
                return 0
            except (ValueError,OSError) as exc:
                print(f"Advertising: {exc}",file=sys.stderr);return 2
        if args.command == "popup-rules":
            from bojangles.popup_rules import load, origin, update, RuleError
            try:
                key = origin(args.site)
                if args.action == "list":
                    if args.selector is not None:
                        raise RuleError("list does not accept a selector")
                    _print_json(load()["sites"].get(key, []))
                else:
                    if args.action == "clear" and args.selector is not None:
                        raise RuleError("clear does not accept a selector")
                    result = update(args.site, args.selector,
                                    remove=args.action == "remove",
                                    clear=args.action == "clear")
                    _print_json(result["sites"].get(key, []))
                return 0
            except (RuleError, OSError) as exc:
                print(f"Popup rules: {exc}", file=sys.stderr)
                return 2

        if args.command == "help":
            parser.print_help()
            return 0

        if args.command == "version":
            return _version()

        if args.command == "upgrade":
            return _upgrade(args)

        if args.command == "search":
            return _search(args)

        if args.command == "transcribe":
            return _transcribe(args)

        if args.command == "crawler-search":
            return _crawler_search(args)

        if args.command == "diag" and args.diag_command == "open":
            args.command = "open"
            args.diag = True

        if args.command == "diag":
            return _diag(args)

        if args.command == "open":
            if not args.diag:
                return _open(args.target, input_candidate_v2=args.input_candidate_v2, input_candidate_v3=args.input_candidate_v3, frontend=args.frontend, chawan_step19=args.chawan_step19, chawan_step20=args.chawan_step20, chawan_step21=args.chawan_step21, chawan_step22=args.chawan_step22, wpe_windows=args.wpe_windows, engine=args.engine)
            from .diagnostics import start as start_diag, stop as stop_diag
            session = start_diag(args.target or "bojangles://home")
            try:
                result = _open(args.target, input_candidate_v2=args.input_candidate_v2, input_candidate_v3=args.input_candidate_v3, frontend=args.frontend, chawan_step19=args.chawan_step19, chawan_step20=args.chawan_step20, chawan_step21=args.chawan_step21, chawan_step22=args.chawan_step22, wpe_windows=args.wpe_windows, engine=args.engine)
            except Exception:
                stop_diag(clean=False, outcome="exception")
                raise
            ledger = stop_diag(clean=True, outcome=f"exit={result}")
            if ledger is not None:
                print(f"Diagnostics: {ledger}")
            return result

        if args.command == "bookmarks":
            return _bookmarks(args)

        if args.command == "passwords":
            return _passwords(args)

        if args.command == "init-config":
            config = load(DEFAULT_PATH)
            save(config, DEFAULT_PATH)
            print(DEFAULT_PATH)
            return 0

        if args.command == "config":
            if args.config_command == "path":
                print(DEFAULT_PATH)
                return 0

            if args.config_command == "show":
                _print_json(load(DEFAULT_PATH).to_dict())
                return 0

            if args.config_command == "crawler":
                if args.crawler_command == "show":
                    _print_json(
                        load(DEFAULT_PATH).to_dict()["crawler"]
                    )
                    return 0

                if args.crawler_command == "set":
                    field = args.field.replace("-", "_")
                    config = update_crawler(
                        DEFAULT_PATH,
                        **{field: args.value},
                    )
                    _print_json(config.to_dict()["crawler"])
                    return 0

                if args.crawler_command == "reset":
                    config = reset_crawler(DEFAULT_PATH)
                    _print_json(config.to_dict()["crawler"])
                    return 0

            if args.config_command == "filter":
                if args.filter_command == "show":
                    _print_json(
                        load(DEFAULT_PATH).to_dict()["filter"]
                    )
                    return 0

                if args.filter_command == "set":
                    config = update_filter(
                        DEFAULT_PATH,
                        level=args.level,
                    )
                    _print_json(config.to_dict()["filter"])
                    return 0

                if args.filter_command == "reset":
                    config = reset_filter(DEFAULT_PATH)
                    _print_json(config.to_dict()["filter"])
                    return 0

        return _status()

    except (
        ConfigError,
        CrawlerConfigError,
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"bojangles: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

