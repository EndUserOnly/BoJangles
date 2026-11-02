"""First-party item catalog requests; never external search-engine discovery."""
from dataclasses import dataclass
import json
import re
from urllib.parse import urlencode

ARCHIVE_PAGE_SIZE = 100
ARCHIVE_RESULT_LIMIT = 10000
MAX_CATALOG_BYTES = 16 * 1024 * 1024


def archive_query_url(query: str, page: int, *, exact: bool = False) -> str:
    def literal(value):
        return '\"' + value.replace('\\', '\\\\').replace('\"', '\\\"') + '\"'
    terms = [literal(query)] if exact else [
        word if any(ch in word for ch in '*?[]') else literal(word)
        for word in query.split()
    ]
    params = [('q', ' AND '.join(terms)), ('output', 'json'),
              ('rows', str(ARCHIVE_PAGE_SIZE)), ('page', str(page)),
              ('sort[]', 'identifier asc')]
    params.extend(('fl[]', field) for field in (
        'identifier', 'title', 'description', 'subject', 'date', 'mediatype', 'format', 'item_size'))
    return 'https://archive.org/advancedsearch.php?' + urlencode(params)


def metadata_text(value: object, limit: int = 65536) -> str:
    if isinstance(value, list):
        return ' '.join(metadata_text(item, limit) for item in value[:100])[:limit]
    if not isinstance(value, str):
        return ''
    return value[:limit]


@dataclass(frozen=True, slots=True)
class CatalogPage:
    total: int
    start: int
    items: tuple[dict, ...]


def parse_archive_page(body: bytes) -> CatalogPage:
    if len(body) > MAX_CATALOG_BYTES:
        raise ValueError('Internet Archive search response is too large')
    try:
        data = json.loads(body)
        response = data['response']
        total = response['numFound']
        start = response['start']
        docs = response['docs']
        if (type(total) is not int or total < 0 or type(start) is not int or start < 0
                or not isinstance(docs, list) or len(docs) > ARCHIVE_PAGE_SIZE):
            raise ValueError('invalid catalog shape')
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise ValueError('Internet Archive returned an invalid search response') from exc
    return CatalogPage(total, start, tuple(item for item in docs if isinstance(item, dict)))


def archive_item_url(item: dict) -> str | None:
    identifier = item.get('identifier')
    if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,512}', identifier)
            or identifier in {'.', '..'}):
        return None
    return 'https://archive.org/details/' + identifier
