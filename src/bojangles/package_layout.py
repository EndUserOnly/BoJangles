"""Select package-managed authority only for code installed inside that package."""
from pathlib import Path

SYSTEM_RELEASE_STORE = Path('/usr/lib/bojangles/releases')

def release_store(home=None):
    if Path(__file__).resolve().is_relative_to(SYSTEM_RELEASE_STORE):
        return SYSTEM_RELEASE_STORE
    return (Path.home() if home is None else Path(home)) / '.local/share/bojangles/releases'
