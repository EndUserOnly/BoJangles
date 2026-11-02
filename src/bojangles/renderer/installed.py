"""Explicit registry of renderer implementations shipped by this BoJangles tree.

RendererManager stays engine-independent.  This module binds the standing
renderer identity ``wpe`` to WPEBackend. Stage 5J supplies the concrete trusted
foreground Basic prompt. Stage 5K adds a separate trusted Digest SHA-256/qop=auth
prompt. Stage 7 supplies the bounded persistent WPE website-data/cache profile.
WPE itself receives no credential authority.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import hashlib
import json
import os

from .api import RendererBackend
from .chawan import ChawanBackend
from .chawan_step17 import ChawanStep17Backend
from .chawan_step18 import ChawanStep18Backend
from .chawan_step19 import ChawanStep19Backend
from .chawan_step20 import ChawanStep20Backend
from .wpe import WPEBackend
from .wpe_basic_prompt import WPEBasicTerminalResolver
from .wpe_digest_prompt import WPEDigestTerminalResolver
from .browser_transport import BrowserCompatibleTransport
from .browser_cookies import BrowserSessionCookieJar


CHAWAN_STEP16_SHA256 = "d45e19e9e17cdb7a2d03712c010069aaa74a67944cdecd380813de1eefb2bb70"
CHAWAN_STEP17_SHA256 = "5de67e7b96e2459a7800ddb4715786158bb0878b4867e016e8c1d6b20be96ab9"
CHAWAN_STEP17_ADAPTER_SHA256 = "32348776ce6b506f65ca2717ad98c1297dbb0a79c27ab8a71b5cfd54da4adcff"
CHAWAN_STEP19_SHA256 = "e51175a056114aa239de5aa567efbebc1994753c33069caab4311bce37f71c46"


def chawan_step16_factory(root: str | Path | None = None) -> Callable[[], RendererBackend]:
    """Opt-in lifecycle candidate; excluded from installed browser selection."""
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    executable = project_root / "build/chawan-step16/bin/cha"
    return lambda: ChawanBackend(executable, sha256=CHAWAN_STEP16_SHA256)


def chawan_step17_factory(root: str | Path | None = None) -> Callable[[], RendererBackend]:
    """Explicit resource candidate; not added to the installed renderer list."""
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    executable = project_root / "build/chawan-step17/bin/cha"
    return lambda: ChawanStep17Backend(
        executable, sha256=CHAWAN_STEP17_SHA256,
        adapter_sha256=CHAWAN_STEP17_ADAPTER_SHA256,
    )


def chawan_step18_factory(root: str | Path | None = None) -> Callable[[], RendererBackend]:
    """Opt-in BoJangles-owned surface; production selection stays unchanged."""
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    executable = project_root / "build/chawan-step17/bin/cha"
    return lambda: ChawanStep18Backend(
        executable, sha256=CHAWAN_STEP17_SHA256,
        adapter_sha256=CHAWAN_STEP17_ADAPTER_SHA256,
    )


def chawan_step19_factory(root: str | Path | None = None) -> Callable[[], RendererBackend]:
    """Opt-in focused-surface candidate; WPE remains production default."""
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    executable = project_root / "build/chawan-step19/bin/cha"
    return lambda: ChawanStep19Backend(
        executable, sha256=CHAWAN_STEP19_SHA256,
        adapter_sha256=CHAWAN_STEP17_ADAPTER_SHA256,
    )


def chawan_step20_factory(root: str | Path | None = None) -> Callable[[], RendererBackend]:
    """Opt-in media-candidate backend; no player or production promotion."""
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    executable = project_root / "build/chawan-step19/bin/cha"
    return lambda: ChawanStep20Backend(
        executable, sha256=CHAWAN_STEP19_SHA256,
        adapter_sha256=CHAWAN_STEP17_ADAPTER_SHA256,
    )


_WPE_AUTHORITY = {
    "bin/bojangles-wpe": "9f55c6900bf9a1386fe1956bcdf37f880eab3562150b08d21fad3e7788dde3e6",
    "extensions/libbojangles-wpe-dmz.so": "e6a6bba1dab510318d97bf8c6903ad8b43b36da2b84f9787d284e69896d274eb",
    "lib/libWPEWebKit-2.0.so.1.9.10": "cf36684c3d300a0a3b2d7da6e1490226f0740b0a7fb39c6b8343b59059b5a3e8",
}
_WPE_DRM_AUTHORITY = {
    "bin/bojangles-wpe": "55c979e14ad6a2e5d84ecb0ba6488a8c893ac08b546409da2136e1d181a29984",
    "extensions/libbojangles-wpe-dmz.so": "e6a6bba1dab510318d97bf8c6903ad8b43b36da2b84f9787d284e69896d274eb",
    "lib/libWPEWebKit-2.0.so.1.9.10": "134800005ec7f2742054a7f24c874cc08c5d2ae260a1e4b6d8ae344b2dbcc29c",
}


_WPE_RELEASE_MANIFESTS = {'public-release-20261028': '4c16203652c3b3a9b06b201cde6f58038e04c0b2e72110721661a2dc899a2e30', 'library-export-20261027': '2939bce0d2e03b2ea6af09d25e75738672c8f61ac9e59059e805cce21b55fb8d', 'security-r6-20261027': '1f3ff1e73af5a89cb13c63d1329d52173dcaa83aa95651d7064883b55f5f03a0', 'soak-train-20261026-A': 'f442b23991517255a86bb97dce871714f19185399f9ef4059b7cf992f13a4f87', 'soak-train-20261025-A': '44f8f6ec420b518d00d860f76961ed4de3dfaf337af262eaa016c7518f8a5400', 'soak-train-20261024-B': '442a056f50fa7a06239ab439fcaaab0b8bacc2dc0f3d96388ee048f53919b022', 'soak-train-20261024-A': '474400010d9ac234f0a931382ac907b9788cca866787a59c7fd09dddee1e11a5', 'soak-train-20261023-D': 'ab0289abba7d1cd9a403587aca272c471bf1fa052056366962d5c08aa37aeb03', 'soak-train-20261023-C': '940c30b3abcaeca54bdf76fde75f150c90dfb70016f785304cdc48e293d66d46', 'soak-train-20261023-B': '2e1add674b2f226b4c28082b57d02dc75ebabc0ac5aa71dbab29dc3cfe5c1132', 'soak-train-20261022-D': 'c8ffea4aa74375f1512d53055404260491dd23a3fa7fa131b90a57dec4dcf572', 'soak-train-20261022-C': 'e71e822ef4a3d3ab1f6671115d9889ee8217ca65e2a78c3d9802dd47addb1eea', 'soak-train-20261022-A': '6f87edfd7fcb13a3af06f4a7a27419e2bb70dee2220ea13d86e6543f2515d973', 'soak-train-20261021-A': 'af344bd9bbcfba0defefa07e9da85979511c789cf8c0eff58c46a9a471bc1bd5', 'soak-train-20261021-B': 'f43cde0acacb2dd11d6e583a432bcfa5e78ebf1654aac86dd67ba34ea884572c', 'soak-train-20261020-C': 'fe9e527999f163872bfa603bfc6f986bdf4275e873899be808a3a6ffef846b7b', 'soak-train-20261020-B': 'bb060fb8a3e6c61cd2ae8f2f687a894698fb70ca0256653e7e206e03bb8db032', 'soak-train-20261020-A': '4331079f5fc996e592ad7eff875b9df9d102f57241c9c0f6d0991ae21f77e231', 'soak-train-20261017-B': 'fce66788875ddde62ae3bd19c24eb07ecbb605568574fb307b956a4efd944279', 'soak-train-20261017-A': '9ecfebb9e47c77b28ae27dc22809a15a8ca742a64c82a92b34c5a181a19d1250', 'soak-train-20261014-C': 'ca1bf68b1571385585c5f8baa0a188d949e8d663891e52f452b831bdc07692e3', 'soak-train-20261014-B': '962cf3aa1f7e4b0e631195bb09e4985763d1fdf121dffc94db454da7d376e4cf', 'soak-train-20261013-D': 'a0290373fca82a904209729920ce7e2980a69947d3c2f80517e8884ab0804413', 'soak-train-20261013-C': '6f12a3235d2211d3c88a697945098ff0d7a8e6df1dc03de702009f76fbb55ef3', 'soak-train-20261013-B': '7cf15476d1d8fe7d68ec615ff2f1b1efbe3597fc6590d2bebbee0b2c7081d2be', 'soak-train-20261013-A': 'c0818575de420d9071bd19531ea9e47896c74f869421df3e050f175ce12a84ef', 'soak-train-20261012-E': '37bc19c0ff742d2dc0b270a3e2da536a71ceae1600f5876c041f38bfcaff97b0', 'soak-train-20261012-D': '5d1ace5f458179d0ced4519a466bbc56f4a109c9ba3fee1d82ff05fa6397f33b', 'soak-train-20261012-C': '845e6919a469f9f8e85bb3f4198dd66fbc13410702f50a6ea6eb3928e50dfd23', 'soak-train-20261012-B': '9c4ef39e1a62932fd70ecc393f22b3b86d0c586c7ba2c282bb102302f81c8026', 'soak-train-20261012-A': '16d3e5d70a1ff3b730dc55c1a97e94e93c2e54f53161288b7db29c080b4d1298', 'soak-train-20261011-D': '71d051515e424397436a7106d542b444dede8b64c950d124ba797d1a94794b47', 'soak-train-20261011-C': '8e77e09eb351c539cbf64a1726121ceb79cd9c53667fb98743a4124fe4eaf150', 'soak-train-20261011-B': '774e41ed279324331110ae38eff4f9620251ffd16a53654bc01b841976c85165', 'soak-train-20261011-A': '3faf2b3f76bcd7dcee3eb503ef050d0a7cdea05fbbe774b75262a66121195f4d', 'soak-train-20261010-M': '62e2db711df2d96d65704e4243a0ce4431a23c47bc289ba72e54b1623857dd31', 'soak-train-20261010-K': '9406e5b6bf2e5ab254ebee234e3b0dfe3fb9f701b266a5b071983719131a6771', 'soak-train-20261010-J': '38dc8d239fdc05f7e52beba476f1dc79b90180f2caff4cd332ed4acab551a5d1', 'soak-train-20261010-I': '1b023ec9c3a181c2f3c7eb7adc9617a7c5d2f220f89d9fad7d95fcbf8a4c9d54', 'soak-train-20261010-H': '8c885000f10ab696153ce36924ba6f6af8ff7a1e7112325269b215d2f4233f23', 'soak-train-20261010-G': '4f594d3eb6a482cce5b4a74245f2af0dbd4d081dee37e3b1715b9ef0e1757e96', 'soak-train-20261010-F': '503b7b9995a30652f112fdeeb38b3658f0ede5bb7c901496df5e31f6ba0002f5', 'soak-train-20261010-E': 'b59a84fab7354a910639a4878acbe19af5c91d303a0ca653c5af264387c0645e', 'soak-train-20261010-D': '6400a5718b0822fbd4995463a65ed628f62eec968d4ea92aa1d9ecef4aea6362', 'soak-train-20261010-C': '3da3b3a2021c7c66d9f8444628317b09f87c99798df9b6d6b284661939ae18bb', 'soak-train-20261010-B': '1ccd01a3e355cbb9e598ba57dda21f09fb8800e2a777a22565ccc7ca4b311083', 'soak-train-20261010-A': '7509b35b343fc889806346dc5dea8873f9159f7b78ce8a708269c3c380305437', 'soak-train-20261009-B': '0576e28a12f76ce1f5ba227ae01ba541bb71eff43cfec19e625a6a07272bff8d', 'soak-train-20261009-A': '9261567899ff8fef3bb2f14e50e2e14e96b411faf97c28ee6d8221f537a2eacc', 'soak-train-20261008-B': '2528670c6ca3c57c5d78677b8f3f676e132c6c9241be0597c8ac0bd2fec02eef', 'soak-train-20261008-A': '428a66025607c18cd4002cd7cb72b48c55a9a6182c191352225dd6c726f82aa9', 'soak-train-20261007-E': 'd8998f5c5da18888e3fab92d785a4c06582399c8f92fbf5b559cd47191a92313', 'soak-train-20261007-D': 'fd185204ec5ce7ea6a20c3f394f85d2e3aa645c79884b88a44ebd49a77ac28a7', 'soak-train-20261007-C': '8067ef83abdd0d4b533200b3c30c2b32f5d7ae7e4a1b8934fddc196b537fa8ae', 'soak-train-20261007-B': '0828df4b7b1460acf53353606ba567229abaf56ddfdc7502e9078328172c6867', 'soak-train-20261007-A': 'be32dc4fa963ad4da69c40d29545da4ca2a361a211fffcea06499d5c77f25f11', 'soak-train-20261005-B': '3522bd6c696339368b7c504933cc0aa36eea40c14df78919622213078f98f563', 'soak-train-20261005-A': '4ed956d83505aa16ecbdc50cadb735b1287869f72545c0c748f574152b26ba8b', 'soak-train-20261004-A': '944301d56a209fc73344746ed665bf62560f83d0b0dfd4a7482810072b764b46', 'engine-upgrade-20260926-A': '4ec27ab4fcfbea6688fac103f7571ecf3812d0b73cd44eb9bdaf04eac968c34f', 'soak-train-20260927-C': '486652459dee7c5ca955dd9fb1c6717a420809e3dee339f88c9a9c1098205ef8', 'soak-train-20260927-D': 'ebc0625d8d38a27852bebf18129681679cb748e05aacf8adc6e9147cef834910', 'soak-train-20260927-G': '2b756f208953e11a91a5a5cfcdbe623a188309d5ffa314b2b0c0319a973105a0', 'soak-train-20260927-H': 'af464d8f2b40e6b2b0cba62a64bcd5ffd70e82a456a40691ce7f3df246cf4537', 'soak-train-20260928-I': '0ea02eeefa6f02daf7b91fa747c75f3334cb1962d8f6b728e303bb7afda0566f', 'soak-train-20260929-L': '331a77cf76403c58eeb3013ee4b5dd91e7ed350816a3e5bd04e0d3a6eb6db536', 'soak-train-20260929-M': '5bd18bff53c4f38d7dd19998b9e947cdfa946b03040991c4506900b32c1c1c73', 'soak-train-20260929-N': '5f67aba53659510121777f380b8970efdc861ff4fd178015638f16a5eca586f7', 'soak-train-20260929-O': '2ac45c61e71264ab3f71df204c20ee53f5155875469faeafc827ee6071ff41ab', 'soak-train-20260929-P': 'f353bb9c2388ab914e88e5b3d63cdcc449a9dd600c85f55e4aa7d7571b51a3f9', 'soak-train-20260929-Q': '3f49d6352214547cb32611caf67d2278ba28e5a9df38fc4b76b53650eb633572', 'soak-train-20260930-R': '7462e5d922ba0f00e72a766c8db43dfec289af7751ac30b082edcb102b6a69be', 'soak-train-20260930-S': 'd5d7f6762110e45285c7f36a0f867fd74a270b67556e6687b6e706b0d99d1635', 'soak-train-20260930-T': '3c8adc35e85f9306b1fb711791c819d2c81e3fb0881a72277d79ea2a57b5ed96', 'soak-train-20260930-U': '87f0abcdca831f229f54eb06bc9d1f7de907b9b61986258c1d6cdd03790ca5e5', 'soak-train-20260930-V': '930fb5c701541f7d570f32e6a46f19447d1850307a50885eae2c3c373b8e86d3', 'soak-train-20260930-W': '738b3e81481e2e30a6e476971e635e9c3750db506cce6ac75845aea590c92ec1', 'soak-train-20261001-X': 'f2272fc4540e9544d4fbfa36e4bf5d8d71358681e2a0091323e725b8cf5d2710', 'soak-train-20261001-Y': 'bc8d05fb8b5f38e564fe77ad3583cc509b9f8a41e594294a3a957846a20fc774', 'soak-train-20261001-Z': 'd8953fd3c961f5aa5a87cbb40c7bbdfdf7ac7aeaa73a6a1f4be32b105dbc1416', 'soak-train-20261001-AA': 'a3c522e57dfa7735bd38a38584c1e91d60f21901e9f5a5ce2ff6ef2ecabde803', 'soak-train-20261001-AB': 'd107f6f10780ef6e2aab86d2f20f0c554c8ac90dc87e77cc57e3333d71b629d3', 'soak-train-20261001-AC': '304f56edc5f420ea930efeffd2a30929312e7963db39480447a143311cdade7a', 'soak-train-20261001-AD': '2528476fb4623aeb6e7c17f412cf67d4dfd7f8e4907c6eb759093260c31327b0', 'soak-train-20261001-AE': '86a7620939894b6808fb9a210df0fc1f02182f8b78564a00b78fed2ba7d67bed', 'soak-train-20261001-AF': 'b872ecc52adfc4ed9d2fd82116015bb583bf61bac6b368304f09fbdd0b6167dd', 'soak-train-20261001-AG': '66d86930f308fa9e2ce154d6c1e2a2f630a5dcf51e69ea54b55a2437921f31e7', 'soak-train-20261001-AH': '54b7a2215ee507dbe93cf864fe7f59b9f82572920811574e50bd0e63bc0d184c', 'soak-train-20261001-AI': '37b7cef14c335f5d7a72d3b3db9ee0eb115796f7e9093a274d9ac4a4a26fd260', 'soak-train-20261001-AJ': '273b6a092d34533a2d84eb67ee56212184c7488ddbbe078944ec794e4e5ad553', 'soak-train-20261001-AO': '50c13a8fc40bc87c56365d4da166533d56a6a5956c0f6b521db352f8b86e409b', 'soak-train-20261001-AP': 'c8d024bec25ffe02c93c566c8681374d0c72459624584acd18ae5d0c1da5bc57', 'soak-train-20261002-B': 'fa54d57ea5b296631d283a5c9dee8cadd7783d127e252532ff142416e053e3c8', 'security-r1-20261026': '058c846e575d7a686baf2ad87fac0c0507a97969f93a8bb64a2ae93bea7242ce', 'security-r1-20261026-b': '2f1ace40752299054df572885080ce40cbfa877b0157051567f824cbf9089993', 'security-r3-20261026': '5043888ca262937e87ac0fe782b14592794d8e7aae7fceb1464c7ade73db0500', 'security-r4-20261027': '2ebb1a09e8684d013f16fa2fb2978845162531286949aecfed70a50bcb50c1db', 'security-r5-20261027': '98a235bbccbde059c8b4928a5c70338e40f939de2769ce774e4c184a7212663d', 'region-context-20261027': '288a320eb37d3bd504c3b2ce8a19f0538a4246dc7995c34d83d7679e03246d6e', 'recording-reminder-20261027': '76a22829c0a99da5aa93f49768702fb747b468d517f0d457e1ee045b62ec979a'}
_WPE_RELEASE_MANIFESTS['form-paste-20261028'] = '397248e09b1475ea550861297a0bab5ebee6260061b9cdac1a87a1992ab9f6dd'
_WPE_RELEASE_MANIFESTS['public-release-20261030-snapshot'] = '46caae7b8c7f26698db3220829847cfa1ea3c84c246daa311495f5606d1b2afc'
_WPE_RELEASE_MANIFESTS['public-release-20261030-updates'] = '1d6e7631fd843e3b812c737f9ac2a082f38327aa766da0880fd9420c147dc9df'
_WPE_RELEASE_MANIFESTS['public-release-20261030-github-updates'] = '32ed5f1e89ffb151633ce1bea790bbef555456acee7d14296414fb1b35aff7bb'
_WPE_RELEASE_MANIFESTS['public-release-20261101-header-bookmarks-local'] = '84cdb551a32d38298daf0f03ad24fe40882e5319d2c9e0647d6d996a358614ef'
_WPE_RELEASE_MANIFESTS['public-release-20261101-resource-upload-local'] = '1aef99956244720f677b7758f2c0d1dbc72accf260723923b97c15e7768a5298'
_WPE_RELEASE_MANIFESTS['public-release-20261102-media-crawler-local'] = '0f928cadcf97ef5f6d3e22b3a2951774fb52ae5ba42f8cc9a81101bda8f4299b'
_WPE_RELEASE_ID = 'public-release-20261102-media-crawler-local'
_WPE_254_RELEASE_MANIFEST_SHA256 = _WPE_RELEASE_MANIFESTS[_WPE_RELEASE_ID]


def _read_wpe_release_state(release_store: Path) -> dict[str, object]:
    state = release_store / "active.json"
    if not state.exists() and not state.is_symlink():
        return {"schema": 1, "active": "legacy", "previous": None}
    if state.is_symlink() or not state.is_file():
        raise RuntimeError("WPE release selection authority invalid")
    value = json.loads(state.read_text())
    allowed = {"legacy", *_WPE_RELEASE_MANIFESTS}
    if (not isinstance(value, dict) or set(value) != {"schema", "active", "previous"} or
            value["schema"] != 1 or not isinstance(value["active"], str) or
            value["active"] not in allowed or
            (value["previous"] is not None and
             (not isinstance(value["previous"], str) or value["previous"] not in allowed))):
        raise RuntimeError("WPE release selection authority invalid")
    return value


def _verify_wpe_release_candidate(area: Path) -> Path:
    manifest_path = area / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("WPE release manifest missing")
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    candidate = manifest.get("candidate")
    if (candidate not in _WPE_RELEASE_MANIFESTS or
            hashlib.sha256(raw).hexdigest() != _WPE_RELEASE_MANIFESTS[candidate]):
        raise RuntimeError("WPE release manifest authority mismatch")
    if (area.name not in ("release", candidate) or
            manifest.get("wpe_version") not in {"2.54.0", "2.54.2"} or
            manifest.get("install_prefix") != "/wpe" or
            manifest.get("single_release") is not True or
            manifest.get("clear_key_built_in") is not True or
            manifest.get("ordinary_eme_default") is not False):
        raise RuntimeError("WPE release manifest identity mismatch")
    prefix = area / "stage/wpe"
    if prefix.is_symlink() or not prefix.is_dir() or prefix.stat().st_mode & 0o022:
        raise RuntimeError("WPE release directory is writable by another user")
    expected = set()
    for entry in manifest["files"]:
        relative = entry["path"]
        path = prefix / relative
        if (not relative or relative.startswith("/") or
                ".." in Path(relative).parts or relative in expected):
            raise RuntimeError("WPE release manifest path invalid")
        expected.add(relative)
        for parent in path.parents:
            if parent == prefix.parent:
                break
            if parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o022:
                raise RuntimeError("WPE release directory is unsafe")
        if "symlink" in entry:
            if (not path.is_symlink() or os.readlink(path) != entry["symlink"] or
                    not path.resolve(strict=True).is_relative_to(prefix.resolve(strict=True))):
                raise RuntimeError(f"WPE release authority mismatch: {relative}")
        elif (not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o022 or
              hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]):
            raise RuntimeError(f"WPE release authority mismatch: {relative}")
    present = {path.relative_to(prefix).as_posix() for path in prefix.rglob("*")
               if path.is_file() or path.is_symlink()}
    if present != expected:
        raise RuntimeError("WPE release file set mismatch")
    return prefix


def _verify_wpe_authority(label: str, prefix: Path, expected_files: dict[str, str]) -> None:
    for relative, expected in expected_files.items():
        artifact = prefix / relative
        if not artifact.is_file() or hashlib.sha256(artifact.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"{label} authority mismatch: {relative}")


def _wpe_factories(
    *,
    root: str | Path | None,
    prefix: str | Path | None,
    include_drm: bool,
    input_candidate_v2: bool,
    input_candidate_v3: bool,
    release_candidate: bool = False,
    release_area: Path | None = None,
    release_store: Path | None = None,
):
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    if input_candidate_v2 and input_candidate_v3:
        raise ValueError("Choose only one input candidate")
    if input_candidate_v2 or input_candidate_v3:
        raise RuntimeError(
            "Historical single-socket input candidates are incompatible with Step 12; "
            "use the pinned broker-v1 renderer"
        )

    from bojangles.package_layout import release_store as default_release_store
    store = release_store if release_store is not None else default_release_store()
    selected = _read_wpe_release_state(store)["active"] if prefix is None and not release_candidate else "legacy"
    using_unified = release_candidate or selected in _WPE_RELEASE_MANIFESTS
    if using_unified:
        if release_candidate and prefix is not None:
            raise ValueError("release candidate has a fixed verified package path")
        if release_candidate:
            area = release_area if release_area is not None else project_root / "build/candidates/engine-upgrade-20260926-A/release"
        else:
            area = store / selected
        wpe_prefix = drm_prefix = _verify_wpe_release_candidate(area)
    else:
        wpe_prefix = Path(prefix) if prefix is not None else project_root / "build/wpe-broker-v1"
        drm_prefix = project_root / "build/wpe-drm-v1"
        _verify_wpe_authority("WPE", wpe_prefix, _WPE_AUTHORITY)
        if include_drm:
            _verify_wpe_authority("WPE Clear Key", drm_prefix, _WPE_DRM_AUTHORITY)

    profile_data_dir = Path.home() / ".local" / "share" / "bojangles" / "wpe-profile"
    profile_cache_dir = Path.home() / ".cache" / "bojangles" / "wpe-profile"
    resource_redirect_handoff = (using_unified and
        json.loads((area / "manifest.json").read_text()).get("resource_redirect_handoff") is True)
    native_pdf_viewer = (using_unified and
        json.loads((area / "manifest.json").read_text()).get("native_pdf_viewer") is True)
    from .wpe_transport import MAX_RESOURCE_BYTES
    transport = BrowserCompatibleTransport(
        max_resource_bytes=MAX_RESOURCE_BYTES,
        session_cookies=BrowserSessionCookieJar(
            storage_path=Path.home() / ".local/share/bojangles/browser-profile/cookies.json"),
        basic_credential_resolver=WPEBasicTerminalResolver(),
        digest_credential_resolver=WPEDigestTerminalResolver(),
    )

    def make_wpe() -> RendererBackend:
        return WPEBackend(
            wpe_prefix / "bin/bojangles-wpe",
            prefix=wpe_prefix,
            extension_dir=wpe_prefix / "extensions",
            transport=transport,
            profile_data_dir=profile_data_dir,
            profile_cache_dir=profile_cache_dir,
            backend_id="wpe",
            drm_mode=False,
            resource_redirect_handoff=resource_redirect_handoff,
            native_pdf_viewer=native_pdf_viewer,
        )

    def make_wpe_drm() -> RendererBackend:
        if using_unified:
            _verify_wpe_release_candidate(area)
        else:
            _verify_wpe_authority("WPE Clear Key", drm_prefix, _WPE_DRM_AUTHORITY)
        return WPEBackend(
            drm_prefix / "bin/bojangles-wpe",
            prefix=drm_prefix,
            extension_dir=drm_prefix / "extensions",
            transport=transport,
            profile_data_dir=profile_data_dir,
            profile_cache_dir=profile_cache_dir,
            backend_id="wpe-drm",
            drm_mode=True,
            resource_redirect_handoff=resource_redirect_handoff,
            native_pdf_viewer=native_pdf_viewer,
        )

    return make_wpe, make_wpe_drm


def installed_renderer_factories(
    *,
    input_candidate_v2: bool = False,
    input_candidate_v3: bool = False,
    root: str | Path | None = None,
    prefix: str | Path | None = None,
    release_store: Path | None = None,
) -> dict[str, Callable[[], RendererBackend]]:
    """Standing renderer registry. DRM remains outside generic selection."""
    make_wpe, make_wpe_drm = _wpe_factories(
        root=root,
        prefix=prefix,
        include_drm=False,
        input_candidate_v2=input_candidate_v2,
        input_candidate_v3=input_candidate_v3,
        release_store=release_store,
    )
    # Private companion authority: not part of the generic installed-renderer
    # registry. Frontends may add it only to a live WPE session.
    make_wpe._bojangles_drm_factory = make_wpe_drm  # type: ignore[attr-defined]
    return {"wpe": make_wpe}


def wpe_session_renderer_factories(
    *,
    root: str | Path | None = None,
    prefix: str | Path | None = None,
    release_store: Path | None = None,
) -> dict[str, Callable[[], RendererBackend]]:
    """Private WPE session registry with consent-gated Clear Key authority."""
    make_wpe, make_wpe_drm = _wpe_factories(
        root=root,
        prefix=prefix,
        include_drm=True,
        input_candidate_v2=False,
        input_candidate_v3=False,
        release_store=release_store,
    )
    return {"wpe": make_wpe, "wpe-drm": make_wpe_drm}


def wpe_release_candidate_factories(*, root: str | Path | None = None,
                                    area: Path | None = None) -> dict[str, Callable[[], RendererBackend]]:
    """Explicit, hash-verified 2.54 preview; both modes use one staged package."""
    ordinary, authorized_drm = _wpe_factories(
        root=root,
        prefix=None,
        include_drm=True,
        input_candidate_v2=False,
        input_candidate_v3=False,
        release_candidate=True,
        release_area=area,
    )
    return {"wpe": ordinary, "wpe-drm": authorized_drm}
