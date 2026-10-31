"""Build and qualify a complete BoJangles update on a disposable GitHub runner."""
from pathlib import Path
import hashlib, importlib.util, json, os, re, shlex, shutil, subprocess, sys, tarfile, tempfile, urllib.request, zipfile

# Verification must not add bytecode files to an authenticated release tree.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'ci-work'
SOURCE = WORK / 'source'
CANDIDATE = 'public-release-20261030-header-bookmarks'
TAG = 'v0.1.0-header-bookmarks.20261030'
RELEASE = WORK / 'release' / CANDIDATE
BUILDER = WORK / 'builder'
OUT = WORK / 'artifacts'
BASE = 'https://github.com/EndUserOnly/BoJangles/releases/download/v0.1.0-updates.20261030/'
INPUTS = {
 'source': ('BoJangles-0.1.0-github-updates-20261030-source.tar.gz', 'f360b81fb412cd637a72cef5a3dab6c310079c0595e1d14d0a17ac4a312b8d65'),
 'binary': ('BoJangles-0.1.0-github-updates-20261030-linux-x86_64.tar.gz', '3ca29e4ad301eade21571433cb6959665fb3c01d368d4cb2b3861e34fed6cabe'),
}

def sha(path):
 with Path(path).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def write(path, data):
 Path(path).write_text(json.dumps(data, indent=2) + '\n')

def run(args, **kwargs):
 subprocess.run([str(a) for a in args], check=True, **kwargs)

def inventory(root):
 return [({'path': p.relative_to(root).as_posix(), 'symlink': os.readlink(p)} if p.is_symlink() else {'path': p.relative_to(root).as_posix(), 'sha256': sha(p)}) for p in sorted(root.rglob('*')) if p.is_file() or p.is_symlink()]

def prepare():
 WORK.mkdir(); OUT.mkdir()
 for kind, (name, digest) in INPUTS.items():
  archive = WORK / name
  urllib.request.urlretrieve(BASE + name, archive)
  if sha(archive) != digest: raise ValueError('Baseline archive checksum mismatch: ' + kind)
  target = WORK if kind == 'source' else WORK / 'release'
  target.mkdir(exist_ok=True)
  with tarfile.open(archive) as tf: tf.extractall(target, filter='data')
 old = WORK / 'release/public-release-20261030-github-updates'
 old.rename(RELEASE)
 spec = importlib.util.spec_from_file_location('installer', RELEASE / 'install-public-release.py')
 installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
 installer.verify(RELEASE, '37fd875f0d7e76a02399f5f4b56a3fb217da55f3bd26353d7dc1bf09c54968a3')
 files = json.loads((ROOT / 'ci/source-files.json').read_text())
 for name, digest in files.items():
  relative = Path(name)
  if relative.is_absolute() or '..' in relative.parts or sha(ROOT / name) != digest: raise ValueError('Unsafe or changed source input')
  destination = SOURCE / name; destination.parent.mkdir(parents=True, exist_ok=True)
  shutil.copy2(ROOT / name, destination)
 # Preserve optional runtime support from the qualified predecessor rather
 # than letting a clean runner silently omit decryption/proxy/media modules.
 pins = {'Brotli': '1.1.0', 'PySocks': '1.7.1', 'bcrypt': '3.2.2',
         'chardet': '5.2.0', 'dbus-python': '1.3.2', 'idna': '3.6',
         'mutagen': '1.46.0', 'olefile': '0.46', 'pyOpenSSL': '23.2.0',
         'pycryptodomex': '3.20.0', 'simplejson': '3.19.2', 'six': '1.16.0',
         'urllib3': '2.0.7'}
 requirements = SOURCE / 'requirements-build.txt'
 with requirements.open('a') as f:
  f.write('\n# Qualified predecessor runtime distribution versions.\n')
  for name, version in pins.items(): f.write(name + '==' + version + '\n')
 recipe = json.loads((SOURCE / 'native/wpe/production-application-build.json').read_text())
 packages = sorted(set(recipe['required_runtime_packages'] + recipe['required_build_packages'] + ['libsoup-3.0-dev', 'libegl1-mesa-dev', 'libdrm-dev', 'libgbm-dev', 'libinput-dev', 'libxkbcommon-dev', 'libudev-dev', 'libgstreamer1.0-dev', 'libgstreamer-plugins-base1.0-dev', 'python3-tk', 'python3-setuptools', 'python3-wheel', 'dbus-x11', 'xauth', 'xvfb', 'gir1.2-gtk-4.0', 'gir1.2-graphene-1.0', 'gir1.2-gst-plugins-base-1.0', 'gir1.2-soup-3.0', 'python3-dbus', 'libdbus-1-dev']))
 (WORK / 'apt-packages.txt').write_text('\n'.join(packages) + '\n')
 write(WORK / 'input-record.json', {'source_commit': os.environ['GITHUB_SHA'], 'baseline_inputs': INPUTS, 'changed_source_sha256': files})

def broker():
 prefix = RELEASE / 'stage/wpe'
 env = dict(os.environ, PKG_CONFIG_PATH=str(prefix / 'lib/pkgconfig'))
 packages = ['wpe-webkit-2.0', 'wpe-platform-2.0', 'wpe-platform-headless-2.0']
 recorded = subprocess.check_output(['pkg-config', '--variable=prefix', packages[0]], env=env, text=True).strip()
 flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', *packages], env=env, text=True))
 flags = [flag.replace(recorded + '/', str(prefix) + '/') for flag in flags]
 run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', SOURCE / 'native/wpe/broker-v1/main.c', '-o', prefix / 'bin/bojangles-wpe', '-Wl,--disable-new-dtags', '-Wl,-rpath,$ORIGIN/../lib:/wpe/lib', *flags])
 manifest = json.loads((RELEASE / 'manifest.json').read_text()); manifest['candidate'] = CANDIDATE
 for entry in manifest['files']:
  if entry['path'] == 'bin/bojangles-wpe': entry['sha256'] = sha(prefix / entry['path'])
 write(RELEASE / 'manifest.json', manifest)
 path = SOURCE / 'src/bojangles/renderer/installed.py'
 text = path.read_text()
 line = "_WPE_RELEASE_ID = 'public-release-20261030-github-updates'"
 if text.count(line) != 1: raise ValueError('Unexpected baseline renderer authority')
 text = text.replace(line, f"_WPE_RELEASE_MANIFESTS[{CANDIDATE!r}] = {sha(RELEASE / 'manifest.json')!r}\n_WPE_RELEASE_ID = {CANDIDATE!r}")
 path.write_text(text)
 write(WORK / 'native-build.json', {'broker_sha256': sha(prefix / 'bin/bojangles-wpe'), 'source_sha256': sha(SOURCE / 'native/wpe/broker-v1/main.c'), 'wpe_manifest_sha256': sha(RELEASE / 'manifest.json'), 'engine_recompiled': False})


def bootstrap():
 if (os.cpu_count() or 0) < 4: raise ValueError('At least four compiler jobs are required')
 run([sys.executable, SOURCE / 'scripts/bootstrap-public-build.py', BUILDER])


def tests():
 env = dict(os.environ, BOJANGLES_BROKER_RUNTIME=str(RELEASE / 'stage/wpe'))
 modules = ['test_response_header_budget', 'test_wpe_stage5c_transport', 'test_wpe_stage5d_transport', 'test_bookmarks', 'test_error_isolation.ErrorIsolation.test_header_count_value_and_directional_byte_limits', 'test_wpe_step12.DescriptorTests', 'test_bookmark_save_regression', 'test_response_header_runtime', 'test_bookmark_save_runtime', 'test_bookmark_same_window.BookmarkRuntimeTests', 'test_update_notifications', 'test_update_panel']
 # Separate native/UI lifetimes: destroyed Tk roots must never be collected
 # by an update worker belonging to a later fixture in the same interpreter.
 modules.remove('test_update_panel')
 modules += ['test_update_panel.UpdatePanelTests.' + name for name in [
  'test_preview_is_inline_and_cannot_download_or_install',
  'test_signed_feed_appears_once_and_worker_retires',
  'test_automatic_check_refreshes_an_already_open_panel',
  'test_secondary_browser_can_open_updates_on_the_primary',
  'test_preview_cannot_retry_or_change_a_real_queued_operation']]
 # Every invocation isolates HOME/XDG before any test/frontend import.
 with (OUT / 'source-native-tests.log').open('w') as log:
  for module in modules:
   print('ISOLATED PROCESS: ' + module, file=log, flush=True)
   run(['xvfb-run', '-a', BUILDER / 'bojangles-app-build-venv/bin/python', SOURCE / 'scripts/run-isolated-tests.py', '-v', module], env=env, stdout=log, stderr=subprocess.STDOUT)


def compile_app():
 run([sys.executable, SOURCE / 'scripts/build-production-application.py', '--builder-root', BUILDER, '--jobs', '4'])


def package():
 import xml.etree.ElementTree as ET
 report = BUILDER / 'bojangles-app-compilation.xml'
 if ET.parse(report).getroot().get('completion') != 'yes': raise ValueError('Incomplete compilation report')
 shutil.rmtree(RELEASE / 'native-command/app')
 shutil.copytree(BUILDER / 'bojangles-app-output/bojangles.dist', RELEASE / 'native-command/app', symlinks=True)
 wheels = WORK / 'wheels'; wheels.mkdir()
 python = BUILDER / 'bojangles-app-build-venv/bin/python'
 run([python, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', wheels, SOURCE])
 wheel, = wheels.glob('*.whl')
 hashes = {p.relative_to(SOURCE / 'src').as_posix(): sha(p) for p in (SOURCE / 'src').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc' and '.egg-info' not in str(p)}
 with zipfile.ZipFile(wheel) as z:
  for name in z.namelist():
   if name.startswith('bojangles/') and not name.endswith('/'):
    if hashlib.sha256(z.read(name)).hexdigest() != hashes[name]: raise ValueError('Wheel/source mismatch: ' + name)
 for old in (RELEASE / 'application').glob('*.whl'): old.unlink()
 shutil.copy2(wheel, RELEASE / 'application' / wheel.name)
 shutil.copy2(report, RELEASE / 'compilation-report.xml')
 product = json.loads((RELEASE / 'product-manifest.json').read_text())
 product.update(candidate=CANDIDATE, wpe_manifest_sha256=sha(RELEASE / 'manifest.json'))
 product['application']['sha256'] = sha(wheel)
 product['native_command']['sha256'] = sha(RELEASE / 'native-command/app/bojangles.bin')
 product['native_command']['files'] = inventory(RELEASE / 'native-command/app')
 write(RELEASE / 'product-manifest.json', product)
 record = {'schema': 1, 'candidate': CANDIDATE, 'revision': 'header-bookmarks-20261030', 'application_source_sha256': hashes, 'command_sha256': product['native_command']['sha256'], 'wpe_manifest_sha256': sha(RELEASE / 'manifest.json'), 'native_broker': json.loads((WORK / 'native-build.json').read_text()), 'compiler_jobs': 4, 'engine_rebuilt': False, 'github_commit': os.environ['GITHUB_SHA'], 'github_run': os.environ['GITHUB_RUN_ID']}
 write(RELEASE / 'source-record.json', record)
 shutil.copy2(RELEASE / 'CERTIFICATION.json', RELEASE / 'PREDECESSOR-CERTIFICATION.json')
 write(RELEASE / 'CERTIFICATION.json', {'schema': 1, 'revision': record['revision'], 'application_recompiled': True, 'native_broker_recompiled': True, 'engine_recompiled': False, 'scope': 'Bounded response headers and bookmark visibility. Anonymous live-site rendering was checked during source qualification; playback/login not certified.', 'github_commit': os.environ['GITHUB_SHA']})
 write(RELEASE / 'PACKAGING-REVISION.json', {'schema': 1, 'candidate': CANDIDATE, 'revision': record['revision'], 'application_recompiled': True, 'native_broker_recompiled': True, 'engine_recompiled': False, 'persistent_services': False})
 for p in [RELEASE, *RELEASE.rglob('*')]:
  if not p.is_symlink(): p.chmod(0o755 if p.is_dir() or p.stat().st_mode & 0o111 else 0o644)
 validation = RELEASE / 'validation'; validation.mkdir(exist_ok=True)
 shutil.copy2(OUT / 'source-native-tests.log', validation / 'header-bookmark-tests.log')
 shutil.copy2(WORK / 'input-record.json', validation / 'github-inputs.json')
 shutil.copy2(WORK / 'native-build.json', validation / 'header-native-build.json')
 audit = OUT / 'runtime-audit.json'
 run([sys.executable, SOURCE / 'scripts/runtime_dependencies.py', RELEASE, '--audit', '--output', audit])
 if not json.loads(audit.read_text())['passed']: raise ValueError('Runtime ELF audit failed')
 shutil.copy2(audit, validation / 'header-runtime-audit.json')
 compiled_checks()
 shutil.copy2(OUT / 'compiled-checks.json', validation / 'header-compiled-checks.json')
 (RELEASE / 'publication-manifest.json').unlink()
 write(RELEASE / 'publication-manifest.json', {'schema': 1, 'candidate': CANDIDATE, 'files': inventory(RELEASE)})
 digest = sha(RELEASE / 'publication-manifest.json')
 run([sys.executable, RELEASE / 'install-public-release.py', RELEASE, '--sha256', digest, '--check-runtime'])
 # Retain complete corresponding source, including the generated authority pin.
 shutil.copytree(ROOT / 'ci', SOURCE / 'ci', dirs_exist_ok=True)
 write(SOURCE / 'GITHUB-BUILD.json', record)
 binary = OUT / 'BoJangles-0.1.0-header-bookmarks-20261030-linux-x86_64.tar.gz'
 source = OUT / 'BoJangles-0.1.0-header-bookmarks-20261030-source.tar.gz'
 run(['tar', '--sort=name', '--owner=0', '--group=0', '--numeric-owner', '-czf', binary, '-C', RELEASE.parent, RELEASE.name])
 run(['tar', '--sort=name', '--owner=0', '--group=0', '--numeric-owner', '--exclude=__pycache__', '--exclude=*.pyc', '--exclude=*.egg-info', '-czf', source, '-C', SOURCE.parent, SOURCE.name])
 # Verify using the same extractor the installed Updates feature uses, without installation.
 script = '''from pathlib import Path\nfrom bojangles.update_notifications import UpdateService\nimport sys,json\nr=json.loads(Path(sys.argv[2]).read_text())\narea=UpdateService()._extract_verified(Path(sys.argv[1]),r)\nassert area.name==r['id']\nprint('Native updater accepted complete archive; no installation performed')\n'''
 metadata = {'id': CANDIDATE, 'sequence': 2026103002, 'version': '0.1.0 — header and bookmark fixes', 'date': '2026-10-30', 'notes': 'Fixes bounded HTTP response handling and cross-browser bookmark visibility. Built and tested on GitHub. Previous application retained for rollback.', 'url': f'https://github.com/EndUserOnly/BoJangles/releases/download/{TAG}/{binary.name}', 'sha256': sha(binary), 'size': binary.stat().st_size, 'manifest_sha256': digest}
 write(OUT / 'release-metadata.json', metadata)
 with tempfile.TemporaryDirectory() as td:
  env = isolated_env(td); env['PYTHONPATH'] = str(SOURCE / 'src')
  run([python, '-c', script, binary, OUT / 'release-metadata.json'], env=env)
 (OUT / 'SHA256SUMS.txt').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in (binary, source)))
 print(json.dumps(metadata, indent=2))


def isolated_env(home):
 env = os.environ.copy()
 env.update(HOME=str(home), PYTHONDONTWRITEBYTECODE='1', **{key: str(Path(home) / name) for key, name in [('XDG_DATA_HOME', 'data'), ('XDG_CONFIG_HOME', 'config'), ('XDG_CACHE_HOME', 'cache'), ('XDG_STATE_HOME', 'state'), ('XDG_RUNTIME_DIR', 'runtime')]})
 return env


def compiled_checks():
 results = []
 with tempfile.TemporaryDirectory() as temporary:
  home = Path(temporary); env = isolated_env(home)
  store = home / '.local/share/bojangles/releases'; store.mkdir(parents=True)
  (store / CANDIDATE).symlink_to(RELEASE, target_is_directory=True)
  (store / 'active.json').write_text(json.dumps({'schema': 1, 'active': CANDIDATE, 'previous': None}))
  for args in [['--help'], ['version'], ['status'], ['advertising', 'rules'], ['transcribe', '--help'], ['media', 'status'], ['maint', 'check', '--json']]:
   p = subprocess.run([str(RELEASE / 'native-command/app/bojangles.bin'), *args], env=env, capture_output=True, text=True, timeout=120, cwd='/tmp')
   results.append({'args': args, 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
   if p.returncode: write(OUT / 'compiled-checks.json', results); raise ValueError('Compiled command failed: ' + repr(args))
 write(OUT / 'compiled-checks.json', results)


if __name__ == '__main__':
 actions = {'prepare': prepare, 'broker': broker, 'bootstrap': bootstrap, 'tests': tests, 'compile': compile_app, 'package': package}
 actions[sys.argv[1]]()
