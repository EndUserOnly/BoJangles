#!/usr/bin/env python3
"""Build Ubuntu 24.04 amd64 Debian packaging outside canonical source."""
import argparse, hashlib, json, os, shutil, subprocess
from pathlib import Path

def sha(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()

def dump(p,d):
    p.write_text(json.dumps(d,indent=2)+'\n')

def inventory(root):
    result=[]
    for p in sorted(root.rglob('*')):
        if p.is_symlink():result.append({'path':p.relative_to(root).as_posix(),'symlink':os.readlink(p)})
        elif p.is_file():result.append({'path':p.relative_to(root).as_posix(),'sha256':sha(p)})
    return result

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for n in ['release','bundle','wheel','report','stage','output']:a.add_argument('--'+n,type=Path,required=True)
    args=a.parse_args()
    source=Path(__file__).resolve().parents[1]
    if args.stage.resolve().is_relative_to(source) or args.output.resolve().is_relative_to(source):
        a.error('build output must be outside canonical source')
    if args.stage.exists() or args.output.exists():a.error('use new stage and output paths')
    candidate=json.loads((args.release/'product-manifest.json').read_text())['candidate']
    r=args.stage/'usr/lib/bojangles/releases'/candidate
    shutil.copytree(args.release,r,symlinks=True)
    shutil.rmtree(r/'native-command/app')
    shutil.copytree(args.bundle,r/'native-command/app',symlinks=True)
    shutil.copy2(args.wheel,r/'application'/args.wheel.name)
    product=json.loads((r/'product-manifest.json').read_text())
    product['application']['sha256']=sha(args.wheel)
    product['native_command']['sha256']=sha(r/'native-command/app/bojangles.bin')
    product['native_command']['files']=inventory(r/'native-command/app')
    dump(r/'product-manifest.json',product)
    record=json.loads((r/'source-record.json').read_text())
    record['application_source_sha256']={p.relative_to(source/'src').as_posix():sha(p) for p in sorted((source/'src').rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
    dump(r/'source-record.json',record)
    dump(r/'DEBIAN-PACKAGING.json',{'version':'0.1.0-2','architecture':'amd64','application_recompiled':False,'compiler_jobs':4,'engine_recompiled':False,'system_release_store':'/usr/lib/bojangles/releases','persistent_workers':False,'source_authority':'matching deb-source archive'})
    if args.report.resolve() != (r/'compilation-report.xml').resolve():
        shutil.copy2(args.report,r/'compilation-report.xml')
    shutil.copy2(r/'CERTIFICATION.json',r/'PREDECESSOR-CERTIFICATION.json')
    dump(r/'CERTIFICATION.json',{'schema':1,'package':'bojangles','version':'0.1.0-2','application_recompiled':False,'compiler_jobs':4,'engine_recompiled':False,'qualification':'See accompanying DEB-VALIDATION report; previous feature qualification is historical.'})
    dump(r/'PACKAGING-REVISION.json',{'schema':1,'packaging_revision':'debian-0.1.0-2','application_recompiled':False,'engine_recompiled':False,'system_release_store':'/usr/lib/bojangles/releases','publication':'Debian artifact; see release checksums'})
    (r/'publication-manifest.json').unlink()
    dump(r/'publication-manifest.json',{'schema':1,'candidate':candidate,'files':inventory(r)})
    dump(r.parent/'active.json',{'schema':1,'active':candidate,'previous':None})
    bin=args.stage/'usr/bin';bin.mkdir(parents=True)
    (bin/'bojangles').symlink_to('/usr/lib/bojangles/releases/'+candidate+'/native-command/app/bojangles.bin')
    desktop=args.stage/'usr/share/applications';desktop.mkdir(parents=True)
    (desktop/'bojangles.desktop').write_text('[Desktop Entry]\nType=Application\nName=BoJangles\nComment=Browser and media application\nExec=/usr/bin/bojangles open\nTryExec=/usr/bin/bojangles\nTerminal=true\nCategories=Network;WebBrowser;AudioVideo;\n')
    doc=args.stage/'usr/share/doc/bojangles';doc.mkdir(parents=True)
    shutil.copy2(source/'LICENSE',doc/'copyright')
    shutil.copy2(source/'DEBIAN.md',doc/'DEBIAN.md')
    (doc/'README.Debian').write_text('Ubuntu 24.04-compatible amd64. Install with apt install ./bojangles_0.1.0-2_amd64.deb so APT resolves dependencies. Run /usr/bin/bojangles or use the desktop entry. A pre-existing ~/.local/bin/bojangles may take precedence in a shell; no private installation or user data is changed. Updates/removal use APT. No services or post-install workers are installed. GTK4 preview and models are optional.\n')
    required=json.loads((source/'runtime-dependencies.json').read_text())['required_packages']
    depends=sorted({p.split(':')[0] for p in required})
    control=args.stage/'DEBIAN';control.mkdir()
    size=sum(p.stat().st_size for p in args.stage.rglob('*') if p.is_file() and not p.is_symlink())//1024
    (control/'control').write_text('Package: bojangles\nVersion: 0.1.0-2\nArchitecture: amd64\nMaintainer: William Jackson <wm.djackson@pm.me>\nSection: web\nPriority: optional\nHomepage: https://github.com/EndUserOnly/BoJangles\nInstalled-Size: '+str(size)+'\nDepends: '+', '.join(depends)+'\nSuggests: gir1.2-gtk-4.0, libgtk-4-1\nDescription: BoJangles browser and media application\n Complete standalone application and authenticated WPE engine for\n Ubuntu 24.04-compatible amd64 desktops. Optional models are separate.\n')
    sums=[]
    for p in sorted((args.stage/'usr').rglob('*')):
        if p.is_file() and not p.is_symlink():
            with p.open('rb') as f:digest=hashlib.file_digest(f,'md5').hexdigest()
            sums.append(digest+'  '+p.relative_to(args.stage).as_posix())
    (control/'md5sums').write_text('\n'.join(sums)+'\n')
    for p in args.stage.rglob('*'):
        if not p.is_symlink():p.chmod(p.stat().st_mode & 0o777 & ~0o022)
    args.stage.chmod(0o755)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run(['dpkg-deb','--root-owner-group','-Zzstd','-z6','--build',str(args.stage),str(args.output)],check=True)
    print(json.dumps({'path':str(args.output),'sha256':sha(args.output),'depends_count':len(depends)}))

if __name__=='__main__':main()
