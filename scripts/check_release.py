#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check KernelSU Modules metadata, native ELF identity and ZIP invariants.

Use --out to build a deterministic local ZIP, and --zip to validate one.
KernelSU-Modules/tools/actions/module-release performs the authoritative
registry check again before publishing.
"""
import argparse
import hashlib
from pathlib import Path
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from check_kpm import audit as audit_kpm  # noqa: E402

ID_RE = re.compile(r'^[A-Za-z][A-Za-z0-9._-]{1,63}$')
MAX_UNCOMPRESSED = 512 * 1024 * 1024


def properties(data):
    content = data.decode('utf-8')
    result = {}
    for line in content.splitlines():
        if not line or line[0] in '#!':
            continue
        if '=' not in line:
            raise ValueError(f'bad module.prop line: {line!r}')
        key, value = line.split('=', 1)
        if key in result:
            raise ValueError(f'duplicate module.prop key: {key}')
        if not key or not value:
            raise ValueError(f'empty module.prop key/value: {key}')
        result[key] = value
    for key in ('id', 'name', 'version', 'versionCode', 'author', 'description'):
        if key not in result:
            raise ValueError(f'missing module.prop key: {key}')
    if not ID_RE.fullmatch(result['id']):
        raise ValueError('invalid module id')
    if not re.fullmatch(r'[1-9]\d*', result['versionCode']) or int(result['versionCode']) > 2147483647:
        raise ValueError('versionCode must be positive signed 32-bit int')
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?',result['version']):
        raise ValueError('version must be vX.Y.Z or prerelease')
    return result


def check_metadata(prop):
    import yaml
    meta = yaml.safe_load((ROOT / 'module.yaml').read_text('utf-8'))
    if meta['schemaVersion'] != 1 or meta['id'] != prop['id']:
        raise ValueError('module.yaml and module.prop id/schema mismatch')
    if not (ROOT / meta['description']).is_file():
        raise ValueError('module.yaml description file missing')
    if meta.get('release',{}).get('assetPattern') != 'selimirror-*.zip':
        raise ValueError('unexpected release asset pattern')
    if prop['id'] != 'selimirror':
        raise ValueError('unexpected module id')


def check_entry_names(names):
    seen = set()
    for name in names:
        if (not name or name.startswith('/') or '\\' in name or '\0' in name
                or any(seg in ('', '.', '..') for seg in name.split('/'))):
            raise ValueError(f'unsafe ZIP path: {name!r}')
        if name in seen:
            raise ValueError(f'duplicate ZIP path: {name}')
        seen.add(name)
    if 'module.prop' not in seen:
        raise ValueError('ZIP root module.prop missing')


def check_bundle(module_files):
    prop = properties(module_files['module.prop'])
    check_metadata(prop)
    kpm = module_files.get('bin/selimirror.kpm')
    ctl = module_files.get('bin/rskctl')
    if not kpm or not ctl:
        raise ValueError('KPM or rskctl missing')
    result = audit_kpm_bytes(kpm)
    if result['metadata'].get('name') != prop['id']:
        raise ValueError('KPM name mismatch')
    if prop['version'] != 'v' + result['metadata'].get('version', ''):
        raise ValueError('KPM version mismatch')
    if not (ctl.startswith(b'\x7fELF\x02\x01\x01') and int.from_bytes(ctl[16:18],'little') == 2
            and int.from_bytes(ctl[18:20],'little') == 183):
        raise ValueError('unexpected controller ELF')
    if b'selimirror\0' not in ctl:
        raise ValueError('controller module name mismatch')
    checksum_data = module_files.get('FILES.sha256',b'').decode('ascii')
    for name, binary in [('bin/selimirror.kpm',kpm),('bin/rskctl',ctl)]:
        line = f'{hashlib.sha256(binary).hexdigest()}  {name}'
        if line not in checksum_data.splitlines():
            raise ValueError(f'checksum entry missing for {name}')
    return prop, result


def audit_kpm_bytes(data):
    # The auditor intentionally accepts a file, so use the repository's bundled
    # file only after verifying it matches the archive's byte-for-byte content.
    expected = (ROOT / 'module/bin/selimirror.kpm').read_bytes()
    if data != expected:
        raise ValueError('archive KPM differs from reviewed source build')
    return audit_kpm(ROOT / 'module/bin/selimirror.kpm')


def check_zip(path):
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        check_entry_names([info.filename for info in infos])
        total = 0
        files = {}
        for info in infos:
            if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('module ZIP must contain regular files only')
            if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError('encrypted or unsupported ZIP member')
            if info.file_size > MAX_UNCOMPRESSED or total + info.file_size > MAX_UNCOMPRESSED:
                raise ValueError('oversized ZIP')
            total += info.file_size
            files[info.filename] = z.read(info)
        prop, result = check_bundle(files)
    return prop, result


def create_zip(out):
    module = ROOT / 'module'
    files = sorted(p for p in module.rglob('*') if p.is_file())
    rels = [p.relative_to(module).as_posix() for p in files]
    check_entry_names(rels)
    data = dict(zip(rels,(p.read_bytes() for p in files)))
    check_bundle(data)
    out.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name in rels:
            info=zipfile.ZipInfo(name,(2026,10,19,0,0,0))
            info.create_system=3
            info.external_attr=(0o100755 if name in ('action.sh','customize.sh','bin/rskctl') else 0o100644)<<16
            info.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(info,data[name],compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,help='create and validate release ZIP')
    parser.add_argument('--zip',type=Path,help='validate an existing release ZIP')
    args=parser.parse_args()
    try:
        if args.out:
            create_zip(args.out)
        if args.out or args.zip:
            prop,kpm=check_zip(args.zip or args.out)
        else:
            module=ROOT/'module'
            prop,kpm=check_bundle({p.relative_to(module).as_posix():p.read_bytes()
                                   for p in module.rglob('*') if p.is_file()})
        print(f"PASS: {prop['id']} {prop['version']} versionCode={prop['versionCode']}, "
              f"KPM {kpm['bytes']} bytes; repository metadata and payload match")
        if args.out:
            print(f'Created {args.out} ({args.out.stat().st_size} bytes)')
    except (OSError, ValueError, UnicodeError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1,f'Release check failed: {exc}\n')

if __name__ == '__main__':
    main()
