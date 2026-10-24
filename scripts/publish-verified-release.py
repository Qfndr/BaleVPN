"""Prepare verified CI artifacts; publish only with an explicit --publish flag.

Publication additionally requires explicit user authorization under AGENTS.md.
This script never reads account data or signing private keys.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ['windows-x86_64', 'linux-x86_64', 'macos-aarch64', 'macos-x86_64']
WORKSPACES = ['lk-signaling-rust', 'bale-signaling-rust', 'lktunnel-rust',
              'bale-vpn-rust', 'bale-vpn-android-rust', 'vendor-webrtc-dtls']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def gh(*args, json_result=False):
    result = subprocess.check_output(['gh', *map(str, args)], cwd=ROOT, text=True, encoding='utf-8')
    return json.loads(result) if json_result else result.strip()


def verify_binary(data, target, headless):
    if target.startswith('windows'):
        assert data[:2] == b'MZ'
        pe = int.from_bytes(data[60:64], 'little')
        assert data[pe:pe+4] == b'PE\0\0'
        assert int.from_bytes(data[pe+4:pe+6], 'little') == 0x8664
        if not headless:
            assert int.from_bytes(data[pe+92:pe+94], 'little') == 2, 'GUI console subsystem'
    elif target.startswith('linux'):
        assert data[:5] == b'\x7fELF\x02'
        assert int.from_bytes(data[18:20], 'little') == 62
    else:
        assert data[:4] == b'\xcf\xfa\xed\xfe', 'Expected thin 64-bit Mach-O'
        assert struct.unpack('<I', data[4:8])[0] == (0x100000c if 'aarch64' in target else 0x1000007)


def verify_bundle(path, version, commit, target, headless):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), 'Duplicate ZIP entries'
        for name in names:
            part = PurePosixPath(name)
            assert not part.is_absolute() and '..' not in part.parts and '\\' not in name
            assert not any(p in ('data', 'client-data', '.git') for p in part.parts)
        info = json.loads(archive.read('build-info.json'))
        assert (info['version'], info['source_commit'], info['target'], info['headless']) == (version, commit, target, headless)
        binary = archive.read(info['binary'])
        assert digest(binary) == info['binary_sha256']
        verify_binary(binary, target, headless)
        listed = set()
        for line in archive.read('SHA256SUMS.txt').decode().splitlines():
            sha, name = line.split('  ', 1)
            assert digest(archive.read(name)) == sha, name
            listed.add(name)
        assert listed == set(names) - {'SHA256SUMS.txt'}, 'Incomplete manifest'
        if not target.startswith('windows'):
            assert (archive.getinfo(info['binary']).external_attr >> 16) & 0o111
        return info


def find_release(repo, tag):
    # The tag endpoint returns published releases. Authenticated list/get-by-ID
    # endpoints also expose drafts, including drafts with no Git tag yet.
    pages = gh('api', f'repos/{repo}/releases', '--paginate', '--slurp', json_result=True)
    matches = [release for page in pages for release in page if release['tag_name'] == tag]
    assert len(matches) <= 1, 'Ambiguous release tag'
    return matches[0] if matches else None


def publish_assets(repo, tag, commit, assets, notes):
    release = find_release(repo, tag)
    if release is None:
        gh('release', 'create', tag, '-R', repo, '--target', commit, '--draft',
           '--title', 'BaleVPN '+tag.removeprefix('v'), '--notes-file', notes)
        release = find_release(repo, tag)
    assert release and release['draft'], 'Refusing to modify an already published release'
    assert release['target_commitish'] == commit, 'Existing draft targets different source'
    endpoint = f'repos/{repo}/releases/{release["id"]}'
    expected = {f.name: 'sha256:'+digest(f.read_bytes()) for f in assets.iterdir() if f.is_file()}
    current = {a['name']: a for a in release['assets']}
    assert not set(current) - set(expected), 'Draft contains unreviewed assets'
    pending = [assets/name for name, sha in expected.items()
               if current.get(name, {}).get('digest') != sha
               or current.get(name, {}).get('state') != 'uploaded']
    if pending:
        gh('release', 'upload', tag, '-R', repo, *sorted(pending), '--clobber')
    release = gh('api', endpoint, json_result=True)
    assert release['draft'] and release['target_commitish'] == commit
    assert all(a['state'] == 'uploaded' for a in release['assets'])
    assert {a['name']: a.get('digest') for a in release['assets']} == expected, 'Remote asset set or SHA256 differs'
    gh('release', 'edit', tag, '-R', repo, '--draft=false', '--latest')
    final = gh('api', endpoint, json_result=True)
    assert not final['draft'] and final['target_commitish'] == commit
    assert {a['name']: a.get('digest') for a in final['assets']} == expected
    print('Published:', final['html_url'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['desktop-run', 'android-run', 'checks-run']:
        p.add_argument('--'+name, required=True, type=int)
    p.add_argument('--repo', default='Qfndr/BaleVPN')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--publish', action='store_true')
    args = p.parse_args()
    version = (ROOT/'VERSION').read_text().strip()
    assert re.fullmatch(r'\d+\.\d+\.\d+', version)
    tag = 'v'+version
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip(), 'Commit all release source first'
    remote = gh('api', f'repos/{args.repo}/branches/main', json_result=True)
    assert remote['commit']['sha'] == commit, 'main must contain the exact source'
    evidence = args.output/'build-artifacts'
    evidence.mkdir(parents=True, exist_ok=True)
    runs = {}
    for kind, run, workflow in [('desktop', args.desktop_run, 'bale-vpn-rust.yml'),
                                 ('android', args.android_run, 'android.yml'),
                                 ('checks', args.checks_run, 'rust.yml')]:
        record = gh('api', f'repos/{args.repo}/actions/runs/{run}', json_result=True)
        assert record['head_sha'] == commit and record['conclusion'] == 'success', (kind, record['conclusion'])
        assert record['path'] == '.github/workflows/'+workflow and record['event'] in ('push', 'workflow_dispatch')
        runs[kind] = {'id': run, 'url': record['html_url'], 'commit': commit}

    def download(run, name):
        destination = evidence/name
        destination.mkdir(exist_ok=True)
        # gh refuses overwrite; an isolated fresh subdirectory makes retries safe.
        temp = evidence/(name+'-download')
        if temp.exists():
            assert temp.resolve().parent == evidence.resolve()
            shutil.rmtree(temp)
        gh('run', 'download', run, '-R', args.repo, '-n', name, '-D', temp)
        shutil.copytree(temp, destination, dirs_exist_ok=True)
        shutil.rmtree(temp)
        return destination

    assets = args.output/'release-assets'
    assets.mkdir(exist_ok=True)
    # Artifacts have disjoint destinations. Fetch independently so a slow
    # platform download does not serialize every other platform behind it.
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = {name: pool.submit(download, run, name) for run, name in
                   [(args.desktop_run, 'bale-vpn-'+target) for target in TARGETS]+
                   [(args.android_run, 'BaleVpn-release-apk'), (args.checks_run, 'security-evidence')]}
        downloaded = {}
        for name, future in pending.items():
            downloaded[name] = future.result()
            print('Downloaded:', name, flush=True)
    verified = []
    for target in TARGETS:
        source = downloaded['bale-vpn-'+target]
        for headless in [False, True]:
            variant = 'headless' if headless else 'desktop'
            bundle = source/f'BaleVPN-{variant}-{target}.zip'
            info = verify_bundle(bundle, version, commit, target, headless)
            raw = source/('bale-vpn-'+('headless' if headless else 'gui')+'-'+target+('.exe' if target.startswith('windows') else ''))
            assert digest(raw.read_bytes()) == info['binary_sha256']
            shutil.copy2(bundle, assets/bundle.name)
            shutil.copy2(raw, assets/raw.name)
            verified.append(info)
            local = {'windows-x86_64': 'Windows-x64', 'linux-x86_64': 'Linux-Desktop-x64',
                     'macos-aarch64': 'macOS-AppleSilicon', 'macos-x86_64': 'macOS-Intel'}[target]
            if headless:
                local = 'Linux-x64' if target == 'linux-x86_64' else local+'-Headless'
            destination = args.output/local
            destination.mkdir(exist_ok=True)
            # verify_bundle checks traversal before extraction; preserve existing data.
            with zipfile.ZipFile(bundle) as archive:
                archive.extractall(destination)
                for item in archive.infolist():
                    (destination/item.filename).chmod((item.external_attr >> 16) & 0o777)

    android = downloaded['BaleVpn-release-apk']
    manifest = json.loads((android/'signing-manifest.json').read_text())
    assert manifest['version'] == version and manifest['source_commit'] == commit
    assert manifest['signature_verified'] and manifest['release_signing_configured']
    assert manifest['signing_certificate_sha256'] == (ROOT/'release/android-signing-certificate.sha256').read_text().strip()
    apk = android/manifest['apk']
    assert digest(apk.read_bytes()) == manifest['sha256']
    assert manifest['abis'] == ['arm64-v8a', 'armeabi-v7a']
    with zipfile.ZipFile(apk) as archive:
        for abi, machine in [('arm64-v8a', 183), ('armeabi-v7a', 40)]:
            binary = archive.read('lib/'+abi+'/liblktunnel_jni.so')
            assert binary[:4] == b'\x7fELF' and int.from_bytes(binary[18:20], 'little') == machine
    for name in [f'BaleVpn-{version}-release.apk', 'BaleVpn-release.apk']:
        shutil.copy2(apk, assets/name)
    shutil.copy2(android/'signing-manifest.json', assets/'android-signing-manifest.json')
    audit = downloaded['security-evidence']
    for workspace in WORKSPACES:
        report = json.loads((audit/(workspace+'.json')).read_text())
        assert report['vulnerabilities']['count'] == 0 and not report['vulnerabilities']['found']
    assert 'PASS' in (audit/'crypto-dependencies.txt').read_text()
    shutil.make_archive(str(assets/'security-evidence'), 'zip', audit)
    report = {'version': version, 'source_commit': commit, 'runs': runs,
              'native_bundles': verified, 'android': manifest, 'dependency_vulnerabilities': 0,
              'limits': 'No live Bale call, real-network throughput, physical Android or interactive macOS GUI test claimed.'}
    (assets/'build-verification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    (assets/'SHA256SUMS.txt').write_text(''.join(digest(f.read_bytes())+'  '+f.name+'\n'
        for f in sorted(assets.iterdir()) if f.is_file() and f.name != 'SHA256SUMS.txt'), encoding='utf-8')
    print('PASS verified exact-commit native bundles, Android signature manifest and six security audits')
    if not args.publish:
        print('Prepared for review:', assets)
        return
    publish_assets(args.repo, tag, commit, assets, ROOT/'release'/f'{tag}.md')


if __name__ == '__main__':
    main()
