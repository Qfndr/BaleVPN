"""Fail if any shipped lockfile reintroduces the vulnerable DTLS arithmetic chain."""
from pathlib import Path
import json,hashlib,tomllib

root=Path(__file__).resolve().parent.parent
workspaces=['lk-signaling-rust','bale-signaling-rust','lktunnel-rust','bale-vpn-rust','bale-vpn-android/rust','vendor/webrtc-dtls']
for workspace in workspaces:
    packages=tomllib.loads((root/workspace/'Cargo.lock').read_text(encoding='utf-8'))['package']
    for package in packages:
        name,version=package['name'],package['version']
        if name=='crypto-bigint':
            assert tuple(map(int,version.split('.'))) >= (0,7,6),(workspace,name,version)
        if name=='webrtc-dtls':
            assert 'source' not in package,(workspace,'Unpatched registry DTLS')
        if name in ['p256','p384','elliptic-curve']:
            assert tuple(map(int,version.split('.'))) >= (0,14,0),(workspace,name,version)
    if workspace in ['lktunnel-rust','bale-vpn-rust','bale-vpn-android/rust','vendor/webrtc-dtls']:
        assert any(p['name']=='crypto-bigint' for p in packages),workspace

vendor=root/'vendor/webrtc-dtls'
record=json.loads((vendor/'UPSTREAM.json').read_text())
intentional={'Cargo.toml','src/curve/named_curve.rs','src/prf/mod.rs','src/prf/prf_test.rs','src/crypto/crypto_cbc.rs'}
for name,expected in record['upstream_source_sha256'].items():
    if name not in intentional:
        # Git's platform checkout can normalize text line endings.
        actual=(vendor/name).read_bytes().replace(b'\r\n',b'\n')
        assert hashlib.sha256(actual).hexdigest()==expected,('Unexpected DTLS source change',name)
print('PASS all lockfiles exclude vulnerable arithmetic; vendored DTLS source changes are bounded')
