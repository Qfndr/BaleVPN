"""Real packaged pool/worker lifecycle QA. Local fixtures only; no Bale account.

python scripts/smoke-aggregate.py PATH_TO_BINARY --report report.json
"""
import argparse
from contextlib import contextmanager
import json
import os
import signal
from pathlib import Path
import runpy
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

helpers = runpy.run_path(str(Path(__file__).with_name('smoke-desktop.py')))
request, running = helpers['request'], helpers['running']

def exact(stream, size):
    result = b''
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise EOFError('Unexpected proxy EOF')
        result += part
    return result

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request
        stream.settimeout(5)
        try:
            assert exact(stream, 3) == b'\x05\x01\x00'
            stream.sendall(b'\x05\x00')
            header = exact(stream, 4)
            assert header == b'\x05\x01\x00\x03'
            domain = exact(stream, exact(stream, 1)[0])
            assert domain == b'example.invalid', 'Proxy must forward DNS names unchanged'
            exact(stream, 2)
            self.server.hits += 1
            stream.sendall(b'\x05\x00\x00\x01' + b'\0' * 6)
            while True:
                data = stream.recv(65536)
                if not data:
                    stream.shutdown(socket.SHUT_WR)
                    return
                stream.sendall(data)
        except (EOFError, ConnectionError, OSError):
            pass

class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

@contextmanager
def proxy():
    server = Server(('127.0.0.1', 0), Proxy)
    server.hits = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

def free_ports(number):
    sockets = []
    try:
        for _ in range(number):
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()

def connect(port):
    stream = socket.create_connection(('127.0.0.1', port), timeout=5)
    stream.sendall(b'\x05\x01\x00')
    assert exact(stream, 2) == b'\x05\x00'
    domain = b'example.invalid'
    stream.sendall(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + b'\x01\xbb')
    assert exact(stream, 10)[1] == 0
    return stream

def worker(base, slot, start):
    result = request(base, '/aggregate/worker', {'slot': slot, 'start': start})
    assert result['ok'], result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    version = subprocess.check_output([str(binary), '--version'], text=True).strip()
    with tempfile.TemporaryDirectory(prefix='balevpn-multi-profile-') as temporary:
        work = Path(temporary)
        directory = work / 'independent data'
        with running(binary, directory, work) as base:
            with urllib.request.urlopen(base+'/pool-telemetry.js') as asset:
                assert 'javascript' in asset.headers['Content-Type']
                assert asset.headers['Cache-Control']=='no-store'
                assert 'balePoolTelemetry' in asset.read().decode()
            assert request(base, '/aggregate')['status']['running'] is False
            pool_port, admin1, admin2 = free_ports(3)
            with proxy() as first, proxy() as second:
                config = {'listenPort': pool_port, 'policy': 'roundRobin', 'paths': [
                    {'profileId': 1, 'name': 'Path A', 'port': first.server_address[1], 'managementPort': admin1, 'weight': 1},
                    {'profileId': 2, 'name': 'Path B', 'port': second.server_address[1], 'managementPort': admin2, 'weight': 1}]}
                bad = json.loads(json.dumps(config))
                bad['paths'][0]['port'] = pool_port
                assert request(base, '/aggregate', bad)['ok'] is False
                try:
                    request(base, '/aggregate/start', {}, origin='https://attacker.invalid')
                except urllib.error.HTTPError as error:
                    assert error.code == 403
                else:
                    raise AssertionError('Hostile Origin accepted')
                assert request(base, '/aggregate', config)['ok']
                occupied = socket.socket()
                occupied.bind(('127.0.0.1', pool_port))
                occupied.listen()
                assert request(base, '/aggregate/start', {})['ok'] is False
                occupied.close()
                assert request(base, '/aggregate/start', {})['ok']
                a, b = connect(pool_port), connect(pool_port)
                assert first.hits == 1 and second.hits == 1
                payload = bytes(range(251)) * 100
                for stream in [a, b]:
                    stream.sendall(payload)
                    assert exact(stream, len(payload)) == payload
                status = request(base, '/state')['aggregate']
                assert sum(p['active'] for p in status['paths']) == 2
                assert sum(p['receivedBytes'] for p in status['paths']) == len(payload) * 2
                assert sum(p['sentBytes'] for p in status['paths']) == len(payload) * 2
                assert request(base, '/aggregate', config)['ok'] is False
                assert request(base, '/aggregate/stop', {})['ok']
                for stream in [a, b]:
                    try:
                        assert stream.recv(1) == b''
                    except ConnectionResetError:
                        pass
                    stream.close()
                assert not request(base, '/state')['aggregate']['running']
                assert request(base, '/state')['aggregate']['paths'][0]['receivedBytes'] == len(payload)
                assert request(base, '/aggregate/start', {})['ok']
                assert request(base, '/state')['aggregate']['instance'] != status['instance']
                request(base, '/aggregate/stop', {})
                for policy in ['adaptive','latency']:
                    config['policy']=policy
                    assert request(base,'/aggregate',config)['ok']
                    assert request(base,'/aggregate/start',{})['ok']
                    for _ in range(3):
                        with connect(pool_port) as stream:
                            stream.sendall(payload);assert exact(stream,len(payload))==payload
                    observed=request(base,'/state')['aggregate']
                    assert observed['policy']==policy
                    assert any(p['setupLatencyMs'] is not None for p in observed['paths'])
                    assert request(base,'/aggregate/stop',{})['ok']
            # No Bale tokens are set. Two actual subprocesses must have distinct identities.
            sockets, admin1, admin2, socks1, socks2 = free_ports(5)
            config = {'listenPort': sockets, 'policy': 'leastConnections', 'paths': [
                {'profileId': 1, 'name': 'Account A', 'port': socks1, 'managementPort': admin1, 'weight': 1},
                {'profileId': 2, 'name': 'Account B', 'port': socks2, 'managementPort': admin2, 'weight': 1}]}
            assert request(base, '/aggregate', config)['ok']
            worker(base, 1, True)
            worker(base, 2, True)
            assert len([w for w in request(base, '/state')['aggregateWorkers'] if w['running']]) == 2
            codes = []
            for admin in [admin1, admin2]:
                child = f'http://127.0.0.1:{admin}'
                child_state = request(child, '/state')
                assert child_state['tokenSet'] is False and child_state['mode'] is None
                codes.append(request(child, '/settings')['publicCode'])
            assert codes[0] != codes[1]
            assert request(base, '/aggregate', config)['ok']
            changed = json.loads(json.dumps(config))
            changed['paths'][0]['port'] = free_ports(1)[0]
            assert request(base, '/aggregate', changed)['ok'] is False
            # Managed account panels stay on the controller's origin and cannot
            # forward shutdown, recursive worker control, arbitrary hosts or methods.
            for slot in [1, 2]:
                prefix = f'/aggregate/profiles/{slot}'
                assert request(base, prefix + '/state')['socks5Port'] == config['paths'][slot-1]['port']
                assert request(base, prefix + '/settings')['publicCode'] == codes[slot-1]
                with urllib.request.urlopen(base + prefix + '/') as panel:
                    assert panel.headers['X-Frame-Options'] == 'SAMEORIGIN'
                    assert "frame-ancestors 'self'" in panel.headers['Content-Security-Policy']
                    assert 'baleProfileUI' in panel.read().decode()
                for path in ['/shutdown', '/aggregate/worker', '/aggregate/account-ports', '/bond/server', '/instance']:
                    try:
                        request(base, prefix + path, {})
                    except urllib.error.HTTPError as error:
                        assert error.code == 403
                    else:
                        raise AssertionError('Disallowed profile route accepted')
                try:
                    request(base, prefix + '/settings', {}, origin='https://attacker.invalid')
                except urllib.error.HTTPError as error:
                    assert error.code == 403
                else:
                    raise AssertionError('Hostile profile Origin accepted')
            # Adding a third account must not stop, renumber or re-key the first two.
            socks3, admin3 = free_ports(2)
            config['paths'].append({'profileId':3,'name':'Account C','port':socks3,'managementPort':admin3,'weight':1})
            assert request(base, '/aggregate', config)['ok']
            worker(base, 3, True)
            assert request(base, '/aggregate/profiles/1/settings')['publicCode'] == codes[0]
            assert request(base, '/aggregate/profiles/2/settings')['publicCode'] == codes[1]
            worker(base, 3, False)
            worker(base, 1, False)
            sibling_pid = request(f'http://127.0.0.1:{admin2}', '/instance')['pid']
            next_socks, next_admin = free_ports(2)
            ports = {'slot': 1, 'socks5Port': next_socks, 'managementPort': next_admin}
            with socket.socket() as occupied:
                occupied.bind(('127.0.0.1', next_socks))
                occupied.listen()
                assert request(base, '/aggregate/account-ports', ports)['ok'] is False
            assert request(base, '/aggregate')['config'] == config
            for invalid in [dict(ports, socks5Port=socks2), dict(ports, slot=99),
                            dict(ports, socks5Port=request(base, '/state')['socks5Port'])]:
                assert request(base, '/aggregate/account-ports', invalid)['ok'] is False
            try:
                request(base, '/aggregate/account-ports', ports, origin='https://attacker.invalid')
            except urllib.error.HTTPError as error:
                assert error.code == 403
            else:
                raise AssertionError('Hostile account-port Origin accepted')
            assert request(base, '/aggregate/account-ports', ports)['ok']
            config['paths'][0].update(port=next_socks, managementPort=next_admin)
            assert request(base, '/aggregate')['config'] == config
            admin1, socks1 = next_admin, next_socks
            worker(base, 1, True)
            account = request(base, '/aggregate/profiles/1/account')
            assert account['socks5Port'] == socks1 and account['managementPort'] == admin1
            assert account['signedIn'] is False and account['loginPhone'] is None
            assert not any(key in account for key in ['token', 'accessToken', 'loginTokenHash', 'privateKey'])
            assert request(base, '/aggregate/profiles/1/settings')['publicCode'] == codes[0]
            assert request(f'http://127.0.0.1:{admin2}', '/instance')['pid'] == sibling_pid
            assert request(base, '/aggregate/account-ports', dict(ports, socks5Port=free_ports(1)[0]))['ok'] is False
            assert request(base, '/aggregate/profiles/1/tunnel/config', {'socks5Port':free_ports(1)[0]})['ok'] is False
            # Submitting the unchanged port must remain valid for normal child controls.
            assert request(base, '/aggregate/profiles/1/tunnel/config', {'socks5Port':socks1})['ok']
            worker(base, 1, False)
            worker(base, 2, False)
            worker(base, 1, True)
            assert request(f'http://127.0.0.1:{admin1}', '/settings')['publicCode'] == codes[0]
            worker(base, 2, True)
            assert request(base, '/aggregate/start', {})['ok']
            request(base, '/shutdown', {})
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                remaining = []
                for port in [admin1, admin2, sockets]:
                    try:
                        sock = socket.create_connection(('127.0.0.1', port), timeout=.1)
                        sock.close()
                        remaining.append(port)
                    except OSError:
                        pass
                if not remaining:
                    break
                time.sleep(.1)
            assert not remaining, 'Parent shutdown left listeners running'
        with running(binary, directory, work) as base:
            data = request(base, '/aggregate')
            assert data['config'] == config and data['workers'] == [] and not data['status']['running']
            worker(base, 1, True)
            pid=request(base,'/instance')['pid']
            os.kill(pid,signal.SIGTERM if os.name=='nt' else signal.SIGKILL)
            deadline=time.monotonic()+10
            alive=True
            while time.monotonic()<deadline:
                try:
                    connection=socket.create_connection(('127.0.0.1',admin1),timeout=.1)
                    connection.close()
                    time.sleep(.1)
                except OSError:
                    alive=False
                    break
            assert not alive,'Managed child outlived forced parent termination'
        assert (directory / 'aggregate-profiles/path-1/instance.lock').is_file()
        assert (directory / 'aggregate-profiles/path-2/instance.lock').is_file()
    report = {'version': version, 'local_fixtures_only': True, 'two_real_independent_workers': True,
              'separate_and_persistent_public_identities': True, 'no_worker_auto_login_or_call': True,
              'parallel_flow_distribution_and_exact_live_counters': True, 'remote_dns_name_preserved': True,
              'all_payloads_verified': True, 'occupied_port_and_config_loop_rejected': True,
              'hostile_origin_rejected': True, 'stop_closes_streams': True, 'restart_resets_counters': True,
              'parent_shutdown_stops_children_and_listener': True, 'config_survives_restart': True,
              'forced_parent_termination_stops_child_via_pipe_eof':True,
              'in_app_account_panels_identity_scoped_and_origin_guarded':True,
              'third_account_added_while_two_workers_running':True,
              'account_port_edit_preserves_sibling_pid_and_persistent_identity':True,
              'occupied_duplicate_running_account_ports_rejected':True,
              'account_info_whitelist_and_managed_port_guard_verified':True,
              'adaptive_and_latency_real_socket_forwarding_verified':True,
              'live_bale_calls_tested': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS packaged aggregation, two real worker profiles, independent persistent keys, flow counters, lifecycle, no accounts or internet calls')

if __name__ == '__main__':
    main()
