#!/usr/bin/env python3
"""Safe public DNS/TLS/HTTP differential diagnostics. No auth, no TLS bypass.

Usage: python tests/diagnose_chatgpt_dns.py [report.json]
The runner's network location is not the user's location. It cannot prove Android behavior.
"""
import concurrent.futures
import datetime
import ipaddress
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time

PROVIDERS = {
    'Comss.one': ['94.250.253.55', '212.109.195.93'],
    'GeoHide EU': ['143.20.64.192', '5.175.161.40'],
    'MagicDNS': ['109.120.177.170', '45.88.163.92'],
    'Xbox DNS': ['111.88.96.54', '111.88.96.55'],
    'Cloudflare control': ['1.1.1.1'],
    'Google control': ['8.8.8.8'],
    'MagicDNS historical': ['109.120.132.43', '94.249.177.102'],
    'GeoHide historical': ['45.13.237.213'],
    'Comss historical': ['83.220.169.155', '195.133.25.16'],
}
HOSTS = ['chatgpt.com', 'auth.openai.com', 'ws.chatgpt.com', 'www.cloudflare.com']
Q_TYPES = {'A': 1, 'AAAA': 28}

def skip_name(b, off):
    jumped = False
    hops = 0
    while True:
        if off >= len(b) or hops > 100:
            raise ValueError('invalid DNS name')
        hops += 1
        n = b[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(b):
                raise ValueError('invalid compression')
            return off + 2
        if n & 0xC0 or n > 63 or off + 1 + n > len(b):
            raise ValueError('invalid label')
        off += 1 + n

def raw_query(host, qt):
    ident = secrets.randbelow(65536)
    packet = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0)
    for label in host.split('.'):
        b = label.encode('idna')
        if not 1 <= len(b) <= 63:
            raise ValueError('invalid host')
        packet += bytes([len(b)]) + b
    return ident, packet + b'\x00' + struct.pack('!HH', qt, 1)

def dns_probe(provider, server, host, qtype):
    t0 = time.monotonic()
    result = {'provider': provider, 'server': server, 'host': host, 'qtype': qtype,
              'status': 'timeout', 'ips': [], 'rcode': None, 'ms': None}
    ident, packet = raw_query(host, Q_TYPES[qtype])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.5)
            s.sendto(packet, (server, 53))
            data, addr = s.recvfrom(4096)
        if addr[0] != server or len(data) < 12 or struct.unpack_from('!H', data, 0)[0] != ident:
            raise ValueError('mismatched DNS response')
        flags, questions, answers = struct.unpack_from('!HHH', data, 2)
        if not flags & 0x8000:
            raise ValueError('not a DNS response')
        result['rcode'] = flags & 0x0f
        result['truncated'] = bool(flags & 0x0200)
        p = 12
        for _ in range(questions):
            p = skip_name(data, p) + 4
            if p > len(data):
                raise ValueError('incomplete question')
        ips = []
        for _ in range(min(answers, 200)):
            p = skip_name(data, p)
            if p + 10 > len(data):
                raise ValueError('incomplete answer')
            rrtype, rrclass, ttl, length = struct.unpack_from('!HHIH', data, p)
            p += 10
            if p + length > len(data):
                raise ValueError('incomplete rdata')
            if rrclass == 1 and (rrtype, length) in ((1, 4), (28, 16)):
                ip = str(ipaddress.ip_address(data[p:p+length]))
                if ip not in ips:
                    ips.append(ip)
            p += length
        result['ips'] = ips
        result['status'] = 'ok' if result['rcode'] == 0 else 'dns-error'
    except Exception as e:
        result['error'] = str(e)[:160]
    result['ms'] = round((time.monotonic() - t0) * 1000)
    return result

def https_probe(host, ip, provider, server, path="/"):
    t0 = time.monotonic()
    result = {'host': host, 'ip': ip, 'provider': provider, 'server': server,
              'status': None, 'redirect': None, 'curl_exit': None, 'tls_verified': None, 'path': path}
    if not ipaddress.ip_address(ip).is_global:
        result['error'] = 'Non-public IP: do not connect to resolver supplied address'
        return result
    args = ['curl', '--noproxy', '*', '--silent', '--show-error', '--http1.1', '--output', '/dev/null',
            '--dump-header', '-', '--connect-timeout', '6', '--max-time', '11',
            '--resolve', f'{host}:443:{ip}', '--write-out', '\nDIAG-CODE:%{http_code};VERIFY:%{ssl_verify_result};REMOTE:%{remote_ip}\n',
            f'https://{host}{path}']
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, errors='replace', timeout=14)
        result['curl_exit'] = p.returncode
        result['stderr'] = p.stderr.strip()[:200]
        for ln in p.stdout.splitlines():
            if ln.startswith('HTTP/'):
                parts = ln.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    result['status'] = int(parts[1])
            elif ln.lower().startswith('location:'):
                result['redirect'] = ln.split(':', 1)[1].strip()[:220]
            elif ln.startswith('DIAG-CODE:'):
                fields = dict(pair.split(':', 1) for pair in ln.split(';') if ':' in pair)
                result['tls_verified'] = (fields.get('VERIFY') == '0' and p.returncode == 0)
        if p.returncode == 0 and result['status'] in (301, 302, 303, 307, 308):
            result['explanation'] = 'redirect: not automatically an error'
        elif result['status'] in (401, 403, 451):
            result['explanation'] = 'HTTP refusal from endpoint; not a DNS status'
        elif p.returncode != 0:
            result['explanation'] = 'TLS, TCP, timeout or network-layer failure'
        elif result['status'] in (200, 204):
            result['explanation'] = 'HTTPS response received; login/app functionality untested'
    except Exception as e:
        result['error'] = str(e)[:160]
    result['ms'] = round((time.monotonic() - t0) * 1000)
    return result

def main():
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tasks = [(p,s,h,q) for p, servers in PROVIDERS.items() for s in servers for h in HOSTS for q in Q_TYPES]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        dns = list(ex.map(lambda task: dns_probe(*task), tasks))
    https_tasks = []
    seen_routes = set()
    for row in dns:
        if row['host'] not in ('chatgpt.com', 'auth.openai.com') or row['qtype'] != 'A':
            continue
        for ip in row['ips'][:8]:
            key = (row['host'], ip, row['provider'])
            if key in seen_routes:
                continue
            seen_routes.add(key)
            https_tasks.append((row['host'], ip, row['provider'], row['server'], '/'))
            if row['host'] == 'chatgpt.com':
                https_tasks.append((row['host'], ip, row['provider'], row['server'], '/auth/login'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        https = list(ex.map(lambda task: https_probe(*task), https_tasks))
    report = {'timestamp_utc': now, 'vantage': os.environ.get('GITHUB_RUNNER_NAME', 'local'),
              'warning': 'GitHub-hosted network != Android/user network; no VPN or cookies tested.',
              'dns': dns, 'https': https}
    out = sys.argv[1] if len(sys.argv) > 1 else 'dns_chatgpt_report.json'
    with open(out, 'w', encoding='utf8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print('Date:', now)
    print('DNS results (rcode, IPs; timeout means no UDP reply from THIS network):')
    for p, servers in PROVIDERS.items():
        for s in servers:
            arr = [x for x in dns if x['provider'] == p and x['server'] == s and x['host'] == 'chatgpt.com']
            print(f'{p:19} {s:16}', ', '.join(f"{x['qtype']}={x['status']}({','.join(x['ips'][:3]) or '-'})" for x in arr))
    print('HTTPS chatgpt.com via each returned A record (TLS cert validation ON):')
    for x in https:
        if x['host'] == 'chatgpt.com':
            print(f"{x['provider']:19} {x['server']:16} {x['ip']:16} path={x['path']:12} http={x['status']} exit={x['curl_exit']} tls={x['tls_verified']} redirect={x['redirect']} {x.get('stderr', '')[:85]}")
    print('Report:', out)
    # A silent DNS network is a diagnostic outcome, not a script failure.

if __name__ == '__main__':
    main()
