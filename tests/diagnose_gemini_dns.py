#!/usr/bin/env python3
"""Public diagnostic; probe DNS and HTTPS for Gemini and ChatGPT from GitHub runner (not user's phone)."""
import json, random, socket, struct, subprocess, time
HOSTS = ('gemini.google.com', 'chatgpt.com')
SERVERS = {
  'Comss.one': ['94.250.253.55','212.109.195.93'],
  'GeoHide EU': ['143.20.64.192','5.175.161.40'],
  'MagicDNS': ['109.120.177.170','45.88.163.92'],
  'Xbox DNS': ['111.88.96.54','111.88.96.55'],
  'Cloudflare baseline': ['1.1.1.1'],
}
def dns_a(host, server):
    xid=random.randint(0,65535)
    request=struct.pack('!HHHHHH',xid,0x0100,1,0,0,0)
    for label in host.split('.'):
        request+=bytes([len(label)])+label.encode('ascii')
    request+=b'\x00\x00\x01\x00\x01'
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.5)
        sock.sendto(request,(server,53));data,addr=sock.recvfrom(4096)
    except OSError as e:return {'dns_error':type(e).__name__}
    finally:sock.close()
    if addr[0]!=server or len(data)<12 or int.from_bytes(data[:2],'big')!=xid:
        return {'dns_error':'invalid reply'}
    def skip(n):
        for _ in range(128):
            if n>=len(data):raise ValueError('truncated')
            length=data[n];n+=1
            if length==0:return n
            if length & 0xc0==0xc0:return n+1
            if length>63 or n+length>len(data):raise ValueError('name')
            n+=length
        raise ValueError('labels')
    try:
        p=12
        for _ in range(int.from_bytes(data[4:6],'big')):p=skip(p)+4
        addresses=[]
        for _ in range(min(48,int.from_bytes(data[6:8],'big'))):
            p=skip(p)
            kind,klass,ttl,size=struct.unpack('!HHIH',data[p:p+10]);p+=10
            if p+size>len(data):break
            if kind==1 and klass==1 and size==4:
                ip='.'.join(map(str,data[p:p+4]))
                if ip not in addresses:addresses.append(ip)
            p+=size
        return {'rcode':data[3]&15,'ips':addresses}
    except (ValueError,IndexError,struct.error):return {'dns_error':'malformed answer'}
def https(host, ip):
    try:
        p=subprocess.run(['curl','-sS','-o','/dev/null','--max-time','5','--connect-timeout','2',
           '--resolve',f'{host}:443:{ip}', '-w','%{http_code}|%{ssl_verify_result}|%{redirect_url}',
           'https://'+host+'/'],capture_output=True,text=True,timeout=7)
        status,verify,redirect=(p.stdout.split('|',2)+['',''])[:3]
        return {'http':int(status) if status.isdigit() else None,
                'tls_valid':p.returncode==0 and verify=='0',
                'redirect':redirect[:160] or None,
                'curl_exit':p.returncode,
                'error':p.stderr[:160] if p.returncode else None}
    except Exception as e:return {'error':type(e).__name__}
results={}
for host in HOSTS:
    results[host]={}
    print('\n'+host,flush=True)
    for provider,servers in SERVERS.items():
        found={}
        for dns in servers:
            a=dns_a(host,dns)
            for ip in a.get('ips',[])[:4]:
                if ip not in found and ip!='0.0.0.0':found[ip]=https(host,ip)
            print(provider,dns,a,'https=',found,flush=True)
        results[host][provider]=found
open('gemini_chatgpt_dns_report.json','w').write(json.dumps(results,ensure_ascii=False,indent=2))
