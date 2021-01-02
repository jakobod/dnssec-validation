import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.enum
import pandas as pd
import csv
import tldextract
from tqdm import tqdm
from collections import deque


root_ds_list = ['19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5', 
                '20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D']

def split(domain):
    # Root
    chain = list()
    chain.append('.')
    
    # TLD
    ext = tldextract.extract(domain)
    current = ext.suffix
    if current != '':
        chain.append(current)

    # Domain + TLD
    if ext.domain != '':
        current = '.'.join([ext.domain, current])
        chain.append(current)

    # append subdomains
    subdomains = ext.subdomain.split('.')
    subdomains.reverse()
    for sub in subdomains:
        if sub == '':
            continue
        current = '.'.join([sub, current])
        chain.append(current)

    return deque(chain)


def filter(answer, rd_type):
    for rrset in answer:
        if rrset.rdtype == rd_type:
            return rrset
    raise Exception(f'{rd_type} not found in answer')


def query(domain, record_type, ns_addr = '8.8.8.8', want_dnssec=False):
    request = dns.message.make_query(domain, record_type, want_dnssec=want_dnssec)
    response = dns.query.udp(request, ns_addr, timeout=5.0)
    if response.rcode() != 0:
        raise Exception(f'[query] {dns.rcode.to_text(response.rcode())}')
    return response.answer


def query_ns(domain):
    answer = query(domain, dns.rdatatype.NS)
    return filter(answer, dns.rdatatype.NS)


def query_A(domain):
    answer = query(domain, dns.rdatatype.A)
    return filter(answer, dns.rdatatype.A)


def query_cname(domain):
    answer = query(domain, dns.rdatatype.CNAME)
    return filter(answer, dns.rdatatype.CNAME)


def get_ns_addrs(domain):
    ns_addrs = []
    for ns in query_ns(domain):
        ns_addrs.append(query_A(ns.to_text())[0].to_text())
    if not ns_addrs:
        raise Exception('[get_ns_addrs] No ns_addrs found')
    return ns_addrs    


def get_dnskey(domain):
    ns_addrs = get_ns_addrs(domain)
    answer = query(domain, dns.rdatatype.DNSKEY, ns_addrs[0], True)
    if len(answer) < 2:
        raise Exception(f'[get_dnskey] Query-error: Query returned an insufficient amount of results')
    return filter(answer, dns.rdatatype.DNSKEY), filter(answer, dns.rdatatype.RRSIG)


def get_ds(zone, parent_zone):
    ns_addrs = get_ns_addrs(parent_zone)
    answer = query(zone, dns.rdatatype.DS, ns_addrs[0], True)
    if len(answer) < 2:
        raise Exception(f'[get_ds] Query-error: Query returned an insufficient amount of results')
    return filter(answer, dns.rdatatype.DS), filter(answer, dns.rdatatype.RRSIG)


def select_digest(digest):
    if dns.dnssec._is_sha1(digest):
        return dns.dnssec.DSDigest.SHA1
    elif dns.dnssec._is_sha256(digest):
        return dns.dnssec.DSDigest.SHA256
    elif dns.dnssec._is_sha384(digest):
        return dns.dnssec.DSDigest.SHA384
    else:
        raise Exception('Digest not supported')


def validate_ds(domain, dnskey_set, ds_set):
    for dnskey in dnskey_set:
        for ds in ds_set:
            created_ds = dns.dnssec.make_ds(domain, dnskey, select_digest(ds.algorithm))
            if created_ds == ds:
                return True
    return False


def validate_rrsigset(rrset, rrsig, domain, keys=None):
    if keys == None:
        keys = rrset
    name = dns.name.from_text(domain)
    try:
        dns.dnssec.validate(rrset, rrsig, {name: keys})
    except Exception as e:
        return False
    return True


def get_root_ds():
    dns.dnssec