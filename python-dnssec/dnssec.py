import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import pandas as pd
import csv
import tldextract
from tqdm import tqdm


def split(domain):
    chain = list()
    chain.append('.')

    ext = tldextract.extract(domain)
    current = ext.suffix
    chain.append(current)

    current = '.'.join([ext.domain, current])
    chain.append(current)

    # append subdomains
    subdomains = ext.subdomain.split('.')
    subdomains.reverse()
    for sub in subdomains:
        current = '.'.join([sub, current])
        chain.append(current)

    chain.reverse()
    return chain


def get_ns(domain):
    google_ns_addr = '8.8.8.8'
    request = dns.message.make_query(domain, dns.rdatatype.NS)
    response = dns.query.udp(request, google_ns_addr)
    if response.rcode() != 0:
        raise Exception(f'[get_ns] Query-error {dns.rcode.to_text(response.rcode())}')
    return response.answer[0][0].to_text()


def get_A(domain):
    google_ns_addr = '8.8.8.8'
    request = dns.message.make_query(domain, dns.rdatatype.A)
    response = dns.query.udp(request, google_ns_addr)
    if response.rcode() != 0:
        raise Exception(f'[get_A] Query-error {dns.rcode.to_text(response.rcode())}')
    return response.answer[0][0].to_text()


def get_ns_addr(domain):
    return get_A(get_ns(domain))


def unbox(answer):
    # Order answer in rrsig and rrset
    if answer[0].rdtype == dns.rdatatype.RRSIG:
        rrsig, rrset = answer
    elif answer[1].rdtype == dns.rdatatype.RRSIG:
        rrset, rrsig = answer
    else:
        raise Exception('[unbox] ERROR: None of the answers contains an RRSIG')
    return rrset, rrsig


def get_dnskey(domain):
    ns_addr = get_ns_addr(domain)
    # Get DNSKEY for zone.
    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    response = dns.query.udp(request, ns_addr, timeout=5.0)                             
    if response.rcode() != 0:
        raise Exception(f'[get_dnskey] Query-error {dns.rcode.to_text(response.rcode())}')
    if len(response.answer) != 2:
        raise Exception(f'[get_dnskey] Query-error: Query returned {len(response.answer)} results')
    return unbox(response.answer)


def get_ds(zone, parent_zone):
    ns_addr = get_ns_addr(parent_zone)
    request = dns.message.make_query(zone, dns.rdatatype.DS, want_dnssec=True)
    response = dns.query.udp(request, ns_addr, timeout=5.0)
    if response.rcode() != 0:
        raise Exception(f'[get_ds] Query-error {dns.rcode.to_text(response.rcode())}')
    if len(response.answer) != 2:
        raise Exception(f'[get_ds] Query-error: Query returned {len(response.answer)} results')
    return unbox(response.answer)


def get_digest(digest):
    if dns.dnssec._is_sha1(digest):
        return dns.dnssec.DSDigest.SHA1
    elif dns.dnssec._is_sha256(digest):
        return dns.dnssec.DSDigest.SHA256
    elif dns.dnssec._is_sha384(digest):
        return dns.dnssec.DSDigest.SHA384
    else:
        raise Exception('Digest not supported')


def validate_ds(domain, dnskey, ds):
    created_ds = dns.dnssec.make_ds(domain, dnskey, get_digest(ds.algorithm))
    return created_ds == ds


def validate_rrsigset(rrset, rrsig, domain, keys=None):
    if keys == None:
        keys = rrset
    name = dns.name.from_text(domain)
    dns.dnssec.validate(rrset, rrsig, {name: keys})
