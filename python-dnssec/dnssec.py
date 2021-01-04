import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import tldextract
from collections import deque
from exception import *


def split(domain):
    # Root
    chain = list()
    chain.append('.')

    # TLD
    ext = tldextract.extract(domain)
    current = ext.suffix + '.'
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


def get_rrset(answer, rd_type):
    for rrset in answer:
        if rrset.rdtype == rd_type:
            return rrset
    raise RecordMissingError(
        f'{dns.rdatatype.to_text(rd_type)} not found in answer')


def query(domain, record_type, ns_addr='8.8.8.8', want_dnssec=False):
    request = dns.message.make_query(
        domain, record_type, want_dnssec=want_dnssec)
    response = dns.query.udp(request, ns_addr, timeout=5.0)
    if response.rcode() != 0:
        raise QueryError(f'{dns.rcode.to_text(response.rcode())}')
    return response


def query_ns(domain):
    response = query(domain, dns.rdatatype.NS)
    return get_rrset(response.answer, dns.rdatatype.NS)


def query_A(domain):
    response = query(domain, dns.rdatatype.A)
    return get_rrset(response.answer, dns.rdatatype.A)


def query_cname(domain):
    response = query(domain, dns.rdatatype.CNAME)
    return get_rrset(response.answer, dns.rdatatype.CNAME)


def query_ns_addrs(domain):
    ns_addrs = []
    for ns in query_ns(domain):
        ns_addrs.append(query_A(ns.to_text())[0].to_text())
    if not ns_addrs:
        raise NotFoundError('[get_ns_addrs] No ns_addrs found')
    return ns_addrs


def query_dnskey(domain):
    ns_addrs = query_ns_addrs(domain)
    response = query(domain, dns.rdatatype.DNSKEY, ns_addrs[0], True)
    return get_rrset(response.answer, dns.rdatatype.DNSKEY), get_rrset(response.answer, dns.rdatatype.RRSIG)


def query_ds(zone, parent_zone):
    ns_addrs = query_ns_addrs(parent_zone)
    response = query(zone, dns.rdatatype.DS, ns_addrs[0], True)
    return get_rrset(response.answer, dns.rdatatype.DS), get_rrset(response.answer, dns.rdatatype.RRSIG)


def select_digest(digest):
    if digest == 1:
        return dns.dnssec.DSDigest.SHA1
    elif digest == 2:
        return dns.dnssec.DSDigest.SHA256
    elif digest == 4:
        return dns.dnssec.DSDigest.SHA384
    else:
        raise NotFoundError(f'[select_digest] Digest not supported: {digest}')


def validate_zsk(domain, zsk_set, ds_set):
    if not zsk_set:
        raise EmptyError('empty ZSK set')
    if not ds_set:
        raise EmptyError('empty DS set set')
    for ds in ds_set:
        zsk_ds = dns.dnssec.make_ds(domain, get_zsk(
            zsk_set), ds.digest_type)
        print(f'DS = {type(ds)}: {ds}')
        print(f'ZSK_DS = {type(zsk_ds)}: {zsk_ds}')
        if ds == zsk_ds:
            return
    raise ZSKValidationError(domain)


def get_zsk(keyset):
    for key in keyset:
        if key.flags == 257:
            return key
    raise NotFoundError()


def validate_root_zsk(dnskey_set):
    # https://data.iana.org/root-anchors/root-anchors.xml
    root_ds_list = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5',
                    '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
    zsk = get_zsk(dnskey_set)
    ds = dns.dnssec.make_ds('.', zsk, dns.dnssec.DSDigest.SHA256)
    for root_ds in root_ds_list:
        if root_ds == ds.to_text():
            return
    raise ZSKValidationError('.')


def validate_rrsigset(rrset, rrsig, domain):
    dns.dnssec.validate(rrset, rrsig, {dns.name.from_text(domain): rrset})


def validate_chain(domain):
    splits = split(domain)

    first = splits.pop()
    while len(splits) > 0:
        second = splits.pop()
        # Validate
        dnskey_rrset, dnskey_rrsig = query_dnskey(first)
        validate_rrsigset(dnskey_rrset, dnskey_rrsig, first)

        ds_rrset, ds_rrsig = query_ds(first, second)
        validate_zsk(first, dnskey_rrset, ds_rrset)
        first = second

    dnskey_rrset, dnskey_rrsig = query_dnskey(first)
    validate_rrsigset(dnskey_rrset, dnskey_rrsig, first)
    validate_root_zsk(dnskey_rrset)
