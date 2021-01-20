import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import tldextract
import time
import threading

from collections import deque
from collections import namedtuple
from exception import *


Response = namedtuple('Response', 'rrset rrsig, type')
Zone = namedtuple('Zone', 'name dnskey ds ns')
ValidationResult = namedtuple(
    'ValidationResult', 'name validation_state num_validated')
validated_zones = dict()


def get_parent_zone(zone):
    parts = split(zone)
    if len(parts) >= 2:
        return parts[-2]
    else:
        return None


def split(domain):
    # Root
    chain = list()
    chain.append('.')

    # TLD
    ext = tldextract.extract(domain, include_psl_private_domains=False)
    print(ext)
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
    print(chain)
    return deque(chain)
    # chain = domain.split('.')
    # if chain[-1] != '':
    #     chain.append('')
    # res = []
    # while len(chain) > 0:
    #     joined = '.'.join(chain)
    #     res.append(joined)
    #     chain = chain[1:]
    # res[-1] = '.'
    # res.reverse()
    # return deque(res)


def get_from(response, rd_type):
    for ans in response.answer:
        if ans.rdtype == rd_type:
            return ans
    for ans in response.authority:
        if ans.rdtype == rd_type:
            return ans
    for ans in response.additional:
        if ans.rdtype == rd_type:
            return ans
    return None


def query(name, record_type, ns_addr='8.8.8.8'):
    request = dns.message.make_query(
        name, record_type, want_dnssec=True)
    response, _ = dns.query.udp_with_fallback(request, ns_addr, timeout=10)
    if response.rcode() != 0:
        raise QueryError(f'{dns.rcode.to_text(response.rcode())}')
    return Response(get_from(response, record_type),
                    get_from(response, dns.rdatatype.RRSIG),
                    record_type)


def validate_zsk(domain, zsk_set, ds_set):
    if not zsk_set:
        raise EmptyError('empty ZSK set')
    if not ds_set:
        raise EmptyError('empty DS set')
    for ds in ds_set:
        zsk_ds = dns.dnssec.make_ds(domain, get_zsk(
            zsk_set), ds.digest_type)
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
            return ds
    raise ZSKValidationError('.')


def validate_rrsigset(rrset, rrsig, zone, key):
    # if rrset is None:
    #     raise EmptyError('empty rrset')
    # if rrsig is None:
    #     raise EmptyError('empty rrsig')
    # if zone is None:
    #     raise EmptyError('empty zone')
    # if key is None:
    #     raise EmptyError('empty key')
    try:
        dns.dnssec.validate(rrset, rrsig, {dns.name.from_text(zone): key})
    except Exception as e:
        raise dns.dnssec.ValidationFailure(f'{e}: {zone}')


def validate_root_zone():
    print('.')
    ns_name = query('.', dns.rdatatype.NS)
    ns_addr = query(ns_name.rrset[0].to_text(), dns.rdatatype.A)
    ns = ns_addr.rrset[0].to_text()
    dnskey = query('.', dns.rdatatype.DNSKEY, ns)
    if dnskey.rrset is None:
        raise DNSKeyMissingError('.')
    zone = Zone('.', dnskey, None, ns)

    # Validate
    validate_rrsigset(
        dnskey.rrset, dnskey.rrsig, '.', dnskey.rrset)
    validate_rrsigset(
        ns_name.rrset, ns_name.rrsig, '.', dnskey.rrset)
    validate_root_zsk(dnskey.rrset)
    return zone


def validate_zone(zone_name, parent_zone):
    print(zone_name)
    # Query all necessary parts
    ns_name = query(zone_name, dns.rdatatype.NS)
    ns_addr = query(ns_name.rrset[0].to_text(), dns.rdatatype.A)
    ns = ns_addr.rrset[0].to_text()
    dnskey = query(zone_name, dns.rdatatype.DNSKEY, ns)
    if dnskey.rrset is None:
        raise DNSKeyMissingError(zone_name)
    ds = query(zone_name, dns.rdatatype.DS, parent_zone.ns)
    zone = Zone(zone_name, dnskey, ds, ns)

    print(zone)

    # Validate
    validate_rrsigset(
        zone.dnskey.rrset, zone.dnskey.rrsig, zone.name, zone.dnskey.rrset)
    validate_rrsigset(ns_name.rrset, ns_name.rrsig,
                      zone.name, zone.dnskey.rrset)
    validate_rrsigset(
        zone.ds.rrset, zone.ds.rrsig, parent_zone.name, parent_zone.dnskey.rrset)
    validate_zsk(zone.name, zone.dnskey.rrset, zone.ds.rrset)
    return zone


def validate_chain(domain):
    zones = split(domain)
    num_validated_zones = 0

    try:
        # Root zone
        zone_name = zones.popleft()
        print(zone_name)
        zone = validated_zones.get(domain)
        if zone is None:
            zone = validate_root_zone()
            validated_zones[zone.name] = zone
        num_validated_zones += 1

        while zones:
            # Save values from last run!
            parent_zone = zone
            zone_name = zones.popleft()
            zone = validated_zones.get(zone_name)
            if zone is None:
                zone = validate_zone(zone_name, parent_zone)
                validated_zones[zone.name] = zone
            num_validated_zones += 1
    except DNSKeyMissingError as e:
        return ValidationResult(domain, 'UNSECURED', num_validated_zones)
    except dns.exception.Timeout as e:
        return ValidationResult(domain, 'TIMEOUT', num_validated_zones)
    except QueryError as e:
        return ValidationResult(domain, f'QUERY_ERROR: {e}', num_validated_zones)
    except dns.dnssec.ValidationFailure as e:
        return ValidationResult(domain, f'Validation_FAILURE: {e}', num_validated_zones)
    except Exception as e:
        print(domain, ':', type(e), e)
        return ValidationResult(domain, 'OTHER', num_validated_zones)

    return ValidationResult(domain, 'VALIDATED', num_validated_zones)
