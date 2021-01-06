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


Response = namedtuple('SignedResponse', 'rrset rrsig, type')
Zone = namedtuple('Zone', 'name dnskey ds ns')
ValidationResult = namedtuple(
    'ValidationResult', 'name validation_state num_validated')
validated_zones = dict()
lock = threading.Lock()


def get_from_dict(zone):
    val = None
    lock.acquire()
    try:
        val = validated_zones.get(zone)
    finally:
        lock.release()
    return val


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


def get_from(response, rd_type):
    for ans in response.answer:
        if ans.rdtype == rd_type:
            return ans
    return None


def query(name, record_type, ns_addr='8.8.8.8'):
    request = dns.message.make_query(
        name, record_type, want_dnssec=True)
    response = dns.query.udp(request, ns_addr, timeout=1.0)
    if response.rcode() != 0:
        raise QueryError(f'{dns.rcode.to_text(response.rcode())}')
    rrset = get_from(response, record_type)
    rrsig = get_from(response, dns.rdatatype.RRSIG)
    if rrset is None:
        raise RecordMissingError(f'Could not resolve {record_type}')
    return Response(rrset, rrsig, record_type)


# TODO: This can be made more robust by querying all possible NS records
def query_ns_addr(domain):
    response = query(domain, dns.rdatatype.NS)
    response = query(response.rrset[0].to_text(), dns.rdatatype.A)
    return response.rrset[0].to_text()


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


def validate_rrsigset(rrset, rrsig, domain, key):
    try:
        dns.dnssec.validate(rrset, rrsig, {dns.name.from_text(domain): key})
    except Exception as e:
        raise dns.dnssec.ValidationFailure(f'{e}: {domain}')


def validate_root_zone():
    zone_name = '.'
    ns_addr = query_ns_addr(zone_name)
    dnskey = query(zone_name, dns.rdatatype.DNSKEY, ns_addr)
    zone = Zone(zone_name, dnskey, None, ns_addr)

    # Validate
    validate_rrsigset(
        dnskey.rrset, dnskey.rrsig, zone_name, dnskey.rrset)
    validate_root_zsk(dnskey.rrset)
    return zone


def validate_zone(zone_name, parent_zone):
    # Query all necessary parts
    ns = query_ns_addr(zone_name)
    dnskey = query(zone_name, dns.rdatatype.DNSKEY, ns)
    ds = query(zone_name, dns.rdatatype.DS, parent_zone.ns)
    zone = Zone(zone_name, dnskey, ds, ns)

    # Validate
    validate_rrsigset(
        zone.dnskey.rrset, zone.dnskey.rrsig, zone.name, zone.dnskey.rrset)
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
        zone = get_from_dict(domain)
        if zone is None:
            zone = validate_root_zone()
            validated_zones[zone.name] = zone
        num_validated_zones += 1

        while zones:
            # Save values from last run!
            parent_zone = zone
            zone_name = zones.popleft()
            zone = get_from_dict(zone_name)
            if zone is None:
                zone = validate_zone(zone_name, parent_zone)
                validated_zones[zone.name] = zone
            num_validated_zones += 1
    except RecordMissingError as e:
        return ValidationResult(domain, 'UNSECURED', num_validated_zones)
    except dns.exception.Timeout as e:
        return ValidationResult(domain, 'TIMEOUT', num_validated_zones)
    except QueryError as e:
        return ValidationResult(domain, f'QUERY_ERROR: {e}', num_validated_zones)
    except dns.dnssec.ValidationFailure as e:
        return ValidationResult(domain, f'')
    except Exception as e:
        return ValidationResult(domain, 'OTHER', num_validated_zones)
    return ValidationResult(domain, 'VALIDATED', num_validated_zones)
