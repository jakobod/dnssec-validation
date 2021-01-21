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
Zone = namedtuple('Zone', 'name dnskey ns')
ValidationResult = namedtuple(
    'ValidationResult', 'name validation_state num_validated')
validated_zones = dict()
root_zone = None


def split(domain):
    chain = domain.split('.')
    if chain[-1] != '':
        chain.append('')
    res = []
    while len(chain) > 0:
        joined = '.'.join(chain)
        if is_valid_zone(joined):
            res.append(joined)
        chain = chain[1:]
    res.reverse()
    return deque(res)


def get_from(response, rd_type):
    for section in [response.answer, response.authority, response.additional]:
        for ans in section:
            if ans.rdtype == rd_type:
                return ans
    return None


def query(name, record_type, ns_addr='8.8.8.8'):
    request = dns.message.make_query(
        name, record_type, want_dnssec=True)
    response, _ = dns.query.udp_with_fallback(
        request, ns_addr, timeout=10)
    if response.rcode() != 0:
        raise QueryError(f'{dns.rcode.to_text(response.rcode())}')
    return Response(get_from(response, record_type),
                    get_from(response, dns.rdatatype.RRSIG),
                    record_type)


def dnssec_deployed(zone, parent_zone):
    print('checking', zone)
    nsec = query(zone, dns.rdatatype.NSEC3, parent_zone.ns)
    print(nsec.rrset)
    nsec3 = nsec.rrset[0]
    hashed_name = dns.dnssec.nsec3_hash(
        zone, nsec3.salt, nsec3.iterations, nsec3.algorithm)
    print(nsec.rrset.name.to_text().split('.')[0])
    print(hashed_name)
    # parts = nsec.rrset.name.to_text().split('.')
    # return parts[0].upper() == hashed_name


def is_valid_zone(zone):
    soa = query(zone, dns.rdatatype.SOA)
    return soa.rrset.name.to_text() == zone


def validate_zsk(domain, zsk_set, ds_set):
    if not zsk_set:
        raise EmptyError('empty ZSK set')
    if not ds_set:
        raise EmptyError('empty DS set')
    for ds in ds_set:
        # Iterating over the whole ZSK set is necessary since some zones are
        # signed using the KSK (256).. Hence getting the ZSK (257) for
        # validation will fail in some edge cases.
        for zsk in zsk_set:
            zsk_ds = dns.dnssec.make_ds(domain, zsk, ds.digest_type)
            if ds == zsk_ds:
                return
    raise ZSKValidationError(domain)


def validate_root_zsk(dnskey_set):
    # https://data.iana.org/root-anchors/root-anchors.xml
    root_ds_list = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5',
                    '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
    for zsk in dnskey_set:
        ds = dns.dnssec.make_ds('.', zsk, dns.dnssec.DSDigest.SHA256)
        for root_ds in root_ds_list:
            if root_ds == ds.to_text():
                return ds
    raise ZSKValidationError('.')


def validate_rrsigset(rrset, rrsig, zone, key):
    try:
        dns.dnssec.validate(rrset, rrsig, {dns.name.from_text(zone): key})
    except Exception as e:
        raise dns.dnssec.ValidationFailure(f'{e}: {zone}')


def validate_root_zone():
    global root_zone
    ns = '198.41.0.4'  # IP of a.root-servers.net. This doesn't have to be validated!
    dnskey = query('.', dns.rdatatype.DNSKEY, ns)
    if dnskey.rrset is None:
        raise DNSKeyMissingError('.')
    zone = Zone('.', dnskey, ns)

    # Validate
    validate_rrsigset(
        dnskey.rrset, dnskey.rrsig, '.', dnskey.rrset)
    validate_root_zsk(dnskey.rrset)
    root_zone = zone


def validate_zone(zone_name, parent_zone):
    # Query all necessary parts
    soa = query(zone_name, dns.rdatatype.SOA)
    ns_addr = query(soa.rrset[0].mname.to_text(), dns.rdatatype.A)
    ns = ns_addr.rrset[0].to_text()
    dnskey = query(zone_name, dns.rdatatype.DNSKEY, ns)
    if dnskey.rrset is None:
        raise DNSKeyMissingError(zone_name)
    ds = query(zone_name, dns.rdatatype.DS, parent_zone.ns)
    zone = Zone(zone_name, dnskey, ns)

    validate_rrsigset(
        zone.dnskey.rrset, zone.dnskey.rrsig, zone.name, zone.dnskey.rrset)
    validate_rrsigset(soa.rrset, soa.rrsig,
                      zone.name, zone.dnskey.rrset)
    validate_rrsigset(ds.rrset, ds.rrsig, parent_zone.name,
                      parent_zone.dnskey.rrset)
    validate_zsk(zone.name, zone.dnskey.rrset, ds.rrset)
    return zone


def validate_chain(domain):
    zones = split(domain)
    num_validated_zones = 1
    try:
        parent_zone = root_zone
        while zones:
            # Save values from last run!
            zone_name = zones.popleft()
            zone = validated_zones.get(zone_name)
            if zone is None:
                zone = validate_zone(zone_name, parent_zone)
                validated_zones[zone.name] = zone
            num_validated_zones += 1
            parent_zone = zone
    except DNSKeyMissingError as e:
        return ValidationResult(domain, 'UNSECURED', num_validated_zones)
    except dns.exception.Timeout as e:
        return ValidationResult(domain, 'TIMEOUT', num_validated_zones)
    except QueryError as e:
        return ValidationResult(domain, f'QUERY_ERROR: {e}', num_validated_zones)
    except dns.dnssec.ValidationFailure as e:
        return ValidationResult(domain, f'Validation_FAILURE: {e}', num_validated_zones)
    except ZSKValidationError as e:
        return ValidationResult(domain, f'ZSK_VALIDATION_FAILED: {e}', num_validated_zones)
    except Exception as e:
        print(domain, ':', type(e), e)
        return ValidationResult(domain, 'OTHER', num_validated_zones)

    return ValidationResult(domain, 'VALIDATED', num_validated_zones)
