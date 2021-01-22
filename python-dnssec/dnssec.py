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
from dataclasses import dataclass


@dataclass
class Response:
    rrset: list  # dns.rrset.RRset
    rrsig: list  # dns.rrset.RRset


@dataclass
class Zone:
    name: str
    dnskey: Response
    ns: str
    soa: Response


@dataclass
class ValidationResult:
    name: str
    validation_state: str
    num_validated: int
    reason: str


existing_zones = dict()
validated_zones = dict()
root_zone = None


def is_valid_zone(zone):
    soa = query(zone, dns.rdatatype.SOA)
    if soa.rrset is None:
        raise RessourceMissingError(f'{zone} - SOA')
    return soa.rrset.name.to_text() == zone, soa


def split(domain):
    splits = domain.split('.')
    if splits[-1] != '':
        splits.append('')
    res = []
    while len(splits) > 0:
        joined = '.'.join(splits)
        zone = existing_zones.get(joined)
        if zone:
            res.append(zone)
        else:
            is_valid, soa = is_valid_zone(joined)
            if is_valid:
                zone = Zone(joined, None, None, soa)
                existing_zones[joined] = zone
                res.append(zone)
        splits = splits[1:]
    res.reverse()
    return deque(res)


def get_from(response, rd_type, covers=dns.rdatatype.TYPE0):
    # TODO: This should return a list of all answers!
    for section in [response.answer, response.authority, response.additional]:
        for ans in section:
            if ans.rdtype == rd_type and ans.covers == covers:
                return ans
    return None


def raw_query(zone, record_type, ns_addr='8.8.8.8'):
    request = dns.message.make_query(
        zone, record_type, want_dnssec=True)
    try:
        response, _ = dns.query.udp_with_fallback(
            request, ns_addr, timeout=10)
    except dns.exception.Timeout:
        raise TimeoutError(
            f'Querying {dns.rdatatype.to_text(record_type)}@{zone}')
    if response.rcode() != 0:
        raise QueryError(f'{dns.rcode.to_text(response.rcode())}')
    return response


def query(zone, record_type, ns_addr='8.8.8.8'):
    response = raw_query(zone, record_type, ns_addr)
    return Response(get_from(response, record_type),
                    get_from(response, dns.rdatatype.RRSIG, record_type))


def validate_NSEC3(zone, parent_zone, nsec):
    validate_rrsigset(nsec.rrset, nsec.rrsig, parent_zone.name,
                      parent_zone.dnskey.rrset)
    nsec3 = nsec.rrset[0]
    hashed_name = dns.dnssec.nsec3_hash(
        zone.name, nsec3.salt, nsec3.iterations, nsec3.algorithm)
    parts = nsec.rrset.name.to_text().split('.')
    if parts[0].upper() != hashed_name:
        raise DNSSECNotDeployedError('NSEC3')
    else:
        raise ShouldNotHappenError('NSEC3 did not cover zone......')


def validate_NSEC(zone, parent_zone, nsec):
    validate_rrsigset(nsec.rrset, nsec.rrsig, parent_zone.name,
                      parent_zone.dnskey.rrset)
    if nsec.rrset.name.to_text() == zone.name:
        raise DNSSECNotDeployedError('NSEC')
    else:
        raise ShouldNotHappenError('NSEC did not cover zone......')


def query_DS(zone, parent_zone):
    dnskey = query(zone.name, dns.rdatatype.DS, parent_zone.ns)
    if dnskey.rrset:
        return dnskey
    # DS record seems to be nonexistent.. Prove that using NSEC3!
    response = raw_query(zone.name, dns.rdatatype.DS, parent_zone.ns)
    nsec = Response(get_from(response, dns.rdatatype.NSEC3),
                    get_from(response, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3))
    if nsec.rrsig:
        validate_NSEC3(zone, parent_zone, nsec)
    else:
        # NSEC used.. This is definitely NOT Standard conforming..
        nsec = Response(get_from(response, dns.rdatatype.NSEC),
                        get_from(response, dns.rdatatype.RRSIG, dns.rdatatype.NSEC))
        validate_NSEC(zone, parent_zone, nsec)


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
    if rrset is None:
        raise EmptyError('RRSET is None')
    if rrsig is None:
        raise EmptyError('RRSIG is None')
    try:
        dns.dnssec.validate(rrset, rrsig, {dns.name.from_text(zone): key})
    except Exception as e:
        raise dns.dnssec.ValidationFailure(f'{e}: {zone}')


def validate_root_zone():
    global root_zone
    ns = '198.41.0.4'  # IP of a.root-servers.net. This doesn't have to be validated!
    dnskey = query('.', dns.rdatatype.DNSKEY, ns)
    if dnskey.rrset is None:
        raise RessourceMissingError('. - DNSKEY')
    zone = Zone('.', dnskey, ns, None)

    # Validate
    validate_rrsigset(
        dnskey.rrset, dnskey.rrsig, '.', dnskey.rrset)
    validate_root_zsk(dnskey.rrset)
    root_zone = zone


def validate_zone(zone, parent_zone):
    ns_addr = query(zone.soa.rrset[0].mname.to_text(), dns.rdatatype.A)
    if ns_addr is None:
        raise RessourceMissingError(f'{zone} - NS A record')
    zone.ns = ns_addr.rrset[0].to_text()
    ds = query_DS(zone, parent_zone)
    zone.dnskey = query(zone.name, dns.rdatatype.DNSKEY, zone.ns)
    if zone.dnskey.rrset is None:
        raise RessourceMissingError(f'{zone} - DNSKEY')

    validate_rrsigset(
        zone.dnskey.rrset, zone.dnskey.rrsig, zone.name, zone.dnskey.rrset)
    validate_rrsigset(zone.soa.rrset, zone.soa.rrsig,
                      zone.name, zone.dnskey.rrset)
    validate_rrsigset(ds.rrset, ds.rrsig, parent_zone.name,
                      parent_zone.dnskey.rrset)
    validate_zsk(zone.name, zone.dnskey.rrset, ds.rrset)
    return zone


def validate_chain(domain):
    num_validated_zones = 1
    try:
        zones = split(domain)
        parent_zone = root_zone
        while zones:
            # Save values from last run!
            zone = zones.popleft()
            validated_zone = validated_zones.get(zone.name)
            if validated_zone is None:
                validated_zone = validate_zone(zone, parent_zone)
                validated_zones[zone.name] = validated_zone
            num_validated_zones += 1
            parent_zone = validated_zone
    except DNSSECNotDeployedError as e:
        return ValidationResult(domain, 'UNSECURED', num_validated_zones, str(e))
    except TimeoutError as e:
        return ValidationResult(domain, f'TIMEOUT', num_validated_zones, str(e))
    except QueryError as e:
        return ValidationResult(domain, f'QUERY_ERROR', num_validated_zones, str(e))
    except dns.dnssec.ValidationFailure as e:
        return ValidationResult(domain, f'VALIDATION_FAILURE', num_validated_zones, str(e))
    except ZSKValidationError as e:
        return ValidationResult(domain, f'ZSK_VALIDATION_FAILURE', num_validated_zones, str(e))
    except RessourceMissingError as e:
        return ValidationResult(domain, f'MISSING_RESSOURCE', num_validated_zones, str(e))
    except ShouldNotHappenError as e:
        return ValidationResult(domain, f'WEIRD_STUFF_HAPPENED', num_validated_zones, str(e))
    except Exception as e:
        return ValidationResult(domain, f'OTHER', num_validated_zones, f'{type(e)}:{str(e)}')

    return ValidationResult(domain, 'VALIDATED', num_validated_zones, None)
