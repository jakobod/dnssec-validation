import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import traceback

from collections import deque
from collections import defaultdict
from dnssec.probing.exception import *
from dnssec.probing.datatypes import *


# Contains zones for which the SOA record has been queried and was correct.
existing_zones = dict()  # {str zone_name: Zone zone}
# Contains zones for which the SOA record has been queried and was INcorrect.
nonexisting_zones = set()  # str : zone_name

# Contains zones that have been fully validated.
validated_zones = dict()  # {str zone_name: Zone zone}
# Contains zones that do not use DNSSEC (PROVEN using NSEC/3)
invalidated_zones = dict()  # {str zone_name : str way_of_proving}

# Contains the root zone. Caching mitigates the querying overhead.
root_zone = None


def is_valid_zone(zone):
  # Has this zone been checked before?
  if zone in nonexisting_zones:
    return False, None
  if zone in existing_zones:
    return True, existing_zones.get(zone)

  # Has not been checked before. Check it!
  soa = query(zone, dns.rdatatype.SOA)
  if soa.rrset is None:
    raise RessourceMissingError(f'{zone} - SOA')
  exists = soa.rrset.name.to_text() == zone
  if exists:
    existing_zones[zone] = soa
    return exists, soa
  nonexisting_zones.add(zone)
  return False, None


def split(domain):
  splits = domain.split('.')
  if splits[-1] != '':
    splits.append('')
  res = []
  while splits[0] != '':
    joined = '.'.join(splits)
    is_valid, soa = is_valid_zone(joined)
    if is_valid:
      res.append(Zone(joined, None, None, soa, None))
    splits = splits[1:]
  res.reverse()
  return deque(res)


def get_from(response, rd_type, covers=dns.rdatatype.TYPE0):
  for section in [response.answer, response.authority, response.additional]:
    for ans in section:
      if ans.rdtype == rd_type and ans.covers == covers:
        return ans
  return None


def get_all_from(response, rd_type, covers=dns.rdatatype.TYPE0):
  answers = []
  for section in [response.answer, response.authority, response.additional]:
    for ans in section:
      if ans.rdtype == rd_type and ans.covers == covers:
        answers.append(ans)
  if len(answers) == 0:
    return None
  return answers


def raw_query(zone, record_type, ns_addr='8.8.8.8'):
  request = dns.message.make_query(
      zone, record_type, want_dnssec=True)
  try:
    response, _ = dns.query.udp_with_fallback(
        request, ns_addr, timeout=3)
  except dns.exception.Timeout:
    raise TimeoutError(
        f'{dns.rdatatype.to_text(record_type)}@{zone}')
  if response.rcode() != 0:
    raise QueryError(
        f'{dns.rdatatype.to_text(record_type)}@{zone}: {dns.rcode.to_text(response.rcode())}')
  return response


def query(zone, record_type, ns_addr='8.8.8.8'):
  response = raw_query(zone, record_type, ns_addr)
  return Response(get_from(response, record_type),
                  get_from(response, dns.rdatatype.RRSIG, record_type))


def validate_NSEC3(zone_name, parent_zone, rrset, rrsig):
  validate_rrsigset(rrset, rrsig, parent_zone.name,
                    parent_zone.dnskey.rrset)
  nsec3 = rrset[0]
  hashed_name = dns.dnssec.nsec3_hash(
      zone_name, nsec3.salt, nsec3.iterations, nsec3.algorithm)
  parts = rrset.name.to_text().split('.')
  if parts[0].upper() != hashed_name:
    return False
  else:
    nsec3_str = nsec3.to_text()
    if 'DS' in nsec3_str:
      # In this case, something is VERY wrong.
      # The record should have been contained in the response.
      raise ShouldNotHappenError('NSEC3 proved existence of DS record')
    return True


def validate_NSEC(zone_name, parent_zone, rrset, rrsig):
  validate_rrsigset(rrset, rrsig, parent_zone.name,
                    parent_zone.dnskey.rrset)
  if rrset.name.to_text() != zone_name:
    return False
  else:
    nsec_str = rrset[0].to_text()
    if 'DS' in nsec_str:
      # In this case, something is VERY wrong.
      # The record should have been contained in the response.
      raise ShouldNotHappenError('NSEC proved existence of DS record')
    return True


def query_DS(zone, parent_zone):
  if zone.name in invalidated_zones:
    return None, invalidated_zones.get(zone.name)
  response = raw_query(zone.name, dns.rdatatype.DS, parent_zone.ns)
  ds = Response(get_from(response, dns.rdatatype.DS),
                get_from(response, dns.rdatatype.RRSIG, dns.rdatatype.DS))
  if ds.rrset:
    return ds, None
  # DS record seems to be nonexistent.. Prove that using NSEC3!
  nsec = Response(get_all_from(response, dns.rdatatype.NSEC3),
                  get_all_from(response, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3))
  if nsec.rrsig:
    nsec_type = 'NSEC3'
    for i in range(len(nsec.rrsig)):
      if validate_NSEC3(zone.name, parent_zone, nsec.rrset[i], nsec.rrsig[i]):
        break
  else:
    # NSEC used.. This is definitely NOT Standard conforming..
    nsec_type = 'NSEC'
    nsec = Response(get_all_from(response, dns.rdatatype.NSEC),
                    get_all_from(response, dns.rdatatype.RRSIG, dns.rdatatype.NSEC))
    for i in range(len(nsec.rrset)):
      if validate_NSEC(zone.name, parent_zone, nsec.rrset[i], nsec.rrsig[i]):
        break
  invalidated_zones[zone.name] = nsec_type
  return None, nsec_type


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
        return True
  return False


def validate_root_zsk(dnskey_set):
  # https://data.iana.org/root-anchors/root-anchors.xml
  root_ds_list = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5',
                  '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']
  for zsk in dnskey_set:
    ds = dns.dnssec.make_ds('.', zsk, dns.dnssec.DSDigest.SHA256)
    for root_ds in root_ds_list:
      if root_ds == ds.to_text():
        return
  raise ShouldNotHappenError('could not validate root ZSK')


def validate_rrsigset(rrset, rrsig, zone, key):
  try:
    dns.dnssec.validate(rrset, rrsig, {dns.name.from_text(zone): key})
  except Exception:
    return False
  return True


def validate_root_zone():
  global root_zone
  ns = '198.41.0.4'  # IP of a.root-servers.net. This doesn't have to be validated!
  dnskey = query('.', dns.rdatatype.DNSKEY, ns)
  if dnskey.rrset is None:
    raise RessourceMissingError('. - DNSKEY')
  zone = Zone('.', dnskey, ns, None, None)

  # Validate
  if not validate_rrsigset(
          dnskey.rrset, dnskey.rrsig, '.', dnskey.rrset):
    raise ShouldNotHappenError('could not validate root DNSKEY RRSIG')
  validate_root_zsk(dnskey.rrset)
  root_zone = zone


def count_deployed_keys(dnskey_rrset):
  counts = defaultdict(lambda: 0)
  for key in dnskey_rrset:
    counts[key.flags] += 1
  return counts[257], counts[256]


def validate_zone(zone, parent_zone):
  zone_info = ZoneInfo(zone.name)
  try:
    ns_addr = query(zone.soa.rrset[0].mname.to_text(), dns.rdatatype.A)
    if ns_addr.rrset is None:
      raise RessourceMissingError(f'{zone.name} - NS A record')
    zone.ns = ns_addr.rrset[0].to_text()
    ds, nsec_type = query_DS(zone, parent_zone)
    zone.dnskey = query(zone.name, dns.rdatatype.DNSKEY, zone.ns)
    ## Checks ##
    zone_info.has_dnskey = zone.dnskey.rrset is not None
    zone_info.has_ds = ds is not None
    if zone_info.has_dnskey:
      zone_info.valid_dnskey = validate_rrsigset(
          zone.dnskey.rrset, zone.dnskey.rrsig, zone.name, zone.dnskey.rrset)
      zone_info.num_ksk, zone_info.num_zsk = count_deployed_keys(
          zone.dnskey.rrset)
    if ds and parent_zone.dnskey.rrset:
      zone_info.valid_ds = validate_rrsigset(ds.rrset, ds.rrsig, parent_zone.name,
                                             parent_zone.dnskey.rrset)
    zone_info.valid_soa = validate_rrsigset(zone.soa.rrset, zone.soa.rrsig,
                                            zone.name, zone.dnskey.rrset)
    if zone_info.has_ds and zone_info.has_dnskey:
      zone_info.validated = validate_zsk(
          zone.name, zone.dnskey.rrset, ds.rrset)

    if not zone_info.has_ds:
      zone_info.validation_state = 'UNSECURED'
      zone_info.reason = nsec_type
  except Exception as e:
    zone_info.from_error(e)
  return zone, zone_info


def validate_chain(domain):
  current_validation = ValidationResult(domain)
  try:
    parent_zone = root_zone
    for zone in split(domain):
      validated_zone = validated_zones.get(zone.name)
      if validated_zone is None:
        validated_zone, zone_info = validate_zone(
            zone, parent_zone)
        if zone_info:
          validated_zone.info = zone_info
          validated_zones[zone.name] = validated_zone
        else:
          current_validation.from_zone_info(zone_info)
        current_validation.zones.append(zone_info)
      else:
        current_validation.zones.append(validated_zone.info)
      parent_zone = validated_zone
  except Exception as e:
    current_validation.from_error(e)
  return current_validation
