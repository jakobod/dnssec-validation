from dataclasses import dataclass
from dnssec.probing.exception import *


@dataclass
class Response:
  rrset: list  # dns.rrset.RRset
  rrsig: list  # dns.rrset.RRset


class ValidationState:
  def __init__(self):
    self.validation_state = 'VALIDATED'
    self.reason = None

  def from_error(self, ex):
    self.reason = str(ex)
    if isinstance(ex, DNSSECNotDeployedError):
      self.validation_state = 'UNSECURED'
    elif isinstance(ex, TimeoutError):
      self.validation_state = 'TIMEOUT'
    elif isinstance(ex, QueryError):
      self.validation_state = 'QUERY_ERROR'
    elif isinstance(ex, RessourceMissingError):
      self.validation_state = 'MISSING_RESSOURCE'
    elif isinstance(ex, ShouldNotHappenError):
      self.validation_state = 'WEIRD_STUFF_HAPPENED'
    else:
      # Any unmatched Exception is caught here. PRINT THE TYPE FOR DEBUGGING
      self.validation_state = 'OTHER'
      self.reason = f'{type(ex)}: {str(ex)}'

  def _as_dict(self):
    return {'validation_state': self.validation_state, 'reason': self.reason}

  def _from_dict(self, dct):
    self.validation_state = dct['validation_state']
    self.reason = dct['reason']


class ZoneInfo(ValidationState):
  def __init__(self, name=None):
    super().__init__()
    self.name = name
    self.has_dnskey = False
    self.has_ds = False
    self.valid_dnskey = False
    self.valid_soa = False
    self.num_ksk = 0
    self.num_zsk = 0
    self.validated = False

  def __bool__(self):
    return (self.has_dnskey and
            self.has_ds and
            self.valid_dnskey and
            self.valid_soa and
            self.validated)

  def __str__(self):
    return f"ZoneInfo(name='{self.name}', validation_state='{self.validation_state}', reason='{self.reason}', has_dnskey={self.has_dnskey}, has_ds={self.has_ds}, valid_dnskey={self.valid_dnskey}, valid_soa={self.valid_soa}, num_ksk={self.num_ksk}, num_zsk={self.num_zsk}, validated={self.validated})"

  def __repr__(self):
    return f'ZoneInfo({self.name}, {self.validation_state}, {self.reason}, {self.has_dnskey}, {self.has_ds}, {self.valid_dnskey}, {self.valid_soa}, {self.num_ksk}, {self.num_zsk}, {self.validated})'

  def as_dict(self):
    dct = {'name': self.name,
           'has_dnskey': self.has_dnskey,
           'has_ds': self.has_ds,
           'valid_dnskey': self.valid_dnskey,
           'valid_soa': self.valid_soa,
           'num_ksk': self.num_ksk,
           'num_zsk': self.num_zsk,
           'validated': self.validated}
    dct.update(super()._as_dict())
    return dct

  def from_dict(self, dct):
    super()._from_dict(dct)
    self.name = dct['name']
    self.has_dnskey = dct['has_dnskey']
    self.has_ds = dct['has_ds']
    self.valid_dnskey = dct['valid_dnskey']
    self.valid_soa = dct['valid_soa']
    self.num_ksk = dct['num_ksk']
    self.num_zsk = dct['num_zsk']
    self.validated = dct['validated']
    return self


class ValidationResult(ValidationState):
  def __init__(self, name=None):
    super().__init__()
    self.name = name
    self.zones = []

  def from_zone_info(self, zone_info):
    if self.validation_state == 'VALIDATED':
      self.validation_state = zone_info.validation_state
      self.reason = zone_info.reason

  def __str__(self):
    res = f'Domain: {self.name}\n'
    res += f'Result: {self.validation_state}\n'
    res += f'Reason: {self.reason}\n'
    for zone in self.zones:
      res += str(zone) + '\n'
    return res

  def __repr__(self):
    return f'ValidationResult({self.name}, {self.validation_state}, {self.reason}, {self.zones})'

  def as_dict(self):
    zone_dicts = []
    for zone in self.zones:
      zone_dicts.append(zone.as_dict())
    dct = {'name': self.name}
    dct.update(super()._as_dict())
    dct['zones'] = zone_dicts
    return dct

  def from_dict(self, dct):
    super()._from_dict(dct)
    for zone_dct in dct['zones']:
      self.zones.append(ZoneInfo().from_dict(zone_dct))
    self.name = dct['name']
    return self


@ dataclass
class Zone:
  name: str
  dnskey: Response
  ns: str
  soa: Response
  info: ZoneInfo
