from dataclasses import dataclass


@dataclass
class Response:
    rrset: list  # dns.rrset.RRset
    rrsig: list  # dns.rrset.RRset


class ZoneInfo:
    def __init__(self, name):
        self.name = name
        self.has_dnskey = False
        self.has_ds = False
        self.valid_dnskey = False
        self.valid_soa = False
        self.deployed_keys = []
        self.validated = False
        self.error = None
        self.reason = None

    def __bool__(self):
        return (self.has_dnskey and
                self.has_ds and
                self.valid_dnskey and
                self.valid_soa and
                # len(self.deployed_keys) != 0 and
                self.validated)

    def __str__(self):
        return f'ZoneInfo({self.name}, {self.has_dnskey}, {self.has_ds}, {self.valid_dnskey}, {self.valid_soa}, {self.deployed_keys}, {self.validated}, {self.error}, {self.reason})'

    def __repr__(self):
        return self.__str__()


@dataclass
class ValidationResult:
    name: str
    validation_state: str
    reason: str
    zones: list  # <ZoneValidation>


@dataclass
class Zone:
    name: str
    dnskey: Response
    ns: str
    soa: Response
    info: ZoneInfo
