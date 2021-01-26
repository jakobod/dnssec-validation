class ZSKValidationError(Exception):
  pass


class QueryError(Exception):
  pass


class EmptyError(Exception):
  pass


class TimeoutError(Exception):
  pass


class DNSSECNotDeployedError(Exception):
  pass


class RessourceMissingError(Exception):
  pass


class ShouldNotHappenError(Exception):
  pass
