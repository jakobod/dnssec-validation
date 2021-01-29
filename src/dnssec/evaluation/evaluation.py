#!/usr/bin/env python3

import json
import pandas as pd
import time
import argparse
from dnssec.probing.datatypes import *
from dnssec.evaluation import plot
from enum import Enum
from ordered_enum import OrderedEnum
from dnssec.evaluation import tld


class Severity(OrderedEnum):
  MUST_NOT = 0,
  NOT_RECOMMENDED = 1,
  MAY = 2,
  RECOMMENDED = 3,
  MUST = 4


algorithms = {'RSAMD5': Severity.MUST_NOT,
              'DSA': Severity.MUST_NOT,
              'RSASHA1': Severity.NOT_RECOMMENDED,
              'DSANSEC3SHA1': Severity.MUST_NOT,
              'RSASHA1NSEC3SHA1': Severity.NOT_RECOMMENDED,
              'RSASHA256': Severity.MUST,
              'RSASHA512': Severity.NOT_RECOMMENDED,
              'ECCGOST': Severity.MUST_NOT,
              'ECDSAP256SHA256': Severity.MUST,
              'ECDSAP384SHA384': Severity.MAY,
              'ED25519': Severity.RECOMMENDED,
              'ED448': Severity.MAY}


class EvalState(Enum):
  UNBROKEN = 0,
  BROKEN = 1,
  FLAPPING = 2,


def is_flapping(zone_infos):
  state = EvalState.UNBROKEN
  for zone_info in zone_infos:
    if state == EvalState.UNBROKEN and not zone_info.validated:
      state = EvalState.BROKEN
    elif state == EvalState.BROKEN and zone_info.validated:
      state = EvalState.FLAPPING
  return state == EvalState.FLAPPING


def is_tld(zone_name):
  return


def find_keys(keys):
  # keyset = set(keys)
  # for key in keyset:
  #   if algorithms[key] <= Severity.NOT_RECOMMENDED:
  #     print(key, 'NOT SECURE!')
  pass


def to_csv(args):
  zone_infos = []
  domains = []
  with open(args.input, 'r') as json_file:
    for line in json_file:
      result = ValidationResult().from_dict(json.loads(line))
      if is_flapping(result.zones):
        result.validation_state = 'PARTIAL'
      ext_tld = tld.extract(result.name)
      domains.append(result.as_list()+[ext_tld])

      for zone_info in result.zones:
        find_keys(zone_info.key_algos)
        zone_infos.append(zone_info.as_list()+[ext_tld])

    all_domains_df = pd.DataFrame(
        domains, columns=ValidationResult().member_names()+['tld'])
    all_domains_df = all_domains_df.drop_duplicates(subset=['name'])
    all_domains_path = args.output_path+'all_domains.csv'
    all_domains_df.to_csv(all_domains_path, index=False)
    print('wrote', all_domains_path)

    all_zones_df = pd.DataFrame(
        zone_infos, columns=ZoneInfo().member_names()+['tld'])
    all_zones_df = all_zones_df.drop_duplicates(subset=['name'])
    all_zones_path = args.output_path+'all_zones.csv'
    all_zones_df.to_csv(all_zones_path, index=False)
    print('wrote', all_zones_path)


def main():
  # action='store_true'
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--input', help='The json that should be evaluated', metavar='INPUT_FILE')
  parser.add_argument(
      '-o', '--output-path', help='Path at which created files are written to', metavar='OUTPUT_PATH')
  parser.add_argument(
      '-c', '--to-csv', help='Evaluate the given input file and save it to csv', action='store_true')
  parser.add_argument(
      '-p', '--plot', help='Plot the evaluated files and save them to OUTPUT_PATH', action='store_true')

  args = parser.parse_args()

  if args.output_path is None:
    print('An output path is required!')
    exit(-1)
  elif args.output_path[-1] != '/':
    args.output_path += '/'

  to_csv(args)
  if args.plot:
    plot.plot(args.output_path, args.output_path)


if __name__ == '__main__':
  main()
