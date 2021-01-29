#!/usr/bin/env python3

import json
import pandas as pd
import time
import argparse
from dnssec.probing.datatypes import *
from dnssec.evaluation import plot
from enum import Enum
from dnssec.evaluation import tld

algorithms = {'RSAMD5': 'MUST NOT',
              'DSA': 'MUST NOT',
              'RSASHA1': 'NOT RECOMMENDED',
              'DSANSEC3SHA1': 'MUST NOT',
              'RSASHA1NSEC3SHA1': 'NOT RECOMMENDED',
              'RSASHA256': 'MUST',
              'RSASHA512': 'NOT RECOMMENDED',
              'ECCGOST': 'MUST NOT',
              'ECDSAP256SHA256': 'MUST',
              'ECDSAP384SHA384': 'MAY',
              'ED25519': 'RECOMMENDED',
              'ED448': 'MAY'
              }


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
        zone_infos.append(zone_info.as_list()+[ext_tld])

    all_domains_df = pd.DataFrame(
        domains, columns=ValidationResult().member_names()+['tld'])
    all_domains_df = all_domains_df.drop_duplicates(subset=['name'])
    all_domains_path = args.output_path+'all_domains.csv'
    all_domains_df.to_csv(all_domains_path, index=False)
    print('wrote', all_domains_path)
    print(all_domains_df)

    all_zones_df = pd.DataFrame(
        zone_infos, columns=ZoneInfo().member_names()+['tld'])
    all_zones_df = all_zones_df.drop_duplicates(subset=['name'])
    all_zones_path = args.output_path+'all_zones.csv'
    all_zones_df.to_csv(all_zones_path, index=False)
    print('wrote', all_zones_path)
    print(all_zones_df)


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
