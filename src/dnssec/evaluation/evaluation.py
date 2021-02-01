#!/usr/bin/env python3

import json
import pandas as pd
import time
import argparse

from collections import defaultdict
from dnssec.probing.datatypes import *
from dnssec.evaluation import plot
from enum import Enum
from ordered_enum import OrderedEnum
from dnssec.evaluation import tld
from os import path


class Severity(OrderedEnum):
  MUST_NOT = 0
  NOT_RECOMMENDED = 1
  MAY = 2
  RECOMMENDED = 3
  MUST = 4


def severity_to_string(severity):
  names = ['MUST_NOT', 'NOT_RECOMMENDED', 'MAY', 'RECOMMENDED', 'MUST']
  return names[severity.value]


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

digests = {'NULL': Severity.MUST_NOT,
           'SHA1': Severity.MUST_NOT,
           'SHA256': Severity.MUST,
           'GOST': Severity.MUST_NOT,
           'SHA384': Severity.MAY}


class EvalState(Enum):
  UNBROKEN = 0
  BROKEN = 1
  FLAPPING = 2


def is_flapping(zone_infos):
  state = EvalState.UNBROKEN
  for zone_info in zone_infos:
    if state == EvalState.UNBROKEN and not zone_info.validated:
      state = EvalState.BROKEN
    elif state == EvalState.BROKEN and zone_info.validated:
      state = EvalState.FLAPPING
  return state == EvalState.FLAPPING


def to_csv(args):
  zone_infos = []
  domains = []
  algo_count = defaultdict(lambda: 0)
  digest_count = defaultdict(lambda: 0)

  with open(args.input, 'r') as json_file:
    for line in json_file:
      result = ValidationResult().from_dict(json.loads(line))
      if is_flapping(result.zones):
        result.validation_state = 'PARTIAL'
      ext_tld = tld.extract(result.name)
      domains.append(result.as_list()+[ext_tld])

      for zone_info in result.zones:
        for algo in set(zone_info.key_algos):
          algo_count[algo] += 1
        for digest in set(zone_info.ds_digests):
          digest_count[digest] += 1
        zone_infos.append(zone_info.as_list()+[ext_tld])

    algo_counts = []
    algo_names = []
    algo_recommendation = []
    algo_conformity = []
    for algo in algo_count:
      if algorithms[algo] <= Severity.NOT_RECOMMENDED:
        algo_conformity.append('NON_CONFORMING')
      else:
        algo_conformity.append('CONFORMING')
      algo_names.append(algo)
      algo_recommendation.append(severity_to_string(algorithms[algo]))
      algo_counts.append(algo_count[algo])

    digest_counts = []
    digest_names = []
    digest_recommendation = []
    digest_conformity = []
    for digest in digest_count:
      if digests[digest] <= Severity.NOT_RECOMMENDED:
        digest_conformity.append('NON_CONFORMING')
      else:
        digest_conformity.append('CONFORMING')
      digest_names.append(digest)
      digest_recommendation.append(severity_to_string(digests[digest]))
      digest_counts.append(digest_count[digest])

    algo_count_df = pd.DataFrame(
        {'name': algo_names, 'count': algo_counts, 'recommendation': algo_recommendation, 'standard_conforming': algo_conformity})
    algo_count_path = args.output_path+'dnskey_algorithms.csv'
    algo_count_df.to_csv(algo_count_path, index=False)
    print('wrote', algo_count_path)

    digest_count_df = pd.DataFrame(
        {'name': digest_names, 'count': digest_counts, 'recommendation': digest_recommendation, 'standard_conforming': digest_conformity})
    digest_count_path = args.output_path+'ds_digests.csv'
    digest_count_df.to_csv(digest_count_path, index=False)
    print('wrote', digest_count_path)

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
      '-i', '--input', help='The json that should be evaluated', metavar='INPUT_FILE')
  parser.add_argument(
      '-o', '--output-path', help='Path at which created files are written to', metavar='OUTPUT_PATH')
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
