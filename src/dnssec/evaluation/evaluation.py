#!/usr/bin/env python3

import json
import pandas as pd
import time
import argparse
from dnssec.probing.datatypes import ValidationResult
from enum import Enum


class EvalState(Enum):
  UNBROKEN = 0,
  BROKEN = 1,
  FLAPPING = 2,


def is_flapping(zone_infos):
  state = EvalState.UNBROKEN
  for zone_info in zone_infos:
    if state == EvalState.UNBROKEN and not zone_info['validated']:
      state = EvalState.BROKEN
    elif state == EvalState.BROKEN and zone_info['validated']:
      state = EvalState.FLAPPING
  return state == EvalState.FLAPPING


def deployed_keys(zone_infos):
  zones = []
  for i, zone_info in enumerate(zone_infos):
    if zone_info['num_ksk'] != 0 and zone_info['num_zsk'] == 0:
      zones.append(zone_info['name'])
  # if len(zones) != 0:
  #   return None
  return zones


def to_csv(args):
  weird_dnssec_deployment = set()
  with open(args.input, 'r') as json_file:
    lst = []
    t1 = time.time()
    for i, line in enumerate(json_file):
      dct = json.loads(line)
      zones = dct['zones']
      flapping = is_flapping(zones)

      #
      weird_dnssec_deployment.update(deployed_keys(zones))
      # lst.append([dct['name'], dct['validation_state'], dct['reason']])

      # if i > 10:
      #   break

      # df = pd.DataFrame(lst,
      #                   columns=['name', 'result', 'reason'])
    t2 = time.time()
    print(t2-t1, 's')
    print(len(weird_dnssec_deployment), 'zones deploy dnssec only using KSKs')


def main():
  # action='store_true'
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '-c', '--to-csv', help='Evaluate the given input file and save it to csv', metavar='OUTFILE')
  parser.add_argument(
      '-o', '--output-path', help='Path at which created files are written to', metavar='PATH')

  parser.add_argument(
      'input', help='The json that should be evaluated', metavar='JSON_PATH')
  args = parser.parse_args()

  if args.to_csv:
    to_csv(args)


if __name__ == '__main__':
  main()
