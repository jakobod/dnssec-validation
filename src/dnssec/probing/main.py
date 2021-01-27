#!/usr/bin/env python3

from tqdm import tqdm
from multiprocessing.dummy import Pool as ThreadPool
import csv
import pandas as pd
import argparse
import dns
import time
import json
from dnssec.probing import dnssec


def test(domains):
  dnssec.validate_root_zone()
  for domain in domains:
    print('Checking:', domain)
    print(dnssec.validate_chain(domain))


def main():
  # , action='store_true' for boolean flags
  parser = argparse.ArgumentParser()
  parser.add_argument('--test', nargs='+', help='Domain(s) to validate')
  parser.add_argument('input', help='The csv containing domains')
  parser.add_argument(
      '--output', help='The output path to write the csv to', default='../output/out.csv')
  args = parser.parse_args()

  if args.test:
    test(args.test)
  else:
    dnssec.validate_root_zone()
    with open(args.input, 'r') as csv_file:
      reader = csv.reader(csv_file)
      with open(args.output, 'w', encoding='utf-8') as json_file:
        for domain in tqdm(reader):
          result = dnssec.validate_chain(domain[1])
          json.dump(result.as_dict(), json_file, ensure_ascii=False)
          json_file.write('\n')
          json_file.flush()


if __name__ == '__main__':
  main()
