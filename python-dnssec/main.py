#!/usr/bin/env python3

import dnssec
import csv
import pandas as pd
import argparse
import dns
import time
import json

from multiprocessing.dummy import Pool as ThreadPool
from tqdm import tqdm


def test(domains):
  with open('eggs.csv', newline='') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
    for row in spamreader:
      print(', '.join(row))

  dnssec.validate_root_zone()
  for domain in domains:
    print('Checking:', domain)
    print(dnssec.validate_chain(domain))


if __name__ == '__main__':
  # , action='store_true' for boolean flags
  parser = argparse.ArgumentParser()
  parser.add_argument('--test', nargs='+', help='Domain(s) to validate')
  parser.add_argument(
      '--output', help='The output path to write the csv to', default='../output/out.csv')
  args = parser.parse_args()

  if args.test:
    test(args.test)
  else:
    dnssec.validate_root_zone()
    alexa_df = pd.read_csv(
        '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv.tar.gz', sep=',', index_col=0, names=['domain'])[:-1]
    with open(args.output, 'w', encoding='utf-8') as json_file:
      for i, domain in enumerate(tqdm(alexa_df['domain'].values)):
        result = dnssec.validate_chain(domain)
        json.dump(result.as_dict(), json_file, ensure_ascii=False)
        json_file.write('\n')
        if (i % 10):
          json_file.flush()
