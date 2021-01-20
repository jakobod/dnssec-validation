#!/usr/bin/env python3

import dnssec
import csv
import pandas as pd
import argparse

from multiprocessing.dummy import Pool as ThreadPool
from tqdm import tqdm


def test(domain):
    print(dnssec.validate_chain(domain))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', help='Domain to validate')
    parser.add_argument(
        '--output', help='The output path to write the csv to', default='../output/out.csv')

    args = parser.parse_args()
    if args.test:
        try:
            test(args.test)
        except Exception as e:
            print(type(e), e)
    else:
        pool = ThreadPool(8)
        alexa_df = pd.read_csv(
            '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv.tar.gz', sep=',', index_col=0, names=['domain'])[:-1]
        with open(args.output, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(
                ['domain', 'validation_state', 'num_validated_zones'])
            domains = alexa_df['domain'].values
            for res in tqdm(pool.imap_unordered(dnssec.validate_chain, domains), total=len(domains)):
                writer.writerow(
                    [res.name, res.validation_state, res.num_validated])
                csvfile.flush()
