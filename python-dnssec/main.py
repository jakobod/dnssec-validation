#!/usr/bin/env python3

import dnssec
import csv
import pandas as pd
import argparse
import dns

from multiprocessing.dummy import Pool as ThreadPool
from tqdm import tqdm


def nsec3(domain):
    dnssec.validate_root_zone()
    try:
        if dnssec.query_DS(
                dnssec.Zone('jakob-otto.de.', None, None, None),
                dnssec.Zone('de.', None, '194.0.0.53', None)):
            print('jakob-otto.de has DNSSEC deployed')
    except Exception as e:
        print(e)
    try:
        print(dnssec.query_DS(
            dnssec.Zone('sina.com.cn.', None, None, None),
            dnssec.Zone('com.cn.', None, '203.119.25.1', None)))
    except Exception as e:
        print(type(e), e)


def test(domain):
    dnssec.validate_root_zone()
    print(dnssec.validate_chain(domain))
    print(dnssec.validate_chain(domain))


def test_main(nrows):
    dnssec.validate_root_zone()
    alexa_df = pd.read_csv(
        '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv.tar.gz', sep=',', index_col=0, names=['domain'], nrows=nrows)[:-1]
    domains = alexa_df['domain'].values
    for domain in domains:
        print(dnssec.validate_chain(domain))


def test_split(domain):
    dnssec.validate_root_zone()
    for zone in dnssec.split(domain):
        print(zone)


if __name__ == '__main__':
    # , action='store_true' for boolean flags
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', help='Domain to validate')
    parser.add_argument(
        '--test_main', help='Run the testmain', type=int)
    parser.add_argument(
        '--test_split', help='Test the split func', type=str)
    parser.add_argument('--nsec', help='Check NSEC3 for given domain')
    parser.add_argument(
        '--output', help='The output path to write the csv to', default='../output/out.csv')

    args = parser.parse_args()
    if args.nsec:
        nsec3(args.nsec)
    elif args.test:
        test(args.test)
    elif args.test_main:
        test_main(args.test_main)
    elif args.test_split:
        test_split(args.test_split)
    else:
        pool = ThreadPool(1)
        alexa_df = pd.read_csv(
            '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv.tar.gz', sep=',', index_col=0, names=['domain'])[:-1]
        with open(args.output, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(
                ['domain', 'validation_state', 'num_validated_zones'])
            domains = alexa_df['domain'].values
            dnssec.validate_root_zone()
            for i, res in enumerate(tqdm(pool.imap_unordered(dnssec.validate_chain, domains), total=len(domains))):
                writer.writerow(
                    [res.name, res.validation_state, res.num_validated])
                if i % 100:
                    csvfile.flush()
