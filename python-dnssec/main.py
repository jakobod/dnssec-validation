import dnssec
import csv
import pandas as pd
import dns.exception
import time

from multiprocessing.dummy import Pool as ThreadPool
from tqdm import tqdm
from exception import RecordMissingError
from exception import QueryError


def main():
    t1 = time.time()
    pool = ThreadPool(128)
    alexa_df = pd.read_csv(
        '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv.tar.gz', sep=',', index_col=0, names=['domain'])
    domains = alexa_df['domain'].values
    results = set()
    for val in tqdm(pool.imap_unordered(dnssec.validate_chain, domains), total=len(domains)):
        results.add(val)
    t2 = time.time()
    print(f'validating took {t2-t1}s')
    with open('../output/dnssec_validation.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(
            ['domain', 'validation_state', 'num_validated_zones'])
        for res in results:
            writer.writerow(
                [res.name, res.validation_state, res.num_validated])


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f'{type(e)}: {e}')
