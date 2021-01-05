import dnssec
import csv
import pandas as pd
import dns.exception
import time

from tqdm import tqdm
from exception import RecordMissingError
from exception import QueryError


def main(num_domains):
    validated = 0
    alexa_df = pd.read_csv(
        '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv.tar.gz', sep=',', index_col=0, names=['domain'], nrows=num_domains)
    with tqdm(total=len(alexa_df)) as pbar:
        with open('../output/dnssec_deployed.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(['domain', 'validationState'])
            for i, domain in enumerate(alexa_df['domain']):
                try:
                    dnssec.validate_chain(domain)
                    print(f'{domain} VALIDATED')
                    writer.writerow([domain, 'VALIDATED'])
                    validated += 1
                except RecordMissingError as e:
                    print(f'{domain} UNSECURED')
                    writer.writerow([domain, 'UNSECURED'])
                except dns.exception.Timeout as e:
                    print(f'{domain} TIMEOUT')
                    writer.writerow([domain, 'TIMEOUT'])
                except QueryError as e:
                    print(f'{domain} e')
                    writer.writerow([domain, e])
                except Exception as e:
                    print(f'{type(e)}: {e}')
                    writer.writerow([domain, 'OTHER'])
                pbar.update()
                if i % 100:
                    csvfile.flush()
            print(f'validated {validated} of {len(alexa_df)} domains')


if __name__ == '__main__':
    try:
        t1 = time.time()
        main(1000)
        t2 = time.time()
        print(f'validating took {t2-t1}s')
    except Exception as e:
        print(f'{type(e)}: {e}')
