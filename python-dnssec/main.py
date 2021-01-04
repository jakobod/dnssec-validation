import dnssec
import csv
import pandas as pd
import dns.exception

from tqdm import tqdm
from exception import RecordMissingError
from exception import QueryError


def main():
    alexa_df = pd.read_csv(
        '../datasets/alexa-top1m-2021-01-04_0900_UTC.csv', sep=',', index_col=0, names=['domain'])
    with tqdm(total=len(alexa_df)) as pbar:
        with open('../output/dnssec_deployed.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(['domain', 'validationState'])
            for i, domain in enumerate(alexa_df['domain']):
                try:
                    dnssec.validate_chain(domain)
                    writer.writerow([domain, 'VALIDATED'])
                except RecordMissingError as e:
                    writer.writerow([domain, 'UNSECURED'])
                except dns.exception.Timeout as e:
                    writer.writerow([domain, 'TIMEOUT'])
                except QueryError as e:
                    writer.writerow([domain, e])
                except Exception as e:
                    print(f'{type(e)}: {e}')
                    writer.writerow([domain, 'OTHER'])
                pbar.update()
                if i == 100:
                    csvfile.flush()
                    break


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f'{type(e)}: {e}')
