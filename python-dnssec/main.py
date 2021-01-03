import dnssec
from tqdm import tqdm
import time
import csv
import pandas as pd
import dns.rdatatype


def main():
    alexa_df = pd.read_csv('../data/alexa-top1m-2020-10-30_0900_UTC.csv', sep=',', index_col=0, names=['domain'])
    with tqdm(total=len(alexa_df)) as pbar:
        with open('../output/dnssec_deployed.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            writer.writerow(['domain', 'validated'])
            for i, domain in enumerate(alexa_df['domain']):
                try:
                    dnssec.validate_chain(domain)
                    writer.writerow([domain, True])
                except Exception as e:
                    writer.writerow([domain, False])
                pbar.update()
                if i % 100 == 0:
                    csvfile.flush()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)

