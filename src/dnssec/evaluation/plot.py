#!/usr/bin/env python3


import pandas as pd
import argparse
import matplotlib.pyplot as plt

algorithms = {'RSAMD5': 'MUST NOT',
              'DSA': 'MUST NOT',
              'RSASHA1': 'NOT RECOMMENDED',
              'DSANSEC3SHA1': 'MUST NOT',
              'RSASHA1NSEC3SHA1': 'NOT RECOMMENDED',
              'RSASHA256': 'MUST',
              'RSASHA512': 'NOT RECOMMENDED',
              'ECCGOST': 'MUST NOT',
              'ECDSAP256SHA256': 'MUST',
              'ECDSAP384SHA384': 'MAY',
              'ED25519': 'RECOMMENDED',
              'ED448': 'MAY'}


def plot_errors(df, output_path):
  group = df.groupby(['result', 'reason']).count()
  print(group)


def plot_deployment(df, output_path):
  print(df)
  count_df = df.groupby('validation_state', as_index=False).count()
  # count_df = count_df.drop(['name', 'is_flapping'], axis=1)
  # count_df.columns = ['validation_state', 'count']
  # count_df.sort_values(by='count', inplace=True, ascending=False)
  print(count_df)

  # plt.bar(x=count_df['validation_state'], height=count_df['count'])
  # plt.xlabel('Result')
  # plt.ylabel('Count [#]')
  # plt.title('Results of DNSSEC validation', loc='left')
  # plt.gcf().set_size_inches(12, 5)

  # if output_path:
  #   plt.savefig(output_path + 'dnssec_deployment.pdf',
  #               bbox_inches='tight')
  # else:
  #   plt.show()


def plot(input_path, output_path):
  all_domains_df = pd.read_csv(input_path+'all_domains.csv')
  plot_deployment(all_domains_df, output_path)
  # all_zones_df = pd.read_csv(input_path+'all_zones.csv')


def main():
  # action='store_true'
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--input-path', help='The path from which the files should be read', metavar='INPUT_PATH')
  parser.add_argument(
      '--output-path', help='Path at which created files are written to', metavar='OUTPUT_PATH')
  args = parser.parse_args()

  # Check input
  if args.input_path is None:
    print('An input path is required!')
    exit(-1)
  elif args.input_path[-1] != '/':
    args.input_path += '/'
  if args.output_path:
    if args.output_path[-1] != '/':
      args.output_path += '/'

  plot(args.input_path, args.output_path)


if __name__ == '__main__':
  main()
