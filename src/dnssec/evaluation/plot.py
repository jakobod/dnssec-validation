#!/usr/bin/env python3


import pandas as pd
import argparse
import matplotlib.pyplot as plt
import matplotlib.colors as clrs
import seaborn as sns
import numpy as np


# TODO
# [] Plot used Algorithms and distinguish secure and unsecure ciphers.
# [] Visualize trust chain
# [] Plot NSEC usage


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


def plot_or_show(output_path, figure_name):
  if output_path:
    plt.savefig(output_path+figure_name,
                bbox_inches='tight')
  else:
    plt.show()


def plot_key_distribution(df, output_path):
  counted_df = df.groupby(['num_ksk', 'num_zsk'], as_index=False).count()
  counted_df.drop(counted_df.columns.difference(
      ['num_ksk', 'num_zsk', 'name']), 1, inplace=True)
  counted_df.columns = ['num_zsk', 'num_ksk', 'count']
  counted_df = counted_df.drop(
      counted_df[(counted_df['num_zsk'] == 0) & (counted_df['num_ksk'] == 0)].index)
  counted_df.plot.scatter(x='num_ksk', y='num_zsk',
                          c='count', colormap='viridis', marker='s', s=50**2,
                          figsize=(10, 8), norm=clrs.LogNorm())
  plt.xlabel('Number of KSK [#]')
  plt.ylabel('Number of ZSK [#]')
  plt.title('Distribution of keys', loc='left')
  plot_or_show(output_path, 'key_distribution.pdf')


def plot_deployment(df, output_path):
  count_df = df.groupby('validation_state', as_index=False).count()
  count_df = count_df.drop(['reason'], axis=1)
  count_df.columns = ['validation_state', 'count']
  count_df.sort_values(by='count', inplace=True, ascending=False)
  plt.bar(x=count_df['validation_state'], height=count_df['count'])
  plt.xlabel('Result')
  plt.ylabel('Count [#]')
  plt.title('Results of DNSSEC validation', loc='left')
  plt.gcf().set_size_inches(12, 5)
  plot_or_show(output_path, 'dnssec_deployment.pdf')


def plot(input_path, output_path):
  all_domains_df = pd.read_csv(input_path+'all_domains.csv')
  all_zones_df = pd.read_csv(input_path+'all_zones.csv')

  plot_deployment(all_domains_df, output_path)
  plot_key_distribution(all_zones_df, output_path)


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
