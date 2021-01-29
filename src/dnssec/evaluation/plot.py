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


def plot_or_show(output_path, figure_name):
  if output_path:
    plt.savefig(output_path+figure_name,
                bbox_inches='tight')
  else:
    plt.show()


def plot_ciphers(df, output_path):
  print(df)


def get_count(df, tld, key):
  try:
    return df.loc[tld, key].get(0, 0)
  except KeyError:
    return 0


def get_counts(df, tld):
  row = []
  for key in ['UNSECURED', 'TIMEOUT', 'QUERY_ERROR', 'MISSING_RESSOURCE', 'OTHER', 'VALIDATED']:
    row.append(get_count(df, tld, key))
  row.append(sum(row))
  return row


def plot_by_tld(df, output_path):
  indexes = df.groupby('tld').count().index
  count_df = df.groupby(['tld', 'validation_state']).count()
  count_df.drop(count_df.columns.difference(
      ['name']), 1, inplace=True)
  count_df.columns = ['count']

  rows = []
  for tld in indexes:
    rows.append(get_counts(count_df, tld))
  new_df = pd.DataFrame(
      rows, columns=['UNSECURED', 'TIMEOUT', 'QUERY_ERROR', 'MISSING_RESSOURCE', 'OTHER', 'VALIDATED', 'TOTAL'], index=indexes)
  new_df.sort_values(by='TOTAL', inplace=True, ascending=False)
  new_df.drop('TOTAL', 1, inplace=True)
  new_df = new_df[:40]
  new_df.plot.bar(stacked=True, figsize=(12, 5))
  plot_or_show(output_path, 'results_by_tld.pdf')


def plot_nsec_version(df, output_path):
  unsecured_df = df.groupby('validation_state',
                            as_index=False).get_group(('UNSECURED'))
  count_df = unsecured_df.groupby('reason', as_index=False).count()
  count_df.drop(count_df.columns.difference(
      ['reason', 'name']), 1, inplace=True)
  count_df.columns = ['version', 'count']

  count_df.plot.bar(x='version', y='count', rot=0, figsize=(12, 5))

  plt.xlabel('NSEC version')
  plt.ylabel('Count [#]')
  plt.title('NSEC Version Deployment across probed zones', loc='left')
  plot_or_show(output_path, 'nsec_deployment.pdf')


def plot_key_distribution(df, output_path):
  count_df = df.groupby(['num_ksk', 'num_zsk'], as_index=False).count()
  count_df.drop(count_df.columns.difference(
      ['num_ksk', 'num_zsk', 'name']), 1, inplace=True)
  count_df.columns = ['num_zsk', 'num_ksk', 'count']

  count_df.plot.scatter(x='num_ksk', y='num_zsk',
                        c='count', colormap='viridis', marker='s', s=50**2,
                        figsize=(10, 8), norm=clrs.LogNorm())

  plt.xlabel('Number of KSK [#]')
  plt.ylabel('Number of ZSK [#]')
  plt.title('Distribution of keys', loc='left')
  plot_or_show(output_path, 'key_distribution.pdf')


def plot_deployment(df, output_path):
  count_df = df.groupby('validation_state', as_index=False).count()
  count_df.drop(count_df.columns.difference(
      ['validation_state', 'name']), 1, inplace=True)
  count_df.columns = ['validation_state', 'count']
  count_df.sort_values(by='count', inplace=True, ascending=False)

  count_df.plot.bar(x='validation_state', y='count', rot=0, figsize=(12, 5))

  plt.xlabel('Result')
  plt.ylabel('Count [#]')
  plt.title('Results of DNSSEC validation', loc='left')
  plot_or_show(output_path, 'dnssec_deployment.pdf')


# TODO This is not representative. Or is it?!
def plot_deployment_across_popularity(df, output_path):
  index_df = df.reset_index()
  sampled_df = index_df.sample(frac=0.3)

  sampled_df.drop(sampled_df.columns.difference(
      ['index', 'validation_state']), 1, inplace=True)
  sampled_df = sampled_df.drop(
      sampled_df[(sampled_df['validation_state'] != 'UNSECURED') & (sampled_df['validation_state'] != 'VALIDATED') & (sampled_df['validation_state'] != 'PARTIAL')].index)
  sampled_df.plot.scatter(x='index', y='validation_state',
                          rot=0, s=1, figsize=(25, 5))

  plt.xlabel('Result')
  plt.ylabel('Count [#]')
  plt.title('Results of DNSSEC validation', loc='left')
  plot_or_show(output_path, 'dnssec_deployment_popularity.pdf')

  # Idea: X axis is position in alexa list + y axis yes or no. Maybe that shows interesting stuff?


def plot(input_path, output_path):
  all_domains_df = pd.read_csv(input_path+'all_domains.csv')
  all_zones_df = pd.read_csv(input_path+'all_zones.csv')

  plot_deployment(all_domains_df, output_path)
  plot_deployment_across_popularity(all_domains_df, output_path)
  plot_key_distribution(all_zones_df, output_path)
  plot_nsec_version(all_zones_df, output_path)
  plot_by_tld(all_domains_df, output_path)
  plot_ciphers(all_zones_df, output_path)


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
