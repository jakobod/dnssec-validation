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


def plot_or_show(output_path, figure_name):
  if output_path:
    plt.savefig(output_path+figure_name,
                bbox_inches='tight')
  else:
    plt.show()


def plot_dnskey_algorithms(df, output_path):
  df.sort_values(by='count', inplace=True, ascending=False)
  colors = []
  for val in df['standard_conforming']:
    if val == 'CONFORMING':
      colors.append('#1f77b4')
    else:
      colors.append('#ff7f0e')
  df.plot.bar(x='name', y='count', color=colors, rot=45, figsize=(12, 5))
  plt.gca().get_legend().remove()
  plt.title('DNSKEY Algorithms used', loc='left')
  plt.xlabel('DNSKEY Algorithm')
  plt.ylabel('Count [#]')
  plot_or_show(output_path, 'dnskey_algorithms.pdf')

  df.plot.pie(y='count', figsize=(7, 7),
              labels=df['name'], labeldistance=None, explode=[.05, .05, .05, .05, .05, .05, .05, .05], pctdistance=1.1, startangle=90, autopct='%1.1f%%', title='DNSKEY Algorithms used')
  plt.ylabel('')
  plt.tight_layout()
  plot_or_show(output_path, 'dnskey_algorithms_pie.pdf')


def plot_ds_digests(df, output_path):
  df.sort_values(by='count', inplace=True, ascending=False)
  colors = []
  for val in df['standard_conforming']:
    if val == 'CONFORMING':
      colors.append('#1f77b4')
    else:
      colors.append('#ff7f0e')
  df.plot.bar(x='name', y='count', color=colors, rot=45, figsize=(12, 5))
  plt.gca().get_legend().remove()
  plt.title('DS Digests used', loc='left')
  plt.xlabel('DS Digest')
  plt.ylabel('Count [#]')
  plot_or_show(output_path, 'ds_digests.pdf')

  df.plot.pie(y='count', figsize=(7, 7),
              labels=df['name'], labeldistance=None, explode=[.05, .05, .05, .05], pctdistance=1.1, startangle=90, autopct='%1.1f%%', title='DS Digests used')
  plt.ylabel('')
  plt.tight_layout()
  plot_or_show(output_path, 'ds_digests_pie.pdf')


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


def get_from_df(df, keys):
  lst = []
  for key in keys:
    try:
      lst.append(df.loc[key].get(0))
    except KeyError:
      lst.append(0)
  return lst


def get_list(df, to_keep, what):
  dropped = df.drop(df[(df['validation_state'] != to_keep)].index)
  dropped = dropped.groupby('tld').count()
  return get_from_df(dropped, what)


def plot_partial_validations(df, output_path):
  partial_df = df.drop(df[(df['validation_state'] != 'PARTIAL')].index)
  partial_df = partial_df.groupby('tld').count()
  partial_df.drop(partial_df.columns.difference(
      ['name']), 1, inplace=True)
  partial_df.columns = ['count']
  partial_list = partial_df['count'].values

  partial_df.plot.bar(rot=0, figsize=(12, 5), stacked=True)
  plt.xlabel('TLD')
  plt.ylabel('Count [#]')
  plt.title('Partially Broken Chains', loc='left')
  plot_or_show(output_path, 'partial_dnssec_deployment.pdf')

  tlds = partial_df.index

  all_domains_with_tld_df = df.drop(
      df[(~df['tld'].isin(partial_df.index))].index)

  columns = []
  for state in ['VALIDATED', 'UNSECURED', 'TIMEOUT', 'QUERY_ERROR', 'MISSING_RESSOURCE', 'OTHER']:
    columns.append(get_list(all_domains_with_tld_df, state, tlds))

  # For completeness sake: This will also include the errors. In the current dataset no errors were present, so 'm deleting them
  # new_df = pd.DataFrame({'partial': partial_list,
  #                        'validated': columns[0], 'unsecured': columns[1], 'timeout': columns[2],
  #                        'query_error': columns[3], 'missing_ressource': columns[4], 'other': columns[5]}, index=tlds)

  new_df = pd.DataFrame(
      {'partial': partial_list, 'unsecured': columns[1]}, index=tlds)

  # count_df.sort_values(by='count', inplace=True, ascending=False)
  new_df.plot.bar(rot=0, figsize=(12, 5), stacked=True)

  plt.xlabel('TLD')
  plt.ylabel('Count [#]')
  plt.title('Partially Broken Chains', loc='left')
  plot_or_show(output_path, 'partial_dnssec_deployment_stacked.pdf')


# TODO This is not representative. Or is it?!
def plot_deployment_across_popularity(df, output_path):
  # index_df = df.reset_index()
  sampled_df = df.reset_index()
  # sampled_df = index_df.sample(frac=1)

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
  dnskey_algorithms_df = pd.read_csv(input_path+'dnskey_algorithms.csv')
  ds_digests_df = pd.read_csv(input_path+'ds_digests.csv')

  # plot_deployment(all_domains_df, output_path)
  # plot_deployment_across_popularity(all_domains_df, output_path)
  # plot_key_distribution(all_zones_df, output_path)
  # plot_nsec_version(all_zones_df, output_path)
  # plot_by_tld(all_domains_df, output_path)
  plot_dnskey_algorithms(dnskey_algorithms_df, output_path)
  plot_ds_digests(ds_digests_df, output_path)
  # plot_partial_validations(all_domains_df, output_path)


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
