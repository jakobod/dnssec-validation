#!/usr/bin/env python3


import pandas as pd
import argparse
import matplotlib.pyplot as plt
import matplotlib.colors as clrs
import seaborn as sns
import numpy as np
from collections import defaultdict


# TODO
# [] Plot used Algorithms and distinguish secure and unsecure ciphers.
# [] Visualize trust chain


standard_width = (10, 4)


def y_formatter(y, pos):
  if y >= 1_000_000:
    return '{:>}M'.format(int(y / 1_000_000))
  elif y >= 1_000:
    return '{:>}K'.format(int(y / 1_000))
  return '{:>}'.format(int(y))


def plot_or_show(output_path, figure_name):
  if output_path:
    plt.savefig(output_path+figure_name,
                bbox_inches='tight', transparent=True)
    print('wrote', output_path+figure_name)
  else:
    plt.show()


def add_labels_to_stacked_bars(ax, width, bar_count, height_offset=1):
  patch_dct = defaultdict(lambda: 0)
  for i, p in enumerate(ax.patches):
    patch_dct[i % bar_count] += p.get_height()
  for i in range(bar_count):
    p = ax.patches[i]
    height = patch_dct[i]
    height_str = str(int(height))
    padding_len = int((width - len(height_str)))
    padding = ' ' * padding_len
    label = padding + height_str
    ax.annotate(label, (p.get_x(), height + height_offset))


def add_labels_to_bars(ax, width, height_offset=1000):
  for p in ax.patches:
    height = str(p.get_height())
    padding_len = int((width - len(height)))
    padding = ' ' * padding_len
    label = padding + height
    ax.annotate(label, (p.get_x(), p.get_height() + height_offset))


def plot_dnskey_algorithms(df, output_path):
  df.sort_values(by='count', inplace=True, ascending=False)
  ax = df.plot.pie(y='count', figsize=standard_width,
                   labels=df['name'], labeldistance=None, explode=[.05, .05, .05, .05, .05, .05, .05, .05], pctdistance=1.1, startangle=90)
  percent = 100.*df['count'].values/df['count'].values.sum()

  unsecure = {'RSAMD5', 'DSA', 'RSASHA1', 'DSANSEC3SHA1',
              'RSASHA1NSEC3SHA1', 'RSASHA512', 'ECCGOST'}
  labels = []
  for i, j in zip(df['name'], percent):
    if i in unsecure:
      labels.append('{0} - {1:1.2f} % (✘)'.format(i, j))
    else:
      labels.append('{0} - {1:1.2f} % (✔)'.format(i, j))

  patches, labels, dummy = zip(*sorted(zip(ax.patches, labels, df['count'].values),
                                       key=lambda x: x[2],
                                       reverse=True))
  plt.legend(patches, labels, bbox_to_anchor=(.97, 0.5), loc='center right', bbox_transform=plt.gcf().transFigure,
             fontsize=8, prop={'size': 10})
  plt.ylabel('')
  plt.tight_layout()
  plot_or_show(output_path, 'dnskey_algorithms_pie.pdf')

  plt.legend(patches, labels, bbox_to_anchor=(1.2, 0.5), loc='center right', bbox_transform=plt.gcf().transFigure,
             fontsize=10, prop={'size': 18})
  plot_or_show(output_path, 'dnskey_algorithms_pie_large_legend.pdf')


def plot_ds_digests(df, output_path):
  df.sort_values(by='count', inplace=True, ascending=False)

  ax = df.plot.pie(y='count', figsize=standard_width,
                   labels=df['name'], labeldistance=None,
                   explode=[.05, .05, .05, .05], pctdistance=1.1,
                   startangle=90)
  percent = 100.*df['count'].values/df['count'].values.sum()

  unsecure = {'NULL', 'SHA1', 'GOST'}
  labels = []
  for i, j in zip(df['name'], percent):
    if i in unsecure:
      labels.append('{0} - {1:1.2f} % (✘)'.format(i, j))
    else:
      labels.append('{0} - {1:1.2f} % (✔)'.format(i, j))

  patches, labels, dummy = zip(*sorted(zip(ax.patches, labels, df['count'].values),
                                       key=lambda x: x[2],
                                       reverse=True))
  plt.legend(patches, labels, bbox_to_anchor=(.9, 0.5), loc='center right', bbox_transform=plt.gcf().transFigure,
             fontsize=8, prop={'size': 10})

  plt.ylabel('')
  plt.tight_layout()
  plot_or_show(output_path, 'ds_digests_pie.pdf')

  plt.legend(patches, labels, bbox_to_anchor=(1.2, 0.5), loc='center right', bbox_transform=plt.gcf().transFigure,
             fontsize=10, prop={'size': 22})
  plot_or_show(output_path, 'ds_digests_pie_large_legend.pdf')


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
  new_df = new_df[:20]
  ax = new_df.plot.bar(rot=0, stacked=True, figsize=standard_width)
  ax.yaxis.set_major_formatter(plt.FuncFormatter(y_formatter))
  plt.ylabel('Count [#]')
  plt.xlabel('')

  plot_or_show(output_path, 'results_by_tld.pdf')

  tld_count_df = df.groupby('tld').count()
  tld_count_df.drop(tld_count_df.columns.difference(
      ['reason', ]), 1, inplace=True)
  tld_count_df.columns = ['count']
  tld_count_df.sort_values(by='count', inplace=True, ascending=False)
  tld_count_df = tld_count_df[:20]
  ax = tld_count_df.plot.bar(rot=0, figsize=standard_width)
  ax.yaxis.set_major_formatter(plt.FuncFormatter(y_formatter))
  ax.get_legend().remove()
  plt.ylabel('Count [#]')
  plt.xlabel('')
  # plt.title('Results of DNSSEC validation', loc='left')
  plot_or_show(output_path, 'domains_by_tld.pdf')


def plot_nsec_version(df, output_path):
  unsecured_df = df.groupby('validation_state',
                            as_index=False).get_group(('UNSECURED'))
  count_df = unsecured_df.groupby('reason', as_index=False).count()
  count_df.drop(count_df.columns.difference(
      ['reason', 'name']), 1, inplace=True)
  count_df.columns = ['version', 'count']
  count_df.sort_values(by='count', ascending=False, inplace=True)

  ax = count_df.plot.bar(x='version', y='count',
                         color=['#1f77b4', '#ff7f0e'], rot=0, figsize=standard_width)
  ax.yaxis.set_major_formatter(plt.FuncFormatter(y_formatter))
  add_labels_to_bars(ax, 22, 4000)

  ax.get_legend().remove()
  plt.xlabel('NSEC version')
  plt.ylabel('Count [#]')
  # plt.title('NSEC Version Deployment across probed zones', loc='left')
  plot_or_show(output_path, 'nsec_deployment.pdf')

  ax = count_df.plot.pie(y='count', figsize=standard_width,
                         labels=count_df['version'], labeldistance=None, explode=[.05, .05], pctdistance=1.1, startangle=90)
  percent = 100.*count_df['count'].values/count_df['count'].values.sum()
  labels = ['{0} - {1:1.2f} %'.format(i, j)
            for i, j in zip(count_df['version'], percent)]
  patches, labels, dummy = zip(*sorted(zip(ax.patches, labels, count_df['count'].values),
                                       key=lambda x: x[2],
                                       reverse=True))
  plt.legend(patches, labels, bbox_to_anchor=(.875, 0.5), loc='center right', bbox_transform=plt.gcf().transFigure,
             fontsize=8, prop={'size': 10})
  plt.ylabel('')
  plt.tight_layout()
  plot_or_show(output_path, 'nsec_deployment_pie.pdf')


def plot_key_distribution(df, output_path):
  count_df = df.groupby(['num_ksk', 'num_zsk'], as_index=False).count()
  count_df.drop(count_df.columns.difference(
      ['num_ksk', 'num_zsk', 'name']), 1, inplace=True)
  count_df.columns = ['num_zsk', 'num_ksk', 'count']

  count_df.plot.scatter(x='num_ksk', y='num_zsk',
                        c='count', colormap='viridis', marker='s', s=(29.5)**2,
                        figsize=(6, 4.8), norm=clrs.LogNorm())
  plt.xticks(np.arange(min(count_df['num_ksk']),
                       max(count_df['num_ksk'])+1, 1.0))
  plt.xlabel('Number of KSK [#]')
  plt.ylabel('Number of ZSK [#]')
  # plt.title('Distribution of keys', loc='left')
  plot_or_show(output_path, 'key_distribution.pdf')


def plot_deployment(df, output_path):
  count_df = df.groupby('validation_state', as_index=False).count()
  count_df.drop(count_df.columns.difference(
      ['validation_state', 'name']), 1, inplace=True)
  count_df.columns = ['validation_state', 'count']
  count_df.sort_values(by='count', inplace=True, ascending=False)

  ax = count_df.plot.bar(x='validation_state', y='count',
                         rot=30, figsize=standard_width)
  ax.yaxis.set_major_formatter(plt.FuncFormatter(y_formatter))
  ax.get_legend().remove()
  add_labels_to_bars(ax, 6, 4000)

  plt.xlabel('')
  plt.ylabel('Count [#]')
  # plt.title('Results of DNSSEC validation', loc='left')
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

  ax = partial_df.plot.bar(rot=0, figsize=standard_width)
  ax.yaxis.set_major_formatter(plt.FuncFormatter(y_formatter))
  add_labels_to_bars(ax, 15, 0.1)
  ax.get_legend().remove()
  plt.xlabel('TLD')
  plt.ylabel('Count [#]')
  # plt.title('Partially Broken Chains', loc='left')
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

  ax = new_df.plot.bar(rot=0, figsize=standard_width, stacked=True)
  ax.yaxis.set_major_formatter(plt.FuncFormatter(y_formatter))
  add_labels_to_stacked_bars(ax, 15, 3)

  plt.xlabel('TLD')
  plt.ylabel('Count [#]')
  # plt.title('Partially Broken chains by zone', loc='left')
  plot_or_show(output_path, 'partial_dnssec_deployment_stacked.pdf')


def plot(input_path, output_path):
  all_domains_df = pd.read_csv(input_path+'all_domains.csv')
  all_zones_df = pd.read_csv(input_path+'all_zones.csv')
  dnskey_algorithms_df = pd.read_csv(input_path+'dnskey_algorithms.csv')
  ds_digests_df = pd.read_csv(input_path+'ds_digests.csv')

  plot_deployment(all_domains_df, output_path)
  plot_key_distribution(all_zones_df, output_path)
  plot_nsec_version(all_zones_df, output_path)
  plot_by_tld(all_domains_df, output_path)
  plot_dnskey_algorithms(dnskey_algorithms_df, output_path)
  plot_ds_digests(ds_digests_df, output_path)
  plot_partial_validations(all_domains_df, output_path)


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
