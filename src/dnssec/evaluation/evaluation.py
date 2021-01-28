#!/usr/bin/env python3

import json
import pandas as pd
import time
import argparse
from dnssec.probing.datatypes import ValidationResult
from enum import Enum
import matplotlib.pyplot as plt


class EvalState(Enum):
  UNBROKEN = 0,
  BROKEN = 1,
  FLAPPING = 2,


def plot_or_show(output_path):
  if output_path:
    if output_path[-1] != '/':
      output_path += '/'
    plt.savefig(output_path + 'dnssec_deployment.pdf',
                bbox_inches='tight')
  else:
    plt.show()


def plot_errors(dataframe, output_path):
  error_df = dataframe.groupby('reason')
  print(error_df.get_group(()))
  # count_df = validation_res_df.groupby('result', as_index=False).count()
  # count_df = count_df.drop(['reason'], axis=1)
  # count_df.columns = ['result', 'count']
  # count_df.sort_values(by='count', inplace=True, ascending=False)
  # print(count_df)
  # plot_or_show(output_path)


def plot_deployment(validation_res_df, output_path):
  count_df = validation_res_df.groupby('result', as_index=False).count()
  count_df = count_df.drop(['reason'], axis=1)
  count_df.columns = ['result', 'count']
  count_df.sort_values(by='count', inplace=True, ascending=False)
  print(count_df)

  plt.bar(x=count_df['result'], height=count_df['count'])
  plt.xlabel('Result')
  plt.ylabel('Count [#]')
  plt.title('Results of DNSSEC validation', loc='left')
  plt.gcf().set_size_inches(12, 5)

  plot_or_show(output_path)


def is_flapping(zone_infos):
  state = EvalState.UNBROKEN
  for zone_info in zone_infos:
    if state == EvalState.UNBROKEN and not zone_info['validated']:
      state = EvalState.BROKEN
    elif state == EvalState.BROKEN and zone_info['validated']:
      state = EvalState.FLAPPING
  return state == EvalState.FLAPPING


def deployed_keys(zone_infos):
  zones = []
  for i, zone_info in enumerate(zone_infos):
    if zone_info['num_ksk'] != 0 and zone_info['num_zsk'] == 0:
      zones.append(zone_info['name'])
  return zones


def to_csv(args):
  only_ksks = set()
  with open(args.input, 'r') as json_file:
    lst = []
    t1 = time.time()
    for i, line in enumerate(json_file):
      dct = json.loads(line)
      zones = dct['zones']
      flapping = is_flapping(zones)
      only_ksks.update(deployed_keys(zones))

      lst.append([dct['name'], dct['validation_state'], dct['reason']])

      # if i > 10:
      #   break
      # break

      # df = pd.DataFrame(lst,
      #                   columns=['name', 'result', 'reason'])

    df = pd.DataFrame(lst,
                      columns=['name', 'result', 'reason'])
    plot_deployment(df, args.output_path)
    plot_errors(df, args.output_path)
    t2 = time.time()
    print(t2-t1, 's')
    print(len(only_ksks), 'zones deploy dnssec only using KSKs')


def main():
  # action='store_true'
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '-c', '--to-csv', help='Evaluate the given input file and save it to csv', metavar='OUTFILE')
  parser.add_argument(
      '-o', '--output-path', help='Path at which created files are written to', metavar='PATH')

  parser.add_argument(
      'input', help='The json that should be evaluated', metavar='JSON_PATH')
  args = parser.parse_args()

  if args.to_csv:
    to_csv(args)


if __name__ == '__main__':
  main()
