#!/usr/bin/env python3

import argparse
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='./evaluate.py',
                                     description='Create graphics from given csv files')
    parser.add_argument(
        'input', help='CSV file containing the values to plot')
    parser.add_argument('output', help='The output path for the graphic')
    args = parser.parse_args()

    if args.input.split('.')[-1] != 'csv':
        print('Input has to be a csv file')
        exit(-1)

    df = pd.read_csv(args.input, sep=',')
    count_df = df.groupby(
        'validation_state', as_index=False).count()

    # plot this
    fig, ax = plt.plot(count_df['validation_state'],
                       count_df['num_validated_zones'])

    ax.set_xlabel('Interval [1800 simulation steps]')
    ax.set_ylabel(args.label + 's [#]')
    ax.set_title(args.label + ' throughput', loc='left')
    ax.legend()

    plt.show()
