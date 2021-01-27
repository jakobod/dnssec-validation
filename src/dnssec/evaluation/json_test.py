#!/usr/bin/env python3

import json
from dnssec.probing.datatypes import ValidationResult


def main():
  file_path = r'datasets/dnssec_validation.json'

  with open(file_path, 'r') as json_file:
    for i, line in enumerate(json_file):

      dct = json.loads(line)
      res = ValidationResult().from_dict(dct)
      print(i, res)
      if i > 10:
        break


if __name__ == '__main__':
  main()
