#!/usr/bin/env python3

import json
from dnssec.probing.datatypes import ValidationResult


def main():
  file_path = r'datasets/dnssec_validation.json'

  with open(file_path, 'r') as json_file:
    for i, line in enumerate(json_file):

      json_obj = json.loads(line)
      res = ValidationResult('blubb')
      print(res)
      break


if __name__ == '__main__':
  main()
