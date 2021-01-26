#!/bin/zsh

# This script will run the python script on the previously split domain.csv files.

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    exit -1
fi

prefix="datasets"
file="${prefix}/alexa-top1m-2021-01-04_0900_UTC.csv"
num_files=$1
total_lines=$(wc -l <$file)
((lines_per_file = (total_lines + num_files - 1) / num_files))

echo "number of files = ${num_files}"
echo "Total lines     = ${total_lines}"
echo "Lines  per file = ${lines_per_file}"

if [[ "$(uname)" == "Darwin" ]]; then
  gsplit --lines=${lines_per_file} -a4 -d ${file} ${prefix}/domains.
else
  split --lines=${lines_per_file} -a4 -d ${file} ${prefix}/domains.
fi

pids=()
for i in {0000..$num_files}; do
  current_input="datasets/domains.${i}"
  current_output="output/results_${i}.json"
  ./python-dnssec/main.py ${current_input} --output ${current_output} &
  pids+=($!)
done;

# wait for all pids
for pid in ${pids[*]}; do
    wait $pid
done
