#!/bin/zsh

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    exit -1
fi

file="datasets/alexa-top1m-2021-01-04_0900_UTC.csv"
num_files=$1
((num_processes=num_files-1))
total_lines=$(wc -l <$file)
((lines_per_file = (total_lines + num_files - 1) / num_files))

echo "Lines per file = ${lines_per_file}"
echo "Number of processes = ${num_processes}"

if [[ "$(uname)" == "Darwin" ]]; then
  # On macos the split command is prefixed with a 'g'
  gsplit --lines ${lines_per_file} -a4 -d ${file} "datasets/domains."
else
  split --lines ${lines_per_file} -a4 -d ${file} "datasets/domains."
fi

pids=()
for i in {0000..$num_processes}; do
  current_input="datasets/domains.${i}"
  current_output="output/results_${i}.json"
  probing --input ${current_input} --output ${current_output} &
  pids+=($!)
  printf "$! "
done;
echo ""

# wait for all pids
for pid in ${pids[*]}; do
    wait $pid
done

cat "output/results_*" > "output/result.json"
rm -rf "output/results_*"