#!/bin/sh

RULES_FILE="ml_data/rules.txt"

while IFS= read -r line
do
  echo " $line"
  eval $line
done < "$RULES_FILE"
