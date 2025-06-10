#!/bin/sh

RULES_FILE="rules.txt"

while IFS= read -r line
do
  echo " $line"
  eval $line
done < "$RULES_FILE"
