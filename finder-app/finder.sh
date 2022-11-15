#!/bin/sh

if [ $# -ne 2 ]; then
    echo "Incorrect number of parameters! Expects directory and search string"
    exit 1
elif [ ! -d $1 ]; then
    echo "First parameter is not a directory!"
    exit 1
else
    directory="$1"
    search_string="$2"
    num_files=$(ls $directory | wc -l)
    num_lines=$(grep -r -l $search_string $directory | wc -l)
    
    echo "The number of files are $num_files and the number of matching lines are $num_lines"
    exit 0
fi
