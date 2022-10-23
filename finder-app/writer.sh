#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Incorrect number of parameters! Expects path/to/filename and string to write to the file"
    exit 1
else
    filename="$1"
    directory=$(dirname $filename)
    string_to_add="$2"
    
    if [ ! -d $directory ]; then
        mkdir $directory
    fi
    echo $string_to_add > $filename
    exit 0
    fi
    
    if [ $? -ne 0 ]; then
        echo "File creation failed!"
        exit 1
    fi
fi
