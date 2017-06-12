#!/usr/bin/env bash

ARGV0=$1
for i in $ARGV0; do
    echo $i
    new_port=8$i
    echo $new_port
done

echo "doing this to $1 and $2"

value=$(<ports.txt)
echo $value
for i in $value; do
    if [ $i -le 100 ]; then
    p=80$i;
    else
        p=8$i;
    fi
echo $i $p
done