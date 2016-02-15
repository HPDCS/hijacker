#!/bin/bash

FILE=data.dat
lines=$(wc -l $DATAFILE)
echo $lines
gnuplot -e "file='$DATAFILE'" -e "lines='$lines'" plot.plt
