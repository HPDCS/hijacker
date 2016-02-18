set terminal postscript eps enhanced color font 'Helvetica,10'

n=100
xmin=0
xmax=lines
binwidth=(xmax-xmin)/n
set xrange [0:100]

bin(x,width)=width*floor(x/width)+width/2.0
countpoints(file) = system(sprintf("grep -v '^#' %s| wc -l", file))

set output sprintf("%s-accuracy.eps",file)
plot file using (bin(($1), binwidth)):(1.0/(binwidth*lines)) smooth freq with boxes;

set output sprintf("%s-access.eps",file)
plot file using (bin(($1), binwidth)):(1.0/(binwidth*lines)) smooth freq with boxes;
