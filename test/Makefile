all: instrument app core/core.o
	ld -s core/core.o model/pcs-instrumented.o

app:
	gcc -c model/pcs.c -I core/ -o model/pcs.o

instrument: app
	hijacker -c conf.xml -i model/pcs.o -o model/pcs-instrumented.o

core/core.o:
	gcc -c core/scheduler.c -I model/ -I core/ -o core/scheduler.o
	gcc -c core/calqueue.c -I core/ -o core/calqueue.o
	gcc -c core/rng.c -I core/ -o core/rng.o
	ld -r core/scheduler.o core/calqueue.o core/rng.o -o core/core.o
	rm core/scheduler.o core/calqueue.o core/rng.o

clean:
	find . -name "*.o" -exec rm {} \;