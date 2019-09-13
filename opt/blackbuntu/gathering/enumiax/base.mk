# Compiler Options
#CC = gcc
CFLAGS = -O2 -Wall ${DEBUG}
DEBUG = -g

# Installation Options
BINDIR = /usr/local/bin

clean:
	rm -f core *.o *~ enumiax
	for i in `ls -l | grep "^d" | awk '{ print $$8 }'`; do \
		cd $$i; \
		if [ -e Makefile ]; then \
			make clean; \
		fi; \
		cd ../; \
	done

recurse:
	for i in `ls -l | grep "^d" | awk '{ print $$8 }'`; do \
		cd $$i; \
		if [ -e Makefile ]; then \
			make; \
		fi; \
		cd ../; \
	done

