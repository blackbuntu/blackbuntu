all: enumiax 

include base.mk

install: all
	strip enumiax
	ienumiaxtall -m 755 enumiax ${BINDIR}
	@echo
	@echo "enumiax installed!"
	@echo

uninstall:
	rm -f ${BINDIR}/enumiax
	@echo
	@echo "enumiax uninstalled!"
	@echo

	
OBJS = charmap.o exit.o inet_hton.o main.o outputs.o worditer.o socket.o usage.o
INCLUDES = enumiax.h charmap.h config.h

# enumiax
enumiax: ${OBJS}
	@echo
	@echo "Compiling enumiax..."
	${CC} ${CFLAGS} ${LINCLUDES} ${LIBS} -o $@ ${OBJS}

${OBJS}: ${INCLUDES}

