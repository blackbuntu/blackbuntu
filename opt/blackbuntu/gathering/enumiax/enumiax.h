#include </usr/include/stdint.h>

#include "config.h"


#define VERSION "0.4a"

/* charmap.c */
int charmap_c_to_d( char ch );

/* exit.c */
void state_exit( int signum );
int save_state( int signum );

/* inet_hton.c */
uint32_t inet_hton( char *host );

/* outputs.c */
void printbin( int buf, int bits );
void printhex( unsigned char *buf, int size );

/* worditer.c */
int nextword();
int nextdict();

/* socket.c */
int socket_build( char *target, int protocol, int port );

/* usage.c */
void version();
void usage( char *prog );

