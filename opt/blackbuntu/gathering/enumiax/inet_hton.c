/*
 * inet_hton.c
 * I)ruid <druid@caughq.org>
 *
 * Function to convert hostname (or IP address) into network byte
 * order.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


uint32_t inet_hton( char *host ) {
	struct in_addr addr;
	struct hostent *h;

	if( (inet_aton( host, &addr )) == 0 ) {
		if( ! (h = gethostbyname( host )) ) {
			perror(host);
			return 0;
		}
		memcpy( &addr, h->h_addr_list[0], sizeof(addr) );
	}
	return addr.s_addr;
}
