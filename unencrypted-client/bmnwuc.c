#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

const char myh[] = "zentop";

#define PACKETSIZE 1500
#define INTERVAL 2
#define UID 6969

void printusage()
{
	printf("Usage: {4|6} IP_TO_TALK_TO PORT_TO_SEND_TO\n");
	return;
}

int main(int argc, char *argv[])
{
	char mode;
	union
	{
		uint32_t ip4;
		__int128 ip6;
	} ip;
	uint16_t port;
	int sock;
	struct sockaddr_storage sender;
	int retval;

	if (setuid(UID))
	{
		printf("failed to setuid\n");
		return 1;
	}
	if (argc!=4)
	{
		printusage();
		return 1;
	}

	mode = *argv[1];
	port = atoi(argv[3]);

	switch (mode)
	{
	case '4':
		printf("ipv4 mode\n");
		if (!inet_pton(AF_INET, argv[2], &ip.ip4))
		{
			printf("Failed to parse ipv4 address\n");
			return 1;
		}
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock == -1)
		{
			printf("failed to socket()\n");
			return 1;
		}
		memset(&sender, 0, sizeof(sender));
		((struct sockaddr_in*)&sender)->sin_family = AF_INET;
		((struct sockaddr_in*)&sender)->sin_addr.s_addr = ip.ip4;
		#ifdef __ORDER_LITTLE_ENDIAN__
		((struct sockaddr_in*)&sender)->sin_port = __builtin_bswap16(port);
		#else
		((struct sockaddr_in*)&sender)->sin_port = port;
		#endif
		break;
	case '6':
		printf("ipv6 mode\n");
		if (!inet_pton(AF_INET6, argv[2], &ip.ip6))
		{
			printf("Failed to parse ipv6 address\n");
			return 1;
		}
		sock = socket(AF_INET6, SOCK_DGRAM, 0);
		if (sock == -1)
		{
			printf("failed to socket()\n");
			return 1;
		}
		memset(&sender, 0, sizeof(sender));
		((struct sockaddr_in6*)&sender)->sin6_family = AF_INET6;
		//((struct sockaddr_in6*)&sender)->sin_addr.s_addr = ip.ip6;
		__builtin_memcpy(((struct sockaddr_in6*)&sender)->sin6_addr.s6_addr, &ip.ip6, sizeof(ip.ip6));
		#ifdef __ORDER_LITTLE_ENDIAN__
		((struct sockaddr_in6*)&sender)->sin6_port = __builtin_bswap16(port);
		#else
		((struct sockaddr_in6*)&sender)->sin6_port = port;
		#endif
		break;
	default:
		printusage();
		return 1;
	}

	if (connect(sock, (struct sockaddr *) &sender, sizeof(struct sockaddr_storage)) == -1)
	{
		printf("connect() failure\n");
		return 1;
	}



	while (1)
	{
		sleep(INTERVAL);
		send(sock, myh, strlen(myh), 0);//, (struct sockaddr*) &sender, sizeof(sender));
		printf("sent packet\n");
		write (1, myh, strlen(myh));
	}
	return 0;
}
