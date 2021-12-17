#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <errno.h>

const char myh[] = "zentop";

#define UID 6969
#define SERVERPUBKEY "server.pem"
#define PRIVKEY "client.key"
#define PUBKEY "client.pem"
#define PACKETSIZE 1500
#define INTERVAL 2
#define MTUMIN 400

#define LOOPCHECK(retval, cmd) do { retval = cmd;} while (retval == GNUTLS_E_AGAIN || retval == GNUTLS_E_INTERRUPTED)

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
	gnutls_session_t session;
	static gnutls_priority_t pcache;
	unsigned mtu;
	static gnutls_certificate_credentials_t x509cred;
	int retval;

	if (setuid(UID))
	{
		printf("failed to setuid\n");
		return 1;
	}
	mtu = PACKETSIZE;
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

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&x509cred);

	gnutls_certificate_set_x509_trust_file(x509cred, SERVERPUBKEY, GNUTLS_X509_FMT_PEM);

	if (gnutls_certificate_set_x509_key_file(x509cred, PUBKEY, PRIVKEY, GNUTLS_X509_FMT_PEM) < 0)
	{
		printf("cert files fucked up\n");
		return 1;
	}

	char *errorpos;
	//retval = gnutls_priority_init2(&pcache, "NONE:+VERS-DTLS1.2:+AES-256-GCM:%SERVER_PRECEDENCE", &errorpos, 0);
	//retval = gnutls_priority_init2(&pcache, "NONE:+VERS-DTLS1.2:+SHA384:+ECDHE-RSA:+DHE-RSA:+AES-256-GCM:+SIGN-RSA-SHA512:+CTYPE-X509:+COMP-NULL", &errorpos, 0);
	retval = gnutls_priority_init2(&pcache, NULL, NULL, 0);
	if (retval != GNUTLS_E_SUCCESS)
	{
		printf("bad\n");
		//printf("bad priorities \"%s\"\n", errorpos);
		return 1;
	}

	gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
	gnutls_priority_set(session, pcache);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509cred);
	gnutls_session_set_verify_cert(session, NULL, 0);

	gnutls_transport_set_int(session, sock);
	gnutls_dtls_set_mtu(session, mtu);

	while (1)
	{
		sleep(INTERVAL);
		gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
		gnutls_priority_set(session, pcache);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509cred);
		gnutls_session_set_verify_cert(session, NULL, 0);
		
		gnutls_transport_set_int(session, sock);
		gnutls_dtls_set_mtu(session, mtu);
		mtu = PACKETSIZE;
		do
		{
			retval = gnutls_handshake(session);
			if (retval == GNUTLS_E_LARGE_PACKET)
			{
				if (mtu!=MTUMIN)
				{
					mtu = mtu-100;
					gnutls_dtls_set_mtu(session, mtu);
				}
				retval = GNUTLS_E_AGAIN;
			}
		}
		while (retval == GNUTLS_E_INTERRUPTED || retval == GNUTLS_E_AGAIN);
		if (retval < 0)
		{
			#ifdef DEBUG
			printf("error in handshake with server %s\n", gnutls_strerror(retval));
			#endif
			gnutls_deinit(session);
			continue;
		}

		#ifdef DEBUG
		char *description;
		description = gnutls_session_get_desc(session);
		printf("Session info: \"%s\"\n",description);
		gnutls_free(description);
		#endif

		do
		{
			retval = gnutls_record_send(session, myh, sizeof(myh)-1);//, &sequence);
			if (retval == GNUTLS_E_LARGE_PACKET)
			{
				if (mtu!=MTUMIN)
				{
					mtu = mtu-100;
					gnutls_dtls_set_mtu(session, mtu);
				}
				retval = GNUTLS_E_AGAIN;
			}
		}
		while (retval == GNUTLS_E_INTERRUPTED || retval == GNUTLS_E_AGAIN);

		do
		{
			retval = gnutls_bye(session, GNUTLS_SHUT_WR);
			if (retval == GNUTLS_E_LARGE_PACKET)
			{
				if (mtu!=MTUMIN)
				{
					mtu = mtu-100;
					gnutls_dtls_set_mtu(session, mtu);
				}
				retval = GNUTLS_E_AGAIN;
			}
		}
		while (retval == GNUTLS_E_INTERRUPTED || retval == GNUTLS_E_AGAIN);
		//sendto(sock, myh, strlen(myh), 0, (struct sockaddr*) &sender, sizeof(sender));
		printf("sent packet\n");
		write (1, myh, strlen(myh));
		gnutls_deinit(session);
	}
	return 0;
}
