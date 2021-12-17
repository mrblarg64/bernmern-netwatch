#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#ifdef FCGI
#include <fcgi_config.h>
#include <fcgiapp.h>
#include <sys/mman.h>

#define HTMLSTATUSA "/var/www/localhost/statusa.html"
#define HTMLSTATUSB "/var/www/localhost/statusb.html"
#endif

#define EXPECTEDFILE "expected.conf"
#define CLIENTPUBKEY "client.pem"
#define PRIVKEY "server.key"
#define PUBKEY "server.pem"

#define MAXHOSTNAMESIZE 100
#define PACKETSIZE 1500
#define MTUMIN 400
#define MAXIPSTRLEN 60
#define MAXPORTSTRLEN 5
//2021-12-12 19:28:28
//12345678901234567890
#define MAXDATESTRLEN 20
//#define SPACEBYTELEN 1
#define CHECKINTERVAL 10
#define PACKETTIMEOUT 5

//#define LOOPCHECK(retval, cmd) do { retval = cmd;} while (retval == GNUTLS_E_AGAIN || retval == GNUTLS_E_INTERRUPTED)

typedef struct
{
	gnutls_session_t session;
	int fd;
	struct sockaddr_storage *cli_addr;
	socklen_t cli_addr_size;
} priv_data_st;

#define HOST_STATE_UNEXPECTED 0
#define HOST_STATE_EXPECTED 1
#define HOST_STATE_DEAD_EXPECTED 2

struct hostnode
{
	char state;
	time_t lastmsg;
	struct sockaddr_storage cliaddr;
	char ipstring[MAXIPSTRLEN];
	struct hostnode *next;
	struct hostnode *prev;
	unsigned namelen;
	char name[];
};

struct clientnode
{
	pthread_t t;
	struct clientnode *next;
	struct clientnode *prev;
	gnutls_session_t session;
	struct sockaddr_storage cliaddr;
	socklen_t cliaddrlen;
	pthread_cond_t newpackets;
	pthread_mutex_t packetqlock;
	struct packetqnode *packetq;
	struct packetqnode *packetqend;
};

struct packetqnode
{
	struct packetqnode *next;
	uint32_t size;
	char packet[PACKETSIZE];
};

//GLOBALS
int sock;
int unencryptedsock;
struct hostnode *alive=NULL;
pthread_mutex_t alivehostslock;
pthread_t checkerthread;
static gnutls_certificate_credentials_t x509cred;
static gnutls_priority_t pcache;
gnutls_datum_t cookiekey;
struct clientnode *clients=NULL;
pthread_mutex_t clientslock;
#ifdef FCGI
pthread_t fcgithread;
#endif
pthread_t unencryptedthread;


/* unsigned long pthreadroot; */
/* static inline void bthread_mutex_lock(pthread_mutex_t *lock) */
/* { */
/* 	pthread_t pt; */
/* 	pthread_mutex_lock(lock); */
/* 	pt = pthread_self(); */
/* 	if (pt!=pthreadroot&&pt!=checkerthread) */
/* 	{ */
/* 		if (lock==&clientslock) */
/* 		{ */
/* 			printf("lock clients\n"); */
/* 		} */
/* 		else if (lock==&alivehostslock) */
/* 		{ */
/* 			printf("lock alive\n"); */
/* 		} */
/* 		else */
/* 		{ */
/* 			printf("lock %p\n",lock); */
/* 		} */
/* 	} */
/* 	return; */
/* } */

/* static inline void bthread_mutex_unlock(pthread_mutex_t *lock) */
/* { */
/* 	pthread_t pt; */
/* 	pthread_mutex_unlock(lock); */
/* 	pt = pthread_self(); */
/* 	if (pt!=pthreadroot&&pt!=checkerthread) */
/* 	{ */
/* 		if (lock==&clientslock) */
/* 		{ */
/* 			printf("unlock clients\n"); */
/* 		} */
/* 		else if (lock==&alivehostslock) */
/* 		{ */
/* 			printf("unlock alive\n"); */
/* 		} */
/* 		else */
/* 		{ */
/* 			printf("unlock %p\n",lock); */
/* 		} */
/* 	} */
/* 	return; */
/* } */

static inline void getipstring(struct sockaddr_storage *s, char *ipstring, uint16_t *port)
{
	//get ip string
	if (s->ss_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in*)s)->sin_addr.s_addr, ipstring, MAXIPSTRLEN);
		#ifdef __ORDER_LITTLE_ENDIAN__
	        *port = __builtin_bswap16(((struct sockaddr_in*)s)->sin_port);
		#else
	        *port = ((struct sockaddr_in*)s)->sin_port;
		#endif
	}
	else
	{
		inet_ntop(AF_INET6, &((struct sockaddr_in6*)s)->sin6_addr.s6_addr, ipstring, MAXIPSTRLEN);
		#ifdef __ORDER_LITTLE_ENDIAN__
	        *port = __builtin_bswap16(((struct sockaddr_in6*)s)->sin6_port);
		#else
		*port = ((struct sockaddr_in6*)s)->sin6_port;
		#endif
	}
	return;
}

static inline void hostnodeadd(struct hostnode *addme)
{
	if (alive)
	{
		addme->next = alive;
		addme->prev = alive->prev;
		alive->prev->next = addme;
		alive->prev = addme;
	}
	else
	{
		alive = addme;
		addme->next = addme;
		addme->prev = addme;
	}
	return;
}

static inline void hostnoderemove(struct hostnode *rmme)
{
	if (rmme->next == rmme)
	{
		alive = NULL;
	}
	else
	{
		rmme->next->prev = rmme->prev;
		rmme->prev->next = rmme->next;
		if (alive == rmme)
		{
			alive = alive->next;
		}
	}
	return;
}

static inline struct hostnode *hostnodefind(char *name, unsigned namelen)
{
	struct hostnode *curhost;

	if (alive)
	{
		curhost = alive;
		do
		{
			//if I treat hostnames as arbitrary byte sequences
			//it is impossible to attack with string escapes (like null terminators)
			if (namelen == curhost->namelen)//(! __builtin_strcmp(name, curhost->name))
			{
				if (! __builtin_memcmp(name, curhost->name, namelen))
				{
					//found
					return curhost;
				}
			}
			curhost = curhost->next;
		}
		while (curhost != alive);
	}
	return NULL;
}

static inline void addpacket(struct clientnode *c, struct packetqnode *p) 
{
	if (c->packetq)
	{
		c->packetqend->next = p;
	}
	else
	{
		c->packetq = p;
	}
	c->packetqend = p;
	return;
}

static inline void rmpacket(struct clientnode *c) 
{
	struct packetqnode *rmme;

	rmme = c->packetq;
	c->packetq = rmme->next;
	free(rmme);
	return;
}

static inline void clientnodeadd(struct clientnode *addme)
{
	if (clients)
	{
		addme->next = clients;
		addme->prev = clients->prev;
		clients->prev->next = addme;
		clients->prev = addme;
	}
	else
	{
		clients = addme;
		addme->next = addme;
		addme->prev = addme;
	}
	return;
}

static inline void clientnoderemove(struct clientnode *rmme)
{
	pthread_mutex_lock(&rmme->packetqlock);
	while (rmme->packetq)
	{
		rmpacket(rmme);
	}
	if (rmme->next == rmme)
	{
		clients = NULL;
	}
	else
	{
		rmme->next->prev = rmme->prev;
		rmme->prev->next = rmme->next;
		if (clients == rmme)
		{
			clients = clients->next;
		}
	}
	pthread_mutex_unlock(&rmme->packetqlock);
	return;
}

static inline struct clientnode *clientnodefind(struct sockaddr_storage *cid, socklen_t cidlen)
{
	struct clientnode *curclient;

	if (clients)
	{
		curclient = clients;
		do
		{
			if (cidlen == curclient->cliaddrlen)//(! __builtin_strcmp(name, curhost->name))
			{
				if (! __builtin_memcmp(cid, &curclient->cliaddr, cidlen))
				{
					//found
					return curclient;
				}
			}
			curclient = curclient->next;
		}
		while (curclient != clients);
	}
	return NULL;
}

static inline void corethreadcleanup(struct clientnode *curclient)
{
	pthread_mutex_lock(&clientslock);
	clientnoderemove(curclient);
	pthread_mutex_unlock(&clientslock);
	pthread_cond_destroy(&curclient->newpackets);
	pthread_mutex_destroy(&curclient->packetqlock);
	free(curclient);
	return;
}

static inline void threadcleanup(struct clientnode *curclient)
{
	gnutls_deinit(curclient->session);
	corethreadcleanup(curclient);
	return;
}

static inline void initexpectedhosts(char *expectedhostfile)
{
	int fd;
	struct stat ehfstat;
	char *fileinheap;
	char *curtok;
	struct hostnode *hn;

	fd = open(expectedhostfile, O_RDONLY);
	fstat(fd, &ehfstat);
	fileinheap = malloc(ehfstat.st_size);
	(void)!read(fd, fileinheap, ehfstat.st_size);
	close(fd);
	curtok = strtok(fileinheap, "\n");
	while (curtok)
	{
		hn = malloc(sizeof(struct hostnode)+((1+__builtin_strlen(curtok))*sizeof(char)));
		__builtin_memset(hn, 0, sizeof(struct hostnode));
		hn->state = HOST_STATE_EXPECTED;
		__builtin_strcpy(hn->name, curtok);
		hostnodeadd(hn);
		curtok = strtok(NULL, "\n");
	}
}

void printusage()
{
	printf("Usage: {4|6} IP_TO_LISTEN_ON PORT_TO_LISTEN_ON [UNENCRYPTED_PORT_TO_LISTEN_ON]\n");
	return;
}

void *unencryptedfunc(void *args)
{
	struct sockaddr_storage curclient;
	socklen_t curclientlen;
	unsigned psize;
	char packet[PACKETSIZE];
	struct hostnode *hn;
	time_t curtime;
	struct tm *curtm;
	char clientip[MAXIPSTRLEN];
	uint16_t clientport;
	
	while (1)
	{
		curclientlen = sizeof(struct sockaddr_storage);
		psize = recvfrom(unencryptedsock, packet, PACKETSIZE, 0, (struct sockaddr*) &curclient, &curclientlen);
		if (!psize)
		{
			continue;
		}
		curtime = time(NULL);
		curtm = localtime(&curtime);
		packet[psize] = 0;
		getipstring(&curclient, clientip, &clientport);
		pthread_mutex_lock(&alivehostslock);
	        hn = hostnodefind(packet, psize);
		if (hn)
		{
			if (hn->state)
			{
				hn->state = HOST_STATE_EXPECTED;
			}
			hn->lastmsg = curtime;
			hn->cliaddr = curclient;
			__builtin_strcpy(hn->ipstring, clientip);
			#ifdef DEBUG
			printf("already\n");
			#endif
		}
		else
		{
			hn = malloc(sizeof(struct hostnode)+psize+sizeof(char));
			hn->state = HOST_STATE_UNEXPECTED;
			hn->lastmsg = curtime;
			hn->cliaddr = curclient;
			hn->namelen = psize;
			__builtin_memcpy(hn->name, packet, psize+1);
			__builtin_strcpy(hn->ipstring, clientip);
			hostnodeadd(hn);
			#ifdef DEBUG
			printf("add\n");
			#endif
		}
		pthread_mutex_unlock(&alivehostslock);
		printf("%u-%02u-%02u %02u:%02u:%02u %s %s %hu\n", curtm->tm_year+1900, curtm->tm_mon+1, curtm->tm_mday, curtm->tm_hour, curtm->tm_min, curtm->tm_sec, packet, clientip, clientport);
	}
	return NULL;
}

#ifdef FCGI
void *fcgifunc(void *args)
{
	int fd;
	char *statusa;
	struct stat statusastat;
	char *statusb;
	struct stat statusbstat;
	FCGX_Request req;
	struct hostnode *curhost;

	fd = open(HTMLSTATUSA, O_RDONLY);
	fstat(fd, &statusastat);
	statusa = mmap(NULL, statusastat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	fd = open(HTMLSTATUSB, O_RDONLY);
	fstat(fd, &statusbstat);
	statusb = mmap(NULL, statusbstat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	FCGX_Init();

	FCGX_InitRequest(&req, 0, 0);
	while (1)
	{
		FCGX_Accept_r(&req);

		FCGX_FPrintF(req.out,"Content-type: text/html\r\n\r\n");
		FCGX_PutStr(statusa, statusastat.st_size, req.out);

		//draw table here
		pthread_mutex_lock(&alivehostslock);
		if (alive)
		{
			curhost = alive;
			do
			{
				if (curhost->state == HOST_STATE_DEAD_EXPECTED)
				{
					FCGX_FPrintF(req.out,"<tr><td>%s</td><td>%s</td><td style=\"background-color: red\">%s</td></tr>", curhost->name, curhost->ipstring, "Offline");
				}
				else
				{
					FCGX_FPrintF(req.out,"<tr><td>%s</td><td>%s</td><td style=\"background-color: green\">%s</td></tr>", curhost->name, curhost->ipstring, "Online");
				}
				curhost = curhost->next;
			}
			while (curhost != alive);
		}
		pthread_mutex_unlock(&alivehostslock);

		FCGX_PutStr(statusb, statusbstat.st_size, req.out);
		FCGX_Finish_r(&req);
	}
	return NULL;
}
#endif

void *checker(void *args)
{
	struct hostnode *curhost;
	time_t curtime;

	while (1)
	{
		pthread_mutex_lock(&alivehostslock);
		curhost = alive;
		if (curhost)
		{
			curtime = time(NULL);
			do
			{
				if ((curtime - curhost->lastmsg)>CHECKINTERVAL)
				{
					switch (curhost->state)
					{
					case HOST_STATE_UNEXPECTED:
						hostnoderemove(curhost);
						//memory leak lol xddddddddddddddd FIXME TODO
						#ifdef DEBUG
						printf("%s died\n", curhost->name);
						#endif
						break;
					case HOST_STATE_EXPECTED:
						curhost->state = HOST_STATE_DEAD_EXPECTED;
						break;
					default:
					}
				}
				curhost = curhost->next;
			}
			while (alive&&(curhost!=alive));
		}
		pthread_mutex_unlock(&alivehostslock);
		sleep(CHECKINTERVAL);
	}
	return NULL;
}

static ssize_t sendfunc(gnutls_transport_ptr_t cli, const void *data, size_t size)
{
	struct clientnode *curclient;
	int retval;
	
	curclient = cli;
	retval = sendto(sock, data, size, 0, (struct sockaddr*) &curclient->cliaddr, sizeof(struct sockaddr_storage));
	return retval;
}

static ssize_t recvfunc(gnutls_transport_ptr_t cli, void *data, size_t size)
{
	struct clientnode *curclient;
	curclient = cli;
	unsigned retval;

	pthread_mutex_lock(&curclient->packetqlock);
	while (!curclient->packetq)
	{
		pthread_cond_wait(&curclient->newpackets,&curclient->packetqlock);
		//pthread_mutex_unlock(&curclient->packetqlock);
		//gnutls_transport_set_errno(curclient->session, EAGAIN);
		//return -1;
	}
	__builtin_memcpy(data, curclient->packetq->packet, curclient->packetq->size);
	retval = curclient->packetq->size;
	rmpacket(curclient);
	pthread_mutex_unlock(&curclient->packetqlock);
	return retval;
	//gnutls_transport_set_errno(priv->session, EAGAIN);

	//return -1;
}


//positive = data available
//0 = timeoute
//negative = error
static int recvtimeoutfunc(gnutls_transport_ptr_t cli, unsigned int ms)
{
	//return 1;
	struct clientnode *curclient;
	curclient = cli;
	struct timespec ts;
	struct timeval now;
	unsigned retval;

	pthread_mutex_lock(&curclient->packetqlock);
	while (!curclient->packetq)
	{
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += PACKETTIMEOUT;
		if (ETIMEDOUT == pthread_cond_timedwait(&curclient->newpackets,&curclient->packetqlock, &ts))
		{
			pthread_mutex_unlock(&curclient->packetqlock);
			return 0;
		}
	}
	pthread_mutex_unlock(&curclient->packetqlock);
	return 1;
}

void *clienthandler(void *args)
{
	struct clientnode *curclient;
	char clientip[MAXIPSTRLEN];
	char packet[PACKETSIZE];
	uint16_t clientport;
	gnutls_dtls_prestate_st prestate;
	unsigned mtu;
	int retval;
	uint64_t sequence;
	struct hostnode *hn;
	time_t curtime;
	struct tm *curtm;
	struct timespec ts;

	curclient = args;
	mtu = PACKETSIZE;

	//get ip string
	getipstring(&curclient->cliaddr, clientip, &clientport);

	__builtin_memset(&prestate, 0, sizeof(prestate));
	pthread_mutex_lock(&curclient->packetqlock);
	while (1)
	{
		while (!curclient->packetq)
		{
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += PACKETTIMEOUT;
			if (ETIMEDOUT == pthread_cond_timedwait(&curclient->newpackets,&curclient->packetqlock, &ts))
			{
				pthread_mutex_unlock(&curclient->packetqlock);
				corethreadcleanup(curclient);
				#ifdef DEBUG
				write(1,"client died\n",12);
				#endif
				return NULL;
			}
		}
			
		if (gnutls_dtls_cookie_verify(&cookiekey, &curclient->cliaddr, sizeof(struct sockaddr_storage), curclient->packetq->packet, curclient->packetq->size, &prestate) < 0)
		{
			//cookie not valid
			//__builtin_memset(&s, 0, sizeof(s));
			//s.fd = sock;
			//s.cli_addr = (void *) &curclient;
			//s.cli_addr_size = sizeof(curclient);
			#ifdef DEBUG
			printf("Sending hello verify request to %s\n", clientip);
			#endif
			gnutls_dtls_cookie_send(&cookiekey, &curclient->cliaddr, sizeof(struct sockaddr_storage), &prestate, (gnutls_transport_ptr_t) curclient, &sendfunc);
			//discard data
			rmpacket(curclient);
			//example sleeps here for some reason
			//usleep(100);
			continue;
		}
		break;
	}
	pthread_mutex_unlock(&curclient->packetqlock);
	#ifdef DEBUG
	printf("Accepted connection from %s\n", clientip);
	#endif
	gnutls_init(&curclient->session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
	gnutls_priority_set(curclient->session, pcache);
	gnutls_credentials_set(curclient->session, GNUTLS_CRD_CERTIFICATE, x509cred);
	gnutls_dtls_prestate_set(curclient->session, &prestate);
	gnutls_dtls_set_mtu(curclient->session, mtu);

	//priv.session = session;
	//priv.fd = sock;
	//priv.cli_addr = &curclient;
	//priv.cli_addr_size = sizeof(curclient);

	gnutls_transport_set_ptr(curclient->session, curclient);
	gnutls_transport_set_push_function(curclient->session, sendfunc);
	gnutls_transport_set_pull_function(curclient->session, recvfunc);
	gnutls_transport_set_pull_timeout_function(curclient->session, recvtimeoutfunc);
	gnutls_handshake_set_timeout(curclient->session, PACKETTIMEOUT * 1000);

	//request client certificate
	gnutls_certificate_server_set_request(curclient->session, GNUTLS_CERT_REQUIRE);

	//LOOPCHECK(retval, gnutls_handshake(curclient->session));
	do
	{
		retval = gnutls_handshake(curclient->session);
		if (retval == GNUTLS_E_LARGE_PACKET)
		{
			if (mtu!=MTUMIN)
			{
				mtu = mtu-100;
				gnutls_dtls_set_mtu(curclient->session, mtu);
			}
			retval = GNUTLS_E_AGAIN;
		}
	}
	while (retval == GNUTLS_E_INTERRUPTED || retval == GNUTLS_E_AGAIN);

	if (retval < 0)
	{
		#ifdef DEBUG
		printf("error in handshake with %s %s\n", clientip, gnutls_strerror(retval));
		#endif
		threadcleanup(curclient);
		return NULL;
	}
	#ifdef DEBUG
	printf("handshake ok\n");
	#endif

	//LOOPCHECK(retval, gnutls_record_recv_seq(curclient->session, packet, PACKETSIZE, &sequence));
	do
	{
		retval = gnutls_record_recv_seq(curclient->session, packet, PACKETSIZE, (unsigned char *)&sequence);
		if (retval == GNUTLS_E_LARGE_PACKET)
		{
			if (mtu!=MTUMIN)
			{
				mtu = mtu-100;
				gnutls_dtls_set_mtu(curclient->session, mtu);
			}
			retval = GNUTLS_E_AGAIN;
		}
	}
	while (retval == GNUTLS_E_INTERRUPTED || retval == GNUTLS_E_AGAIN);
	if (retval < 0)
	{
		if (gnutls_error_is_fatal(retval) == 0)
		{
			#ifdef DEBUG
			printf("Warning: %s\n", gnutls_strerror(retval));
			#endif
		}
		#ifdef DEBUG
		printf("error in recv(): %s\n", gnutls_strerror(retval));
		#endif
		goto endthread;
	}
	if (retval == 0)
	{
		#ifdef DEBUG
		printf("EOF\n");
		#endif
		goto endthread;
	}
	//null terminator
	packet[retval]=0;
	curtime = time(NULL);
	curtm = localtime(&curtime);

	pthread_mutex_lock(&alivehostslock);
	hn = hostnodefind(packet, retval);
	if (hn)
	{
		if (hn->state)
		{
			hn->state = HOST_STATE_EXPECTED;
		}
		hn->lastmsg = curtime;
		hn->cliaddr = curclient->cliaddr;;
		__builtin_strcpy(hn->ipstring, clientip);
		#ifdef DEBUG
		printf("already\n");
		#endif
	}
	else
	{
		hn = malloc(sizeof(struct hostnode)+retval+sizeof(char));
		hn->state = HOST_STATE_UNEXPECTED;
		hn->lastmsg = curtime;
		hn->cliaddr = curclient->cliaddr;
		hn->namelen = retval;
		__builtin_memcpy(hn->name, packet, retval+1);
		__builtin_strcpy(hn->ipstring, clientip);
		hostnodeadd(hn);
		#ifdef DEBUG
		printf("add\n");
		#endif
	}
	pthread_mutex_unlock(&alivehostslock);
	printf("%u-%02u-%02u %02u:%02u:%02u %s %s %hu\n", curtm->tm_year+1900, curtm->tm_mon+1, curtm->tm_mday, curtm->tm_hour, curtm->tm_min, curtm->tm_sec, packet, clientip, clientport);

endthread:
	//LOOPCHECK(retval, gnutls_bye(curclient->session, GNUTLS_SHUT_WR));
	do
	{
		retval = gnutls_bye(curclient->session, GNUTLS_SHUT_WR);
		if (retval == GNUTLS_E_LARGE_PACKET)
		{
			if (mtu!=MTUMIN)
			{
				mtu = mtu-100;
				gnutls_dtls_set_mtu(curclient->session, mtu);
			}
			retval = GNUTLS_E_AGAIN;
		}
	}
	while (retval == GNUTLS_E_INTERRUPTED || retval == GNUTLS_E_AGAIN);
        threadcleanup(curclient);
	return NULL;
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
	uint16_t unencryptedport=0;
	struct sockaddr_storage listener;
	struct sockaddr_storage unencryptedlistener;
	struct sockaddr_storage curclient;
	socklen_t curclientlen;
	struct clientnode *curclientnode;
	//date null=space + hostnamesize + space + IP null=space + port null=null
	char logstring[MAXDATESTRLEN + MAXHOSTNAMESIZE + 1 + MAXIPSTRLEN + MAXPORTSTRLEN];
	priv_data_st priv;
	int retval;
	unsigned mtu;
	struct packetqnode *curpacket;

	if (argc!=4&&argc!=5)
	{
		printusage();
		return 1;
	}

	mode = *argv[1];
	port = atoi(argv[3]);
	if (argc==5)
	{
		unencryptedport = atoi(argv[4]);
	}

	switch (mode)
	{
	case '4':
		#ifdef DEBUG
		printf("ipv4 mode\n");
		#endif
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
		__builtin_memset(&listener, 0, sizeof(listener));
		((struct sockaddr_in*)&listener)->sin_family = AF_INET;
		((struct sockaddr_in*)&listener)->sin_addr.s_addr = ip.ip4;
		#ifdef __ORDER_LITTLE_ENDIAN__
		((struct sockaddr_in*)&listener)->sin_port = __builtin_bswap16(port);
		#else
		((struct sockaddr_in*)&listener)->sin_port = port;
		#endif
		if (argc==5)
		{
			unencryptedsock = socket(AF_INET, SOCK_DGRAM, 0);
			if (unencryptedsock == -1)
			{
				printf("failed to socket()\n");
				return 1;
			}
			__builtin_memset(&unencryptedlistener, 0, sizeof(unencryptedlistener));
			((struct sockaddr_in*)&unencryptedlistener)->sin_family = AF_INET;
			((struct sockaddr_in*)&unencryptedlistener)->sin_addr.s_addr = ip.ip4;
			#ifdef __ORDER_LITTLE_ENDIAN__
			((struct sockaddr_in*)&unencryptedlistener)->sin_port = __builtin_bswap16(unencryptedport);
			#else
			((struct sockaddr_in*)&unencryptedlistener)->sin_port = port;
			#endif
		}
		break;
	case '6':
		#ifdef DEBUG
		printf("ipv6 mode\n");
		#endif
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
		__builtin_memset(&listener, 0, sizeof(listener));
		((struct sockaddr_in6*)&listener)->sin6_family = AF_INET6;
		//((struct sockaddr_in6*)&listener)->sin_addr.s_addr = ip.ip6;
		__builtin_memcpy(((struct sockaddr_in6*)&listener)->sin6_addr.s6_addr, &ip.ip6, sizeof(ip.ip6));
		#ifdef __ORDER_LITTLE_ENDIAN__
		((struct sockaddr_in6*)&listener)->sin6_port = __builtin_bswap16(port);
		#else
		((struct sockaddr_in6*)&listener)->sin6_port = unencryptedport;
		#endif
		if (argc==5)
		{
			unencryptedsock = socket(AF_INET6, SOCK_DGRAM, 0);
			if (unencryptedsock == -1)
			{
				printf("failed to socket()\n");
				return 1;
			}
			__builtin_memset(&unencryptedlistener, 0, sizeof(unencryptedlistener));
			((struct sockaddr_in6*)&unencryptedlistener)->sin6_family = AF_INET6;
			//((struct sockaddr_in6*)&listener)->sin_addr.s_addr = ip.ip6;
			__builtin_memcpy(((struct sockaddr_in6*)&unencryptedlistener)->sin6_addr.s6_addr, &ip.ip6, sizeof(ip.ip6));
			#ifdef __ORDER_LITTLE_ENDIAN__
			((struct sockaddr_in6*)&unencryptedlistener)->sin6_port = __builtin_bswap16(unencryptedport);
			#else
			((struct sockaddr_in6*)&unencryptedlistener)->sin6_port = unencryptedport;
			#endif
		}
		break;
	default:
		printusage();
		return 1;
	}

	#ifdef DEBUG
	printf("starting up gnutls...\n");
	#endif
	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509cred);
	//don't know what this does
	gnutls_certificate_set_x509_trust_file(x509cred, CLIENTPUBKEY, GNUTLS_X509_FMT_PEM);

	//gnutls_certificate_set_x509_crl_file(x509cred, CRLFILE, GNUTLS_X509_FMT_PEM);

	if (gnutls_certificate_set_x509_key_file(x509cred, PUBKEY, PRIVKEY, GNUTLS_X509_FMT_PEM) < 0)
	{
		printf("cert files bad\n");
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
	gnutls_key_generate(&cookiekey, GNUTLS_COOKIE_KEY_SIZE);

	printf("binding listener to port %hu\n",port);
	if (bind(sock, (struct sockaddr *) &listener, sizeof(struct sockaddr_storage)) == -1)
	{
		printf("bind failed!\n");
		return 1;
	}

	if (argc==5)
	{
		printf("binding unencryptedlistener to port %hu\n",unencryptedport);
		if (bind(unencryptedsock, (struct sockaddr *) &unencryptedlistener, sizeof(struct sockaddr_storage)) == -1)
		{
			printf("bind failed!\n");
			return 1;
		}
	}

	initexpectedhosts(EXPECTEDFILE);

	pthread_create(&checkerthread, NULL, checker, NULL);

	#ifdef FCGI
	pthread_create(&fcgithread, NULL, fcgifunc, NULL);
	#endif

	if (argc==5)
	{
		pthread_create(&unencryptedthread, NULL, unencryptedfunc, NULL);
	}

	while (1)
	{
		//sendto(sock, myh, strlen(myh), 0, (struct sockaddr*) &listener, sizeof(listener));
		curpacket = malloc(sizeof(struct packetqnode));
		curpacket->next = NULL;
	againnomalloc:
		curclientlen = sizeof(curclient);
		curpacket->size = recvfrom(sock, curpacket->packet, PACKETSIZE, 0, (struct sockaddr*) &curclient, &curclientlen);
		if (!curpacket->size)
		{
			goto againnomalloc;
		}
		pthread_mutex_lock(&clientslock);
		curclientnode = clientnodefind(&curclient, curclientlen);
	        if (!curclientnode)
		{
			#ifdef DEBUG
		        (void)!write(1, "new\n", 4);
			#endif
			curclientnode = malloc(sizeof(struct clientnode));
			curclientnode->cliaddrlen = curclientlen;
			curclientnode->packetq = curpacket;
			curclientnode->packetqend = curpacket;
			__builtin_memcpy(&curclientnode->cliaddr, &curclient, curclientlen);
			pthread_cond_init(&curclientnode->newpackets, NULL);
			pthread_mutex_init(&curclientnode->packetqlock, NULL);
			clientnodeadd(curclientnode);
			pthread_create(&curclientnode->t, NULL, clienthandler, curclientnode);
		}
		else
		{
			#ifdef DEBUG
			(void)!write(1, "old\n", 4);
			#endif
			pthread_mutex_lock(&curclientnode->packetqlock);
			addpacket(curclientnode, curpacket);
			pthread_mutex_unlock(&curclientnode->packetqlock);
			pthread_cond_signal(&curclientnode->newpackets);
		}
		pthread_mutex_unlock(&clientslock);
	}
	return 0;
}
