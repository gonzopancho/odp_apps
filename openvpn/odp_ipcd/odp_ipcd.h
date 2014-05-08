#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>

extern ssize_t odp_ipc_app_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
extern ssize_t odp_ipc_app_recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen ODP_UNUSED);
extern int odp_ipc_app_poll(void);

enum {
	IPC_ODP_PACKET_NONE,
	IPC_ODP_PACKET_IN,
	IPC_ODP_PACKET_OUT,
};

/* shm */
struct odp_ipc_shm {
	unsigned char *in_p; //incomming packet
	unsigned int *in_len;
	unsigned char *out_p;
	unsigned int *out_len;
	unsigned long *magic_odp;
	unsigned long *magic_app;
};
