#include <stdint.h>

static inline uint16be_t ip_checksum(uint16_t *ptr, int len)
{
	int sum = 0;
	uint16be_t answer = 0;
	uint16_t *w = ptr;
	int nleft = len;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}
