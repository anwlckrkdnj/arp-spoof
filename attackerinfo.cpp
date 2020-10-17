#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "mac.h"
#include "ip.h"

// https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
bool getAtkMac(Mac* attacker_mac) {
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) /* handle error*/
                return false;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) /* handle error */
                return false;

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		}
		else /* handle error */
                	return false;
    	}

	if (success)
	       	memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, sizeof(Mac));
	else
		return false;

	return true;
}

// https://technote.kr/176
bool getAtkIp(Ip* attacker_ip){
	struct ifreq ifr;
	int s;
 
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ);
 
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
        	return false;
	else
		memcpy(attacker_ip, ifr.ifr_addr.sa_data + 2, sizeof(Ip));
	close(s);

	return true;
}
