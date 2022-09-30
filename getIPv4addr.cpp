#include "getIPv4addr.h"
//

int getIPv4addr (const char * if_name, unsigned char* ip_addr) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");
        return -1;
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (ip_addr, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

    close(sockfd);

    return 0;
}