#include "getMacaddr.h"

int getMacaddr(const char* if_name, uint8_t* mac_addr){
    struct ifreq ifr;
    int sockfd, ret;
    printf("Interface: %s\n",if_name);
    
    //open network interface socket
    sockfd=socket(AF_INET,SOCK_DGRAM,0);//ipv4,udp?
    if(sockfd<0){
        printf("Fail to get interface MAC address-socket() failed\n");
        return -1;
    }

    //check mac address
    if(IFNAMSIZ<strlen(if_name)){
        printf("Fail to get interface MAC address-interace name too long\n");
        return -1;
    }
    strncpy(ifr.ifr_name,if_name,IFNAMSIZ);
    ret=ioctl(sockfd,SIOCGIFHWADDR,&ifr);
    if(ret<0){
        printf("Fail to get interface MAC address-ioctl(SIOCSIFHADDR) failed\n");
        return -1;
    }
    memcpy(mac_addr,ifr.ifr_hwaddr.sa_data,MAC_LEN);

    //close network interface socket
    close(sockfd);
    
   

    return 0;



    
}