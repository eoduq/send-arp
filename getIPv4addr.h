//get ipv4 address
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#define IP_LEN 4

int getIPv4addr (const char* if_name, unsigned char* ip_addr);