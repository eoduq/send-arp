#pragma once
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#define MAC_LEN 6

int getMacaddr(const char* if_name, uint8_t* mac_addr);