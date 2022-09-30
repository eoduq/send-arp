LDLIBS=-lpcap

all: send-arp-test


main.o: mac.h ip.h ethhdr.h arphdr.h getMacaddr.h getIPv4addr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

getMacaddr.o : getMacaddr.h getMacaddr.cpp

getIPv4addr.o : getIPv4addr.h getIPv4addr.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o getMacaddr.o getIPv4addr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
