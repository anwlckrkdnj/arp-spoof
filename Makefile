LDLIBS=-lpcap -lpthread

all: arp-spoof

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o attackerinfo.o arputility.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
