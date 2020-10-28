LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o arp.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
