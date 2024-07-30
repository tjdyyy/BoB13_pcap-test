CC = gcc
CFLAGS = -Wall -Wextra
INCLUDES = -I/usr/local/include
LDFLAGS = -L/usr/local/lib
LIBS = -lpcap

all: pcap-test4

pcap-test4: pcap-test4.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o pcap-test4 pcap-test4.c $(LIBS)

clean:
	rm -f pcap-test4

