# Makefile

CC = g++
CFLAGS = -Wall -Wextra -pedantic

all: dns-monitor

dns-monitor: dns-monitor.o parameters.o
	$(CC) $(CFLAGS) -o dns-monitor dns-monitor.o parameters.o

dns-monitor.o: dns-monitor.cpp dns-monitor.h
	$(CC) $(CFLAGS) -c dns-monitor.cpp

parameters.o: parameters.cpp parameters.h
	$(CC) $(CFLAGS) -c parameters.cpp

clean:
	rm -f dns-monitor *.o