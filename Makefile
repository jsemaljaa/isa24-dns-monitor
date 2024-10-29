# Makefile for dns-monitor

CC = g++
CFLAGS = -Wall -Wextra -pedantic -g -fsanitize=address
TARGET = dns-monitor

# files
SRCFILES = $(wildcard src/*.cpp)

all: $(TARGET)

# $(CC) $(CFLAGS) $^ -o $@ -I"C:\Program Files\WinPcapDev\Include" -I. -lpcap

$(TARGET): $(SRCFILES)
	$(CC) $(CFLAGS) $^ -o $@ -I. -lpcap

clean:
	rm -f dns-monitor *.o