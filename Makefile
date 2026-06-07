CC = gcc
CFLAGS = -Wall -Wextra -g
TARGET = resolver
SRCS = src/main.c src/dns.c src/net.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)