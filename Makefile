OBJS = icwtest.o checksums.o packets.o
SRCS = $(OBJS,.o=.c)
CFLAGS += -Wall -g
LDFLAGS += -lpcap
PROGNAME = icwtest

all: $(PROGNAME)

$(PROGNAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROGNAME) $(OBJS)

clean:
	rm -rf $(OBJS) $(PROGNAME)

