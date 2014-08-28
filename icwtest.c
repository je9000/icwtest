/*
 * Copyright (c) 2012-2013, Yahoo! Inc All rights reserved.
 * Copyright (c) 2013-2014, John Eaglesham All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.  Redistributions
 *     in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or
 *     other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: John Eaglesham
 */

#define __USE_BSD

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <netdb.h>

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_tap.h>
#endif

#ifdef __linux
#define ETHERTYPE_IPV6 ETH_P_IPV6
#define __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <pcap.h>
#include <signal.h>
#include <sys/wait.h>
#include <getopt.h>
#include "packets.h"
#include "constants.h"
#include "checksums.h"


/*
 * XXX We don't close the pcap device on failure anywhere. The OS will do it
 * for us, but it's impolite.
 */

/* Globals */
pcap_t *pcap;
pid_t listener_pid;
int pfd[2];

#ifdef SIOCGIFHWADDR
char *get_interface_mac(char *interface)
{
    int fd;
    struct ifreq ifr;
    char *dest = malloc(MAC_ADDRESS_STRING_LENGTH + 1);

    if (dest == NULL) {
        return NULL;
    }

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return NULL;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return NULL;
    }
    close(fd);

    sprintf(dest, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned char) ifr.ifr_hwaddr.sa_data[0],
            (unsigned char) ifr.ifr_hwaddr.sa_data[1],
            (unsigned char) ifr.ifr_hwaddr.sa_data[2],
            (unsigned char) ifr.ifr_hwaddr.sa_data[3],
            (unsigned char) ifr.ifr_hwaddr.sa_data[4],
            (unsigned char) ifr.ifr_hwaddr.sa_data[5]
           );
    return dest;
}
#elif __FreeBSD__
char *get_interface_mac(char *interface)
{
    struct ifaddrs *ifap;
    char *dest = malloc(MAC_ADDRESS_STRING_LENGTH + 1);

    if (dest == NULL) {
        return NULL;
    }

    if (getifaddrs(&ifap) == 0) {
        struct ifaddrs *p;
        for (p = ifap; p; p = p->ifa_next) {
            if ((p->ifa_addr->sa_family == AF_LINK) && (strcmp(p->ifa_name, interface) == 0)) {
                struct sockaddr_dl *sdp = (struct sockaddr_dl *) p->ifa_addr;
                unsigned char *mac_ptr = (unsigned char *) sdp->sdl_data + sdp->sdl_nlen;
                sprintf(dest, "%02X:%02X:%02X:%02X:%02X:%02X",
                        mac_ptr[0],
                        mac_ptr[1],
                        mac_ptr[2],
                        mac_ptr[3],
                        mac_ptr[4],
                        mac_ptr[5]
                       );
                freeifaddrs(ifap);
                return dest;
            }
        }
        freeifaddrs(ifap);
    }
    return NULL;
}
#else
#error Do not know how to get MAC address on this platform.
#endif

void *malloc_check(int size)
{
    void *r = malloc(size);
    if (r == NULL) {
        err(1, "malloc");
    }
    return r;
}

void calc_checksum(void *iph, int protocol, int len)
{
    if (do_checksum(iph, protocol, len) != 1) {
        fprintf(
            stderr,
            "Warning: Failed to calculate checksum for protocol %i. This is probably a bug.\n",
            protocol
        );
    }
}

void packet_send(void *packet, int len)
{
    if (pcap_inject(pcap, packet, len) != len) {
        errx(1, "pcap_inject failed: %s", pcap_geterr(pcap));
    }
}

/* Returns the layer 4 header if we found one. */
char *find_packet_header(char *packet_data, int len, unsigned short wanted_type)
{
    struct ip *iph;
    size_t s = SIZEOF_ETHER;
    struct ether_header *ethh = (struct ether_header *) packet_data;
    int found_type = -1;
    char *found_header = NULL;

    if (len < SIZEOF_ETHER) {
        printf("Ethernet Frame: \nToo short\n");
        return NULL;
    }
    if (ntohs(ethh->ether_type) == ETHERTYPE_IP) {
        iph = (struct ip *)(packet_data + SIZEOF_ETHER);
        s += (iph->ip_hl * 4);
        if (s > len) {
            printf("IPv4 Header:\n Too short\n");
            return NULL;
        }
        if (wanted_type == IPPROTO_IP) {
            return (char *) iph;
        }
        if ((ntohs(iph->ip_off) & 0x1FFF) || ntohs(iph->ip_off) & (1 << IP_FLAGS_OFFSET)) {
            printf("[ Not parsing data fragment. ]\n");
            found_type = -1;
            found_header = NULL;
        } else if (iph->ip_p == IPPROTO_TCP) {
            if (s + SIZEOF_TCP > len) {
                printf("TCP Header:\n Too short\n");
                return NULL;
            }
            found_type = IPPROTO_TCP;
            found_header = packet_data + s;
        } else if (iph->ip_p == IPPROTO_ICMP) {
            if (s + SIZEOF_PING > len) {
                printf("UDP Header:\n Too short\n");
                return NULL;
            }
            found_type = IPPROTO_ICMP;
            found_header = packet_data + s;
        } else {
            printf("Unsupported protocol:\n IP Protocol %i\n", iph->ip_p);
            return NULL;
        }

    } else {
        printf("Unsupported Protocol:\n Ethertype: %i\n",
               ntohs(ethh->ether_type)
              );
        return NULL;
    }

    if (wanted_type == found_type) {
        return found_header;
    }
    return NULL;
}


int receive_a_packet(const char *filter_str, char **packet_buf, long receive_timeout, int signal_pipe)
{
    struct pcap_pkthdr *received_packet_pcap;
    struct bpf_program pcap_filter;
    unsigned char *received_packet_data;
    int r, fd;
    fd_set select_me;
    struct timeval ts;

    if (pcap_compile(pcap, &pcap_filter, filter_str, 1, 0) == -1) {
        errx(1, "pcap_compile failed: %s", pcap_geterr(pcap));
    }
    if (pcap_setfilter(pcap, &pcap_filter) == -1) {
        errx(1, "pcap_setfilter failed: %s", pcap_geterr(pcap));
    }
    pcap_freecode(&pcap_filter);

    if ((fd = pcap_fileno(pcap)) == -1) {
        errx(1, "pcap_fileno failed");
    }

    FD_ZERO(&select_me);
    FD_SET(fd, &select_me);

    ts.tv_sec = receive_timeout;
    ts.tv_usec = 0;

    if (signal_pipe) {
        /*
         * Signal we're ready to go. Still a race condition. I don't see how to
         * work around this with pcap.
         */
        write(pfd[1], ".", 1);
    }

    r = select(fd + 1, &select_me, NULL, NULL, receive_timeout ? &ts : NULL);
    /* Timed out */
    if (r == 0) {
        return 0;
    }

    r = pcap_next_ex(pcap, &received_packet_pcap, (const unsigned char **) &received_packet_data);

    /* Error or pcap_next_ex timed out (should never happen) */
    if (r < 1) {
        return 0;
    }
    if (received_packet_pcap->len > received_packet_pcap->caplen) {
        errx(1, "pcap didn't capture the whole packet.");
    }

    *packet_buf = (char *) received_packet_data;
    return received_packet_pcap->len;
}

int receive_ack(char *srcip, char *dstip, unsigned short srcport, unsigned short dstport, char **packet_buf, long receive_timeout, int signal_pipe)
{
    /*
     * My back-of-the-napkin for the maximum length for the ipv6 filter string
     * below + 1 byte for the trailing NULL
     */
    const int FILTER_STR_LEN = 203;
    char filter_str[FILTER_STR_LEN];
    int r;

    /*
     * Something prior to now should have validated srcip and dstip are valid
     * IP addresses, we hope. Napkin math says we shouldn't even be close to
     * overflowing our buffer.
     */
    r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            "ip src %s and dst %s and (icmp or (tcp and src port %i and dst port %i))",
            srcip,
            dstip,
            srcport,
            dstport
        );
    if (r < 0 || r >= FILTER_STR_LEN) {
        errx(1, "snprintf for pcap filter failed");
    }
    return receive_a_packet(filter_str, packet_buf, receive_timeout, signal_pipe);
}

int receive_until_dup_ack(const char *filter_str, long receive_timeout, int signal_pipe, int *status)
{
    struct pcap_pkthdr *received_packet_pcap;
    struct bpf_program pcap_filter;
    unsigned char *received_packet_data;
    int r, fd, icw_packet_count, got_initial_seq;
    fd_set select_me;
    struct timeval ts;
    uint32_t last_seq, initial_seq = 0;
    struct tcphdr *tcph;
    struct ip *iph;
    time_t start_time;
    char last_byte;

    if (pcap_compile(pcap, &pcap_filter, filter_str, 1, 0) == -1) {
        errx(1, "pcap_compile failed: %s", pcap_geterr(pcap));
    }
    if (pcap_setfilter(pcap, &pcap_filter) == -1) {
        errx(1, "pcap_setfilter failed: %s", pcap_geterr(pcap));
    }
    pcap_freecode(&pcap_filter);

    if ((fd = pcap_fileno(pcap)) == -1) {
        errx(1, "pcap_fileno failed");
    }

    FD_ZERO(&select_me);
    FD_SET(fd, &select_me);

    ts.tv_sec = receive_timeout;
    ts.tv_usec = 0;

    if (signal_pipe) {
        /*
         * Signal we're ready to go. Still a race condition. I don't see how to
         * work around this with pcap.
         */
        write(pfd[1], ".", 1);
    }

    r = select(fd + 1, &select_me, NULL, NULL, receive_timeout ? &ts : NULL);
    /* Timed out */
    if (r == 0) {
        return 0;
    }

    got_initial_seq = 0;
    icw_packet_count = 0;
    start_time = time(NULL);
    while (1) {
        if (time(NULL) - start_time > receive_timeout) {
            break;
        }
        r = pcap_next_ex(pcap, &received_packet_pcap, (const unsigned char **) &received_packet_data);
        if (r == 0) {
            continue;
        }
        if (r < 1) {
            errx(1, "pcap error");
        }
        if (received_packet_pcap->len > received_packet_pcap->caplen) {
            errx(1, "pcap didn't capture the whole packet.");
        }

        iph = (struct ip *) find_packet_header((char *)received_packet_data, received_packet_pcap->len, IPPROTO_IP);
        if (!iph) {
            continue;
        }
        tcph = (struct tcphdr *) find_packet_header((char *)received_packet_data, received_packet_pcap->len, IPPROTO_TCP);
        if (!tcph) {
            continue;
        }
        last_seq = htonl(tcph->th_seq);

        if (!got_initial_seq && htons(iph->ip_len) - SIZEOF_IPV4 - tcph->th_off * 4 > 0) {
            //fprintf(stderr, "iseq = %u, len = %u\n", initial_seq, htons( iph->ip_len ) - SIZEOF_IPV4 - tcph->th_off * 4 );
            initial_seq = last_seq;
            got_initial_seq = 1;
            icw_packet_count++;

            if (status) {
                last_byte = received_packet_data[received_packet_pcap->len - 1];
                received_packet_data[received_packet_pcap->len - 1] = '\0';
                sscanf((char *) tcph + tcph->th_off * 4, "HTTP/1.1 %i", status);
                received_packet_data[received_packet_pcap->len - 1] = last_byte;
            }

            continue;
        }
        if (got_initial_seq) {
            //fprintf(stderr, "iseq = %u, lseq = %u, len = %u\n", initial_seq, last_seq, htons( iph->ip_len ) - SIZEOF_IPV4 - tcph->th_off * 4);
            if (got_initial_seq && initial_seq == last_seq && htons(iph->ip_len) - SIZEOF_IPV4 - tcph->th_off * 4 > 0) {
                break;
            }
            icw_packet_count++;
        }
    }

    return icw_packet_count;
}

int receive_icw_packets(char *srcip, char *dstip, unsigned short srcport, unsigned short dstport, long receive_timeout, int signal_pipe, int *status)
{
    /*
     * My back-of-the-napkin for the maximum length for the ipv6 filter string
     * below + 1 byte for the trailing NULL
     */
    const int FILTER_STR_LEN = 203;
    char filter_str[FILTER_STR_LEN];
    int r;

    /*
     * Something prior to now should have validated srcip and dstip are valid
     * IP addresses, we hope. Napkin math says we shouldn't even be close to
     * overflowing our buffer.
     */
    r = snprintf(
            (char *) &filter_str,
            FILTER_STR_LEN,
            "ip src %s and dst %s and (icmp or (tcp and src port %i and dst port %i))",
            srcip,
            dstip,
            srcport,
            dstport
        );
    if (r < 0 || r >= FILTER_STR_LEN) {
        errx(1, "snprintf for pcap filter failed");
    }
    return receive_until_dup_ack(filter_str, receive_timeout, signal_pipe, status);
}

/* IPv4 tests. */
void do_ipv4_syn(char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn)
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_TCP + SIZEOF_IPV4;

    ethh = (struct ether_header *) malloc_check(BIG_PACKET_SIZE);
    iph = (struct ip *)((char *) ethh + SIZEOF_ETHER);
    tcph = (struct tcphdr *)((char *) iph + SIZEOF_IPV4);

    append_ethernet(ethh, srcmac, dstmac, ETHERTYPE_IP);
    append_ipv4(iph, srcip, dstip, IPPROTO_TCP);
    append_tcp_syn(tcph, srcport, dstport, isn);
    calc_checksum(iph, IPPROTO_TCP, SIZEOF_TCP);
    calc_checksum(iph, IPPROTO_IP, SIZEOF_IPV4);

    packet_send(ethh, packet_size);
    free(ethh);
}

void do_ipv4_ack(char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn, uint32_t ack)
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_TCP + SIZEOF_IPV4;

    ethh = (struct ether_header *) malloc_check(BIG_PACKET_SIZE);
    iph = (struct ip *)((char *) ethh + SIZEOF_ETHER);
    tcph = (struct tcphdr *)((char *) iph + SIZEOF_IPV4);

    append_ethernet(ethh, srcmac, dstmac, ETHERTYPE_IP);
    append_ipv4(iph, srcip, dstip, IPPROTO_TCP);
    append_tcp(tcph, srcport, dstport, TH_ACK, isn, ack);

    calc_checksum(iph, IPPROTO_TCP, SIZEOF_TCP);
    calc_checksum(iph, IPPROTO_IP, SIZEOF_IPV4);

    packet_send(ethh, packet_size);
    free(ethh);
}

void do_ipv4_data(char *interface, char *srcip, char *dstip, char *srcmac, char *dstmac, unsigned short srcport, unsigned short dstport, uint32_t isn, uint32_t ack, char *data)
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct ether_header *ethh;
    char *data_here;
    int packet_size;

    packet_size = SIZEOF_ETHER + SIZEOF_TCP + SIZEOF_IPV4 + strlen(data);

    ethh = (struct ether_header *) malloc_check(BIG_PACKET_SIZE);
    iph = (struct ip *)((char *) ethh + SIZEOF_ETHER);
    tcph = (struct tcphdr *)((char *) iph + SIZEOF_IPV4);

    append_ethernet(ethh, srcmac, dstmac, ETHERTYPE_IP);
    append_ipv4(iph, srcip, dstip, IPPROTO_TCP);
    iph->ip_len = htons(SIZEOF_IPV4 + SIZEOF_TCP + strlen(data));
    data_here = append_tcp(tcph, srcport, dstport, TH_PUSH | TH_ACK, isn, ack);
    memcpy(data_here, data, strlen(data));

    calc_checksum(iph, IPPROTO_TCP, SIZEOF_TCP + strlen(data));
    calc_checksum(iph, IPPROTO_IP, SIZEOF_IPV4);

    packet_send(ethh, packet_size);
    free(ethh);
}

/* Process functions. */
void fork_pcap_listener(char *dstip, char *srcip, unsigned short dstport, unsigned short srcport, long receive_timeout, int do_count)
{
    char *packet_buf;
    char buf;
    int r, status;

    if (pipe(pfd) == -1) {
        err(1, "Failed to creatre pipe.");
    }

    listener_pid = fork();
    if (listener_pid == -1) {
        err(1, "Failed to fork");
    }
    if (listener_pid)  {
        close(pfd[1]);
        read(pfd[0], &buf, 1);
        return;
    }
    close(pfd[0]);
    /*
     * Due to how pcap works there's still a race between we signal that we are
     * ready and when we actually call select(). Will this even help with our
     * race condition if write() doesn't block? The documentation seems unclear
     * as to the advantages of O_NONBLOCK with a 1 byte write.
     */
    fcntl(pfd[1], F_SETFL, O_NONBLOCK);

    pcap_setdirection(pcap, PCAP_D_IN);

    if (!do_count) {
        r = receive_ack(dstip, srcip, dstport, srcport, &packet_buf, receive_timeout, 1);
        if (r) {
            write(pfd[1], &r, sizeof(int));
            write(pfd[1], packet_buf, r);
        } else {
            r = 0;
            write(pfd[1], &r, sizeof(int));
        }
    } else {
        r = receive_icw_packets(dstip, srcip, dstport, srcport, receive_timeout, 1, &status);
        write(pfd[1], &r, sizeof(int));
        write(pfd[1], &status, sizeof(int));
    }
    close(pfd[1]);
    exit(0);
}

int harvest_pcap_listener(char **packet_buf, int do_count, int *status)
{
    int packet_buf_size;
    int read_status;

    if (read(pfd[0], &packet_buf_size, sizeof(int)) < sizeof(int)) {
        errx(1, "Error communicating with child process.");
    }
    /* No packet received. */
    if (packet_buf_size == 0) {
        return 0;
    }

    if (!do_count) {
        if (packet_buf_size > PCAP_CAPTURE_LEN || packet_buf_size < 1) {
            errx(1, "Bad data received from child process.");
        }
        *packet_buf = (char *) malloc_check(packet_buf_size);
        if (read(pfd[0], *packet_buf, packet_buf_size) < packet_buf_size) {
            errx(1, "Error communicating with child process (2).");
        }
    } else {
        if (read(pfd[0], &read_status, sizeof(int)) < sizeof(int)) {
            errx(1, "Error communicating with child process (3).");
        }
        if (status) {
            *status = read_status;
        }
    }
    wait(NULL);
    return packet_buf_size;
}

void exit_with_usage(void)
{
    fprintf(stderr, "icwtest usage:\n");
    fprintf(stderr, "--help | -h  This message.\n");
    fprintf(stderr, "--srcip      Source IP address (this host).\n");
    fprintf(stderr, "--dstip      Destination IP address (target).\n");
    fprintf(stderr, "--srcport    Source port for TCP tests (optional).\n");
    fprintf(stderr, "--dstport    Destination port.\n");
    fprintf(stderr, "--dstmac     Destination MAC address (default gw or target host if on subnet).\n");
    fprintf(stderr, "--interface  Packet source interface.\n");
    fprintf(stderr, "--host       Host header to send with request.\n");
    fprintf(stderr, "--file       File to request via GET.\n");
    fprintf(stderr, "\n");
    exit(2);
}

void copy_arg_string(char **dst, char *opt)
{
    *dst = malloc_check(strlen(opt) + 1);
    memcpy(*dst, opt, strlen(opt) + 1);
}

int parse_args(
    int argc,
    char **argv,
    char **srcip,
    char **dstip,
    int *srcport,
    unsigned short *dstport,
    char **dstmac,
    char **interface,
    char **host_header,
    char **target_file
)
{
    int option_index = 0;
    int c, tmpport;
    struct hostent *he;
    static struct option long_options[] = {
        {"srcip", required_argument, 0, 0},
        {"dstip", required_argument, 0, 0},
        {"srcport", required_argument, 0, 0},
        {"dstport", required_argument, 0, 0},
        {"dstmac", required_argument, 0, 0},
        {"interface", required_argument, 0, 0},
        {"host", required_argument, 0, 0},
        {"file", required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    if (argc < 2) {
        exit_with_usage();
    }

    *srcip = *dstip = *dstmac = *interface = NULL;
    *srcport = -1;
    *dstport = 0;

    while (1) {
        c = getopt_long(argc, argv, "h", long_options, &option_index);
        if (c != 0 && c != 'h') {
            break;
        }

        if ((c == 'h') || (strcmp(long_options[option_index].name, "help") == 0)) {
            exit_with_usage();

        } else if (strcmp(long_options[option_index].name, "srcip") == 0) {
            copy_arg_string(srcip, optarg);

        } else if (strcmp(long_options[option_index].name, "dstip") == 0) {
            he = gethostbyname(optarg);
            if (he && he->h_addr_list[0]) {
                copy_arg_string(dstip, inet_ntoa(*((struct in_addr **)he->h_addr_list)[0]));
            } else {
                errx(1, "Failed to resolve host %s", optarg);
            }

        } else if (strcmp(long_options[option_index].name, "dstmac") == 0) {
            copy_arg_string(dstmac, optarg);

        } else if (strcmp(long_options[option_index].name, "interface") == 0) {
            copy_arg_string(interface, optarg);

        } else if (strcmp(long_options[option_index].name, "host") == 0) {
            copy_arg_string(host_header, optarg);

        } else if (strcmp(long_options[option_index].name, "file") == 0) {
            copy_arg_string(target_file, optarg);

        } else if (strcmp(long_options[option_index].name, "srcport") == 0) {
            tmpport = atoi(optarg);
            if (tmpport > 65535 || tmpport < 1) {
                errx(1, "Invalid value for srcport");
            }
            *srcport = (unsigned short) tmpport;

        } else if (strcmp(long_options[option_index].name, "dstport") == 0) {
            tmpport = atoi(optarg);
            if (tmpport > 65535 || tmpport < 1) {
                errx(1, "Invalid value for dstport");
            }
            *dstport = (unsigned short) tmpport;
        }
    }

    if (optind < argc) {
        exit_with_usage();
    }

    if (!*srcip) {
        errx(1, "Missing srcip");
    }
    if (!*dstip) {
        errx(1, "Missing dstip");
    }
    if (!*dstmac) {
        errx(1, "Missing dstmac");
    }
    if (!*interface) {
        errx(1, "Missing interface");
    }
    if (!*dstport) {
        errx(1, "Missing dstport");
    }
    if (!*host_header) {
        errx(1, "Missing host_header");
    }
    if (!*target_file) {
        errx(1, "Missing target_file");
    }

    return 1;
}

int check_received_syn_ack(int r, char *buf, uint32_t *remote_isn)
{
    struct tcphdr *tcph = (struct tcphdr *) find_packet_header(buf, r, IPPROTO_TCP);

    if (!tcph) {
        return 0;
    }

    // SYN+ACK
    if (tcph->th_flags == 0x12) {
        *remote_isn = ntohl(tcph->th_seq);
        return 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    char pcaperr[PCAP_ERRBUF_SIZE];
    int r, http_status;
    char *interface;
    char *srcip;
    char *dstip;
    char *srcmac;
    char *dstmac;
    uint16_t dstport;
    int srcport_param;
    uint16_t srcport;
    uint32_t isn = htonl(rand());
    char *packet_buf;
    long receive_timeout = DEFAULT_TIMEOUT_SECONDS;
    uint32_t remote_isn;
    char *data;
    char *data_format = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
    size_t data_size;
    char *host_header;
    char *target_file;

    if (!parse_args(argc, argv, &srcip, &dstip, &srcport_param, &dstport, &dstmac, &interface, &host_header, &target_file)) {
        exit_with_usage();
    }
    srand(getpid());

    if (srcport_param == -1) {
        srcport = rand();
        if (srcport < 1024) {
            srcport += 1024;
        }
    } else {
        srcport = srcport_param;
    }

    // Close enough
    data_size = strlen(data_format) + strlen(host_header) + strlen(target_file);
    if (!(data = malloc(data_size))) {
        err(1, "malloc");
    }
    if (snprintf(data, data_size, data_format, target_file, host_header) >= data_size) {
        errx(1, "snprintf size");
    }

    if ((pcap = pcap_open_live(interface, PCAP_CAPTURE_LEN, 0, 1, pcaperr)) == NULL) {
        errx(1, "pcap_open_live failed: %s", pcaperr);
    }

    if (pcap_datalink(pcap) != DLT_EN10MB) {
        errx(1, "non-ethernet interface specified.");
    }

    if ((srcmac = get_interface_mac(interface)) == NULL) {
        errx(1, "Failed to get MAC address for %s", interface);
    }

    printf("Starting test. Opening interface \"%s\".", interface);
    printf("\n\n");

    fork_pcap_listener(dstip, srcip, dstport, srcport, receive_timeout, 0);

    do_ipv4_syn(interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn);

    printf("Packet transmission successful, gathering replies...\n\n");

    r = harvest_pcap_listener(&packet_buf, 0, NULL);
    if (!r) {
        errx(1, "Test failed, no response before time out (%li seconds).\n", receive_timeout);
    }
    if (!check_received_syn_ack(r, packet_buf, &remote_isn)) {
        printf("\nTest failed (server down? wrong dstmac?).\n");
        free(packet_buf);
        return 1;
    }

    fork_pcap_listener(dstip, srcip, dstport, srcport, receive_timeout, 1);
    do_ipv4_ack(interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn + 1, remote_isn + 1);
    do_ipv4_data(interface, srcip, dstip, srcmac, dstmac, srcport, dstport, isn + 1, remote_isn + 1, data);

    r = harvest_pcap_listener(&packet_buf, 1, &http_status);
    if (!r) {
        errx(1, "Test failed, no response before time out (%li seconds).\n", receive_timeout);
    }
    printf("\nHTTP status (a guess): %i\nNumber of packets seen: %i\n", http_status, r);
    free(packet_buf);
    return 1;
}


