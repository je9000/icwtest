/*
 * Copyright (c) 2012, Yahoo! Inc All rights reserved.
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
#include <err.h>
#include <string.h>

#ifdef __FreeBSD__
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#endif

#ifdef __linux
#define ETHERTYPE_IPV6 ETH_P_IPV6
#define __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include "checksums.h"
#include "constants.h"
#include "packets.h"

void *append_ethernet( void *buf, char *srcmac, char *dstmac, unsigned short ethertype )
{
    struct ether_header *ethh = buf;
    if ( sscanf( srcmac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
            &ethh->ether_shost[0],
            &ethh->ether_shost[1],
            &ethh->ether_shost[2],
            &ethh->ether_shost[3],
            &ethh->ether_shost[4],
            &ethh->ether_shost[5] ) != 6 ) {
        errx( 1, "Unable to parse source MAC address" );
    }

    if ( sscanf( dstmac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
            &ethh->ether_dhost[0],
            &ethh->ether_dhost[1],
            &ethh->ether_dhost[2],
            &ethh->ether_dhost[3],
            &ethh->ether_dhost[4],
            &ethh->ether_dhost[5] ) != 6 ) {
        errx( 1, "Unable to parse destination MAC address" );
    }

    ethh->ether_type = htons( ethertype );
    return (char *) ethh + SIZEOF_ETHER;
}

void *append_tcp( void *buf, unsigned short srcport, unsigned short dstport, int flags, uint32_t isn, uint32_t ack )
{
    struct tcphdr *tcph = buf;

    tcph->th_sport = htons( srcport );
    tcph->th_dport = htons( dstport );
    tcph->th_seq = htonl( isn );
    tcph->th_ack = htonl( ack );
    tcph->th_x2 = 0;
    tcph->th_off = SIZEOF_TCP / 4;
    tcph->th_flags = flags;
    tcph->th_win = TCP_WINDOW;
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    return (char *)tcph + SIZEOF_TCP;
}

void *append_tcp_syn( void *buf, unsigned short srcport, unsigned short dstport, uint32_t isn )
{
    return append_tcp( buf, srcport, dstport, TH_SYN, isn, 0 );
}

void *append_icmp_ping( void *buf, unsigned short payload_length )
{
    struct icmp *icmph = buf;

    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    icmph->icmp_cksum = 0;
    icmph->icmp_id = htons( ICMP_ID );
    icmph->icmp_seq = htons( 1 );
    memset( (char *) icmph + SIZEOF_PING, 0x01, payload_length );

    return (char *)icmph + SIZEOF_PING + payload_length;
}

void *append_icmp6_ping( void *buf, unsigned short payload_length )
{
    struct icmp6_hdr *icmp6h = buf;

    icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6h->icmp6_code = 0;
    icmp6h->icmp6_cksum = 0;
    icmp6h->icmp6_id = htons( ICMP_ID );
    icmp6h->icmp6_seq = htons( 1 );
    memset( (char *) icmp6h + SIZEOF_ICMP6, 0x01, payload_length );

    return (char *)icmp6h + SIZEOF_ICMP6 + payload_length;
}

void *append_ipv4( void *buf, char *srcip, char *dstip, unsigned char protocol )
{
    struct ip *iph = buf;

    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons( SIZEOF_IPV4 + SIZEOF_TCP );
    iph->ip_id = 0;
    iph->ip_off = 0;
    iph->ip_ttl = IPDEFTTL;
    iph->ip_p = protocol;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = inet_addr(srcip);
    iph->ip_dst.s_addr = inet_addr(dstip);

    return (char *)iph + SIZEOF_IPV4;
}

void *append_ipv4_short_frag1( void *buf, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid )
{
    struct ip *iph = buf;

    append_ipv4( iph, srcip, dstip, protocol );
    iph->ip_off = htons( 1 << IP_FLAGS_OFFSET ); /* Set More Fragments (MF) bit */
    iph->ip_id = htons( fragid );
    iph->ip_len = htons( SIZEOF_IPV4 + MINIMUM_FRAGMENT_SIZE );

    return (char *)iph + SIZEOF_IPV4;
}

void *append_ipv4_frag2( void *buf, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short payload_length )
{
    struct ip *iph = buf;

    append_ipv4( iph, srcip, dstip, protocol );
    iph->ip_off = htons( 1 );
    iph->ip_id = htons( fragid );
    iph->ip_len = htons( SIZEOF_IPV4 + payload_length );

    return (char *) iph + SIZEOF_IPV4;
}

void *append_ipv4_optioned_frag1( void *buf, char *srcip, char *dstip, unsigned char protocol, unsigned short fragid, unsigned short optlen )
{
    struct ip *iph = buf;

    append_ipv4( iph, srcip, dstip, protocol );
    iph->ip_off = htons( 1 << IP_FLAGS_OFFSET ); /* Set More Fragments (MF) bit */
    iph->ip_id = htons( fragid );
    iph->ip_len = htons( SIZEOF_IPV4 + optlen + MINIMUM_FRAGMENT_SIZE );

    if ( optlen % 4 != 0 ) errx( 1, "optlen must be a multiple of 4" );
    iph->ip_hl = 5 + ( optlen / 4 );

    /* Pad with NOP's and then end-of-padding option. */
    memset( (char *) iph + SIZEOF_IPV4, 0x01, optlen );
    *( (char *) iph + SIZEOF_IPV4 + optlen ) = 0;

    return (char *) iph + SIZEOF_IPV4 + optlen;
}

void *append_ipv6( void *buf, char *srcip, char *dstip, unsigned char protocol, unsigned short payload_length )
{
    struct ip6_hdr *ip6h = buf;

    /* 4 bits version, 8 bits TC, 20 bits flow-ID. We only set the version bits. */
    ip6h->ip6_flow = htonl( 0x06 << 28 );
    ip6h->ip6_plen = htons( payload_length );
    ip6h->ip6_hlim = 64;
    ip6h->ip6_nxt = protocol;
    if ( !inet_pton( AF_INET6, srcip, &ip6h->ip6_src ) ) errx( 1, "Invalid source address" );
    if ( !inet_pton( AF_INET6, dstip, &ip6h->ip6_dst ) ) errx( 1, "Invalid source address" );

    return (char *) ip6h + SIZEOF_IPV6;
}

void *append_frag( void *buf, unsigned char protocol, unsigned short offset, unsigned short fragid, int more )
{
    struct ip6_frag *fragh = (struct ip6_frag *) buf;

    fragh->ip6f_reserved = 0;
    fragh->ip6f_nxt = protocol;
    fragh->ip6f_ident = htons( fragid );
    if ( offset % 8 != 0 ) errx( 1, "wrong size" );
    offset = offset / 8;
    fragh->ip6f_offlg = htons( offset << 3 );
    if ( more ) fragh->ip6f_offlg |= IP6F_MORE_FRAG;

    return (char *) buf + sizeof( struct ip6_frag );
}

void *append_dest( void *buf, unsigned char protocol, unsigned int optlen )
{
    struct ip6_dest *desth = (struct ip6_dest *) buf;

    desth->ip6d_nxt = protocol;
    if ( optlen > 255 * 8 || optlen % 8 != 6 ) errx( 1, "optlen value not valid" );
    desth->ip6d_len = optlen / 8;
    *( (char *) desth + sizeof( struct ip6_dest ) ) = 1;
    *( (char *) desth + sizeof( struct ip6_dest ) + 1 ) = optlen - 2;
    memset( (char *) desth + sizeof( struct ip6_dest ) + 2, 0, optlen - 2 );

    return (char *) buf + sizeof( struct ip6_dest ) + optlen;
}

