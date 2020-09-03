#pragma once
#include "util.h"
#include "ip.h"
#include "link_ether.h"
#include "options.h"


class IP_Header;

class UDP_Header
{
public:
    UDP_Header(const u_char *packet) : udp_data(packet)
    {
        IP_Header ip_header(packet);
        unsigned short int ipheader_length = ip_header.get_ip_header_length();
        ether_ip_header_len = ipheader_length*4 + 14;
        const u_char *udp_payload_data = (u_char *)(packet + ether_ip_header_len); 
        u_char uc_val = *(packet + 0);
        uc_val = uc_val & 0x0f;
        unsigned int ip_header_length = uc_val * 4;

        unsigned short int *usshortintptr = (unsigned short int *)(udp_payload_data + 0);
        src_port = *usshortintptr;
        src_port = ntohs(src_port);

        usshortintptr = (unsigned short int *)(udp_payload_data + 2);
        dst_port = *usshortintptr;
        dst_port = ntohs(dst_port);

        usshortintptr = (unsigned short int *)(udp_payload_data + 4);
        udp_packet_length = *usshortintptr;
        udp_packet_length = ntohs(udp_packet_length);

        usshortintptr = (unsigned short int *)(udp_payload_data + 6);
        udp_checksum = *usshortintptr;
        udp_checksum = ntohs(udp_checksum);

        init_udp_header_flag = 1;
    }
    bool hasInit() { return init_udp_header_flag != 0; }
    unsigned short get_src_port() { return src_port; }
    unsigned short get_dst_port() { return dst_port; }
    unsigned short get_udp_packet_length() { return udp_packet_length; }
    unsigned short get_udp_checksum() { return udp_checksum; }
    const u_char *get_udp_payload_data() { return (u_char *)(udp_data + ether_ip_header_len);  }
    const u_char *get_udp_data() { return udp_data; }
private:
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned short int udp_packet_length;
    unsigned short int udp_checksum;
    unsigned int init_udp_header_flag = 0;
    const u_char *udp_data; // 包含了UDP首部
    unsigned short int ether_ip_header_len ;
};

class UDP_Packet
{
public:
    UDP_Packet(const u_char *packet_)
      : packet(packet_),
        ether_header(new Ether_Header(packet_)),
        ip_header(new IP_Header(packet_)),
        udp_header(new UDP_Header(packet_)),
        udp_packet_init_flag(1)
    {

    }
    ~UDP_Packet()
    {
        delete ether_header;
        delete ip_header;
        delete udp_header;
    }
    void printhex(const struct pcap_pkthdr *header, const u_char *packet)
    {
        if(header==NULL || packet==NULL || header->caplen!=header->len)
            return;
        int len = header->caplen;
        char time_stamp[64];
        time2str(time_stamp,&header->ts);
        std::string srcipstr = ip_header->get_dots_srcip();
        std::string dstipstr = ip_header->get_dots_dstip();
        printf("-------------------------------   No.%lld packet  --------------------------------------\n",opts.packet_count);
        printf("%s %s %s:%u --> %s:%u , length %u\n",time_stamp, ip_header->getProtocolType(), 
            srcipstr.c_str(), udp_header->get_src_port(), dstipstr.c_str(), udp_header->get_dst_port(), udp_header->get_udp_packet_length());
        ether_header->print_packet_hex(packet,len);
        opts.packet_count += 1;
    }
private:
    Ether_Header *ether_header;
    IP_Header *ip_header;
    UDP_Header *udp_header;
    const u_char *packet;
    unsigned int udp_packet_init_flag = 0;

};