#pragma once
#include "util.h"
#include "ip.h"
#include "link_ether.h"
#include "options.h"

class IP_Header;

class ARP_Packet
{
public:
    ARP_Packet(const u_char *packet) 
    : ether_header(new Ether_Header(packet)),
      arp_data(packet),
      arp_payload_data(packet+14),
      arp_packet_init_flag(1)
    {
        unsigned short int *unshortptr = (unsigned short int *)(arp_payload_data + 0);
        hardware_type = *unshortptr;
        unshortptr = (unsigned short int *)(arp_payload_data+2);
        protocol_type = *unshortptr;
        u_char *ucptr=(u_char *)(arp_payload_data + 4);
        hardware_addr_length = *ucptr;
        ucptr = (u_char *)(arp_payload_data + 5);
        protocol_addr_length = *ucptr;
        unshortptr = (unsigned short int *)(arp_payload_data+6);
        op = *unshortptr;
        op = ntohs(op);
        for(int i=0; i<6; ++i)
        {
            src_mac[i] = *(arp_payload_data+i+8);
            dst_mac[i] = *(arp_payload_data+i+18);
        }
        unsigned int *ptr = (unsigned int *)(arp_payload_data+14);
        src_ip = *ptr;
        ptr = (unsigned int *)(arp_payload_data+24);
        dst_ip = *ptr;
    }
    bool hasInit() { return arp_packet_init_flag!=0; }
    void printhex(const struct pcap_pkthdr *header, const u_char *packet)
    {
        if(header==NULL || packet==NULL || header->caplen!=header->len)
            return;
        int len = header->caplen;
        char time_stamp[64];
        time2str(time_stamp, &header->ts);
        std::string src_mac_str = ether_header->macAddr2str(src_mac);
        std::string dst_mac_str = ether_header->macAddr2str(dst_mac);
        std::string src_ip_str = libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE);
        std::string dst_ip_str = libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE);
        printf("-------------------------------   No.%lld packet  --------------------------------------\n",opts.packet_count);
        if(op==0x01)
        {
            printf("%s Source %s Destination %s. Who has %s? Tell %s\n",time_stamp, ether_header->get_src_mac_str().c_str(), 
                ether_header->get_dst_mac_str().c_str(), dst_ip_str.c_str(),src_ip_str.c_str());
            ether_header->print_packet_hex(packet,len);
        }
        else if(op==0x02)
        {
            printf("%s Source %s Destination %s.  %s is at %s\n",time_stamp, ether_header->get_src_mac_str().c_str(), 
                ether_header->get_dst_mac_str().c_str(), src_ip_str.c_str(),src_mac_str.c_str());
            ether_header->print_packet_hex(packet,len);
        }
        else // RARP TODO
        {
            printf("ARP protocol\n");
            ether_header->print_packet_hex(packet,len);
        }
        opts.packet_count += 1;
    }
    ~ARP_Packet()
    {
        delete ether_header;
    }
private:
    const u_char *arp_data; // 包好了以太网首部
    const u_char *arp_payload_data; // 不包含以太网首部
    Ether_Header *ether_header;
    unsigned int arp_packet_init_flag = 0;

    unsigned short int hardware_type; // 硬件类型，2字节
    unsigned short protocol_type;  // 协议类型，2字节
    u_char hardware_addr_length; // 硬件地址长度，1字节
    u_char protocol_addr_length; // 协议地址长度，1字节
    // 对于以太网上IP地址的ARP请求来说，它们的值为6和4
    unsigned short int op; // 操作类型，<1,ARP请求>, <2,ARP响应>,<3,RARP请求>,<4,RARP应答>
    u_char src_mac[6];
    unsigned int src_ip;
    u_char dst_mac[6];
    unsigned int dst_ip;
};