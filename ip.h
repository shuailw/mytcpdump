#pragma once
#include "util.h"

class IP_Header
{
public:
    IP_Header() : init_flag(0) { }
    IP_Header(const u_char *packet)
    {
        IPdata = packet + 14;
        u_char tmp = *(IPdata + 0);
        _version = tmp>>4;

        tmp = *(IPdata + 0);
        ip_header_length = tmp & 0x0f;

        type_of_service = *(IPdata +1);
        
        unsigned short *unshortptr = (unsigned short *)(IPdata + 2);
        total_length = *unshortptr;
        total_length = ntohs(total_length);
        unshortptr = (unsigned short *)(IPdata + 4);
        idenifiaction = *unshortptr;

        unshortptr = (unsigned short *)(IPdata + 6);
        unsigned short val = *unshortptr;
        val = val & 0xe000;
        val = val >> 13;
        val = val && 0x0007;
        u_char *ucharptr = (u_char *)(&val);
        ucharptr += 1;
        threebitsflag = *ucharptr;

        val = *unshortptr;
        val = val & 0x1fff;
        offset = val;

        ttl = *(IPdata + 8);
        protocol = *(IPdata + 9);
        unshortptr = (unsigned short *)(IPdata + 10);
        header_checksum = *unshortptr;
        // header_checksum = ntohs(header_checksum);

        unsigned int *unsintptr = (unsigned int *)(IPdata + 12);
        src_ip = *unsintptr;
        //src_ip = ntohl(src_ip);

        unsintptr = (unsigned int *)(IPdata + 16);
        dst_ip = *unsintptr; 
        // dst_ip = ntohl(dst_ip);

        if(ip_header_length*4>20) // 有选项
        {
            unsintptr = (unsigned int *)(IPdata + 20);
            opts = *unsintptr;
            // opts = ntohl(opts);
        }
        else
        {
            opts = 0;
        }
        init_flag = 1;
    }
    bool isIPv4()  {    return _version == 0x04;   }
    unsigned short get_ip_header_length()  {   return ip_header_length;  }
    u_char get_ttl() { return ttl; }
    u_char get_tos()  { return type_of_service; }
    unsigned short get_ip_idenifiaction() { return idenifiaction; }
    u_char get_3bitsflag() { return threebitsflag; }
    unsigned short get_13bits_offset() { return offset; }
    u_char get_ip_header_protocol() { return protocol; }
    unsigned short get_header_checksum() { return header_checksum; }
    unsigned int get_src_ip() { return src_ip; }
    unsigned int get_dst_ip() { return dst_ip; }
    unsigned int get_ip_opts() { return opts; }
    u_char get_raw_protocol() { return protocol; }
    const u_char *get_IPdata() { return IPdata; }
    bool hasInit() { return init_flag!=0; }
    std::string get_dots_srcip() { return ip2str(src_ip); }
    std::string get_dots_dstip() { return ip2str(dst_ip); }
    void printIP(unsigned int ip)
    {
        std::string ipstr= ip2str(ip);
        printf("%s\n",ipstr.c_str());
    }
    void printTos()
    {
        u_char tosval = type_of_service;
        u_char priority3bits = tosval & 0xe0;
        priority3bits = priority3bits >> 5;
        switch (priority3bits)
        {
        case 0x000:
            printf("tos: routine , ");
            break;
        case 0x01:
            printf("tos: priority , ");
            break;
        case 0x02:
            printf("tos: immediate , ");
            break;
        case 0x03:
            printf("tos: flash , ");
            break;
        case 0x04:
            printf("tos: flash override , ");
            break;
        case 0x05:
            printf("tos: critic , ");
            break;
        case 0x06:
            printf("tos: internetwork control , ");
            break;
        case 0x07:
            printf("tos: network control");
            break;
        default:
            break;
        }
        u_char service_type = type_of_service;
        service_type = service_type & 0x17;
        service_type >> 1;
        if(service_type & 0x08)
        {
            printf("tos: low latency\n");
        }
        if(service_type & 0x04)
        {
            printf("tos: high throughput\n");
        }
        if(service_type & 0x02)
        {
            printf("tos: high reliability\n");
        }
        if(0x01 & service_type)
            printf("tos: low spending\n");
        printf("\n");
    }
    void printProtocol()
    {
        if(protocol==0x06)
        {
            printf("protocol type : TCP\n");
        }
        else if(protocol==17)
        {
            printf("protocol type: UDP\n");
        }
        else if(protocol==1)
        {
            printf("protocol type : ICMP\n");
        }
        else if(protocol==4)
        {
            printf("protocol type: IP\n");
        }
        else
        {
            printf("protocol type: other protocol\n");
        }
    }
    char *getProtocolType()
    {
        if(protocol==0x06)
        {
            return "TCP";
        }
        else if(protocol==17)
        {
            return "UDP";
        }
        else if(protocol==1)
        {
            return "ICMP";
        }
        else if(protocol==4)
        {
            return "IP";
        }
        else
        {
            return "Other Protocol";
        }
    }
    void printIPHeader()
    {
        if(isIPv4())
            printf("IPv4 packet\n");
        else
        {
            printf("other protocol packet\n");
        }
        printf("%s --> %s\n", get_dots_srcip().c_str() , get_dots_dstip().c_str());
        printf("ip header length : %u , IP packet length : %u\n", ip_header_length*4, total_length);
        printTos();
        printf("ttl: %u\n",ttl);
        printProtocol();
        
    }
    unsigned short int get_total_length() { return total_length; }
    bool isTcp()
    {
        return protocol == 0x06;
    }
private:
    u_char _version; // IPv4 or IPv6;, 4位,参考: https://zh.wikipedia.org/wiki/IP%E5%8D%8F%E8%AE%AE%E5%8F%B7%E5%88%97%E8%A1%A8
    u_char ip_header_length; // IP首部长度,4位
    u_char type_of_service; // 服务类型,8位
    unsigned short total_length; // 16位
    unsigned short idenifiaction; // 16位标识
    u_char threebitsflag; // 3位标识
    unsigned short offset; // 13位标识
    u_char ttl; // 8位的TTL
    u_char protocol; // IP数据包上层的数据包类型，例如TCP，UDP，ICMP等,8位
    unsigned short header_checksum; // 16位校验和
    unsigned int src_ip; // 32位源IP
    unsigned int dst_ip; // 32位目的IP
    unsigned int opts;  // 选项，如果有
    const u_char *IPdata; // 整个数据包，== IP首部 + TCP首部/UDP首部 + 数据负荷
    unsigned int init_flag = 0;
    std::string ip2str(unsigned int ip)
    {
        char *tmp;
        tmp = libnet_addr2name4(ip, LIBNET_DONT_RESOLVE);
        return tmp;
    }
};



