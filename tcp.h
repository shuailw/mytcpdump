#pragma once
#include "util.h"
#include "ip.h"
#include "link_ether.h"
#include <memory>
#include "options.h"
#include <ctime>
#include <iostream>

class IP_Header;

class TCP_Header
{
public:
    TCP_Header(const u_char *packet)
    {
        IP_Header ipheader(packet);

        ether_ip_header_length =ipheader.get_ip_header_length()*4 + 14;

        TCPdata = packet + ether_ip_header_length;
        unsigned short *usshortintptr = (unsigned short *)(TCPdata+0);
        src_port = *usshortintptr;
        src_port = ntohs(src_port);

        usshortintptr = (unsigned short *)(TCPdata+2);
        dst_port = *usshortintptr;
        dst_port = ntohs(dst_port);

        unsigned int *usintptr = (unsigned int *)(TCPdata + 4);
        seq_num = *usintptr;
        seq_num = ntohl(seq_num);

        usintptr = (unsigned int *)(TCPdata + 8);
        ack_num = *usintptr;
        ack_num = ntohl(ack_num);

        u_char *uchar_ptr  = (u_char *)(TCPdata + 12);
        u_char uc_tmp = *uchar_ptr;
        uc_tmp = uc_tmp >> 4;
        uc_tmp = uc_tmp & 0x0f;
        TCP_header_length = uc_tmp; // 使用时需要x4

        usshortintptr = (unsigned short *)(TCPdata + 12);
        unsigned short unshortval = *usshortintptr;
        unshortval = 0x0fc0 & unshortval;
        unshortval = unshortval >> 6;
        uchar_ptr = (u_char *)(&unshortval);
        uchar_ptr += 1;
        preserve_bits = *uchar_ptr;

        uchar_ptr = (u_char *)(TCPdata + 13);
        uc_tmp  = *uchar_ptr;
        uc_tmp = 0x003f & uc_tmp;
        urg_bit = uc_tmp & 0x20;
        ack_bit = uc_tmp & 0x10;
        psh_bit = uc_tmp & 0x08;
        rst_bit = uc_tmp & 0x04;
        syn_bit = uc_tmp & 0x02;
        fin_bit = uc_tmp & 0x01; 

        usshortintptr = (unsigned short *)(TCPdata + 14);
        TCP_windows_sz = *usshortintptr;
        TCP_windows_sz = ntohs(TCP_windows_sz);

        usshortintptr = (unsigned short *)(TCPdata + 16);
        tcp_checksum = *usshortintptr;
        tcp_checksum = ntohs(tcp_checksum);

        usshortintptr = (unsigned short *)(TCPdata + 18);
        emergency_ptr = *usshortintptr;
        emergency_ptr = ntohs(emergency_ptr);

        if(TCP_header_length*4 > 20)
        {
            unsigned int *ptr = (unsigned int *)(TCPdata + 20);
            tcp_opts = *ptr;
        }
        else
            tcp_opts = 0;
        tcp_header_init_flag = 1;
    }
    unsigned short get_src_port() { return src_port; }
    unsigned short get_dst_port() { return dst_port; }
    unsigned int get_seq_num() { return seq_num; }
    unsigned int get_ack_num() { return ack_num; }
    unsigned short int get_tcp_header_length() { return TCP_header_length*4; }
    u_char get_preserve_bits() { return preserve_bits; }
    bool usrbitSet() { return urg_bit!=0; }
    bool ackbitSet() { return ack_bit!=0; }
    bool pshbitSet() { return psh_bit!=0; }
    bool synbitSet() { return syn_bit!=0; }
    bool finbitSet() { return fin_bit!=0; }
    bool rstbitSet() { return rst_bit!=0; }
    unsigned short get_emperence_ptr() { return emergency_ptr; }
    bool hasInited() { return tcp_header_init_flag!=0; }
    unsigned short int get_tcp_windows_sz() { return TCP_windows_sz; }

private:
    unsigned short src_port; // 16位
    unsigned short dst_port; // 16位
    unsigned int seq_num; // 32位
    unsigned int ack_num; // 32位
    u_char TCP_header_length; // 4位首部长度 
    u_char preserve_bits; // 保留位，6位
    u_char TCP_packet_type; // 6位，ACK，SYN，FIN等
    unsigned short TCP_windows_sz; // 16位窗口大小
    unsigned short tcp_checksum; // 16位TCP校验和
    unsigned short emergency_ptr; // 16位紧急指针
    unsigned int tcp_opts; // TCP可选选项
    const u_char *TCPdata; // data = TCP首部/UDP首部 + 负荷数据, TCP的首部第一个字节
    unsigned short ether_ip_header_length;
    u_char urg_bit = 0;
    u_char ack_bit = 0;
    u_char psh_bit = 0;
    u_char syn_bit = 0;
    u_char fin_bit = 0;
    u_char rst_bit = 0;

    unsigned int tcp_header_init_flag = 0;
    
};

class TCP_Packet
{
public:
    TCP_Packet(const u_char *packet_) 
        : ether_header(new Ether_Header(packet_)), 
        ip_header(new IP_Header(packet_)),
        tcp_header(new TCP_Header(packet_)),
        packet(packet_),
        tcp_packet_init_flag(1)
    {

    }
    bool hasInited() { return tcp_packet_init_flag!=0; }
    Ether_Header *get_ether_header()
    {
        return ether_header;
    }
    TCP_Header *get_Tcp_header() { return tcp_header; }
    IP_Header *get_ip_header() { return ip_header; }
    void printhex(const struct pcap_pkthdr *header, const u_char *packet)
    {
        // 该回调仅仅显式数据包        
        if(header==NULL || packet==NULL)
        {
            printf("header or packet is NULL");
            return;
        }
        int len = header->caplen;
        char time_stamp[64];
        time2str(time_stamp, &header->ts);
        std::string srcipstr = ip_header->get_dots_srcip();
        std::string dstipstr = ip_header->get_dots_dstip();
        std::string flag_str = "Flags [";
        if(tcp_header->synbitSet())
            flag_str += 'S';
        if(tcp_header->ackbitSet())
            flag_str += '.';
        if(tcp_header->pshbitSet())
            flag_str += 'P';
        if(tcp_header->usrbitSet())
            flag_str += 'U';
        if(tcp_header->rstbitSet())
            flag_str += 'R';
        if(tcp_header->finbitSet())
            flag_str += 'F';
        flag_str += ']';
        printf("-------------------------------   No.%lld packet  --------------------------------------\n",opts.packet_count);
        printf("%s %s %s:%u --> %s:%u  , %s  seq %u ,  ack %u , win %u , length %u\n", time_stamp, ip_header->getProtocolType(),srcipstr.c_str(), tcp_header->get_src_port(),
            dstipstr.c_str(), tcp_header->get_dst_port(), flag_str.c_str(), tcp_header->get_seq_num(), tcp_header->get_ack_num(), 
                tcp_header->get_tcp_windows_sz(), ip_header->get_total_length());
        ether_header->print_packet_hex(packet,len);
        opts.packet_count += 1;
    }
    ~TCP_Packet()
    {
        delete ip_header;
        delete tcp_header;
        delete ether_header;
    }
private:
    Ether_Header *ether_header;
    IP_Header *ip_header;
    TCP_Header *tcp_header;
    const u_char *packet;
    unsigned int tcp_packet_init_flag = 0;

};