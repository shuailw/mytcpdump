#pragma once
#include "util.h"
#include "ip.h"
#include "tcp.h"
#include "options.h"
#include "udp.h"
#include "arp.h"

static void handle_SIGINT(int sig)
{
    if(opts.SIGINT_trigger_flag!=0) // 避免重复触发,触发SIGINT信号会关闭handle,handle不能重复关闭,否则就会触发段错误
        return;
    opts.SIGINT_trigger_flag = 1;
    struct pcap_stat stat;
    if(pcap_stats(opts.handle, &stat)==0)
    {
        // stat.ps_drop, number of packets dropped because there was no room in the operating system's buffer when they arrived,
        //  because packets weren't being read fast enough;
        // stat.ps_ifdrop , number of packets dropped by the network interface or its driver.
        printf("\n%u packets received\n",stat.ps_recv);
        printf( "%u packets dropped by by the system because there was no room in the operating system's buffer when they arrived.\n", stat.ps_drop);
        printf("%u packets dropped by the network interface or its driver\n\n", stat.ps_ifdrop);
    }
    else
    {
        printf("\ncan't get packet drop and receive information\n");
    }
    if(opts.savefile_flag)
    {
        pcap_close(opts.pd);
        pcap_dump_close(opts.pdumper);
        printf("\nwrite %lld packets to pcap file\n",opts.packet_capture_count-1);
    }
    if(opts.close_flag==0)
        pcap_close(opts.handle);
    opts.close_flag = 1;
    opts.savefile_flag = 0;
}

class Set_Signal_Handler
{
public:
    Set_Signal_Handler()
    {
        if(signal(SIGINT,handle_SIGINT)==SIG_ERR)
        {
            printf("Set_Signal_Handler() error\n");
        }
    }
};
void setSavePcapfile() // 在将数据包写入到pcap文件前，需要进行一些设定
{
    if(opts.savefile_flag!=0)
    {
        opts.pd = pcap_open_dead(DLT_EN10MB,65535);
        opts.pdumper = pcap_dump_open(opts.pd, opts.savefilename);
    }
}
void save_all_types_pcap_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 该回调保存所有类型的数据包到pcap文件
    u_char *pdumper_ = args;
    pcap_dump(pdumper_,header,packet);
    ++opts.packet_capture_count;
}
void print_all_types_packet_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 该回调打印所有类型的数据包到屏幕上
    int len = header->caplen;
    printf("-------------------------------- No.%lld packet -------------------------------------------\n", opts.packet_count);
    for(int i=0; i<len; )
    {
        int j = 0;
        int curlen = 0;
        printf("0x%04x:  ", i);
        for(j=0; j<16;)
        {
            if(i+j<len)
            {
                ++curlen;
                u_char val = packet[i+j];
                ++j;
                printf("%02x ",val);
            }
            else
            {
                ++j;
                printf("   ");
            }
            if(j%8==0)
                printf("  ");
        }
        printf("  ");
        for(j=0; j<16; )
        {
            if(i+j<len)
            {
                u_char val = packet[i+j];
                ++j;
                if(val>=33 && val<127)
                {
                    if(val=='\\')
                    {
                        putchar('\\'); 
                    }
                    else
                    {
                        putchar(val); 
                    }
                    }
                else
                {
                    putchar('.'); 
                }
            }
            else
            {
                ++j;
                printf(" ");
            }
            if(j%8==0)
                printf("  ");
        }
        i += curlen;
        printf("\n");
    }
    printf("\n\n\n");
    opts.packet_count += 1;
}
Set_Signal_Handler set_sigint_handler; // 设置对SIGINT的信号处理函数

enum class Protocol_Type
{
    // 更多协议类型添加TODO
    TCP, UDP, ARP, IP, ICMP, IPv4, Other
};
Protocol_Type get_protocol_type(const u_char *packet)
{
    unsigned short int *ptr = (unsigned short int *)(packet+12);
    unsigned short int ether_protocol = *ptr;
    ether_protocol = ntohs(ether_protocol);
    if(ether_protocol == 0x0800) // IP数据包
    {
        IP_Header ip_header(packet);
        u_char ip_protocol = ip_header.get_raw_protocol();
        switch (ip_protocol)
        {
        case 0x06:
            return Protocol_Type::TCP;
        case 0x01:
            return Protocol_Type::ICMP;
        case 0x04:
            return Protocol_Type::IPv4;
        case 0x11:
            return Protocol_Type::UDP;
        default:
            // 更多基于IP协议的上层协议解析TODO
            return Protocol_Type::Other;
        }
    }
    else if(ether_protocol == 0x0806) // ARP请求/应答
    {
        return Protocol_Type::ARP;
    }
    else 
    {
        // 更多非基于IP协议类型解析TODO
        return Protocol_Type::Other;
    }
    return Protocol_Type::Other;
}

void dispatch(u_char *args,const struct pcap_pkthdr *header, const u_char *packet) // 根据数据包的协议类型，新建不同类型的数据包类型实例，然后处理数据包
{
    if(opts.packet_capture_limit_flag!=0 && opts.packet_count > opts.packet_capture_limit)
    {
        raise(SIGINT);
    }
    else
    {
        // dispatch()处理情形1：只打印数据包到屏幕上，情形2：打印数据包屏幕上和保存数据包到pcap文件中
        Protocol_Type protocol =  get_protocol_type(packet);
        IP_Header ipheader(packet);
        if(opts.display_flag != 0 && opts.savefile_flag==0) // 情形1：只打印数据包到屏幕上
        {
            if(protocol == Protocol_Type::TCP)
            {
                TCP_Packet tcppacket(packet);
                tcppacket.printhex(header, packet);
            }
            else if(protocol == Protocol_Type::UDP)
            {
                UDP_Packet udp_packet(packet);
                udp_packet.printhex(header,packet);
            }
            else if(protocol == Protocol_Type::ARP)
            {
                ARP_Packet arp_packet(packet);
                arp_packet.printhex(header,packet);
            }
            else if(protocol ==  Protocol_Type::Other )
            {
                // 更多协议类型解析，TODO
                printf("protocol = 0x%02x , other protocol packet\n", ipheader.get_raw_protocol());
                print_all_types_packet_cb(args,header,packet);
            }
            else
            {
                // TODO
                printf("protocol = 0x%02x , other protocol packet\n", ipheader.get_raw_protocol());
                print_all_types_packet_cb(args,header,packet);
            }
            
        }
        if(opts.display_flag!=0 && opts.savefile_flag != 0) // 情形2：打印数据包到屏幕上和保存数据包到pcap文件中
        {
            save_all_types_pcap_cb(args,header,packet);
            if(protocol == Protocol_Type::TCP)
            {
                TCP_Packet tcppacket(packet);
                tcppacket.printhex(header, packet);
            }
            else if(protocol == Protocol_Type::UDP)
            {
                UDP_Packet udp_packet(packet);
                udp_packet.printhex(header,packet);
            }
            else if(protocol == Protocol_Type::ARP)
            {
                ARP_Packet arp_packet(packet);
                arp_packet.printhex(header,packet);
            }
            else if(protocol ==  Protocol_Type::Other )
            {
                // 更多协议类型解析，TODO
                printf("protocol = 0x%02x , other protocol packet\n", ipheader.get_raw_protocol());
                print_all_types_packet_cb(args,header,packet);
            }
            else
            {
                // TODO
                printf("protocol = 0x%02x , other protocol packet\n", ipheader.get_raw_protocol());
                print_all_types_packet_cb(args,header,packet);
            }
        }
    }
}

class Packet_Capture
{
public:
    void startCapture(Options *opts)
    {
        // 在调用Packet_Capture::startCapture()前，Tcpdump基本的选项已经读入并且设定好
        assert(opts->device_set_flag !=0);
        
        opts->handle = pcap_open_live(opts->device, 65535, 1,0,errno_buf); // 打开网络接口
        if(opts->handle==NULL)
        {
            printf("PacketCapture::startCapture()::pcap_open_live() error\n");
            exit(-1);
        }
        // 设置过滤条件，如果之前已经设置了的话
        if(opts->filter_set_flag!=0)
        {
            printf("set filter condition: %s\n", opts->filter_string);
            struct bpf_program filter;
            pcap_compile(opts->handle, &filter,opts->filter_string, 1,0);
            pcap_setfilter(opts->handle, &filter);
        }
        // 当前已经设置好了Ctrl+C的信号处理函数
        // 主要有几种使用方法
        //   * 只将捕获的数据包在屏幕上显示
        //   * 将捕获的数据包在屏幕显示和保存到pcap文件中
        //   * 只将捕获的数据包保存到pcap文件中
        int limit = -1;
        if(opts->packet_capture_limit_flag!=0)
            limit = (int)opts->packet_capture_limit;
        if(opts->SIGINT_trigger_flag==0 && opts->display_flag!=0 && opts->savefile_flag==0) // 只将捕获的数据包在屏幕上显示
        {
            while((pcap_loop(opts->handle, limit, dispatch,NULL))>0)
                ;
            raise(SIGINT);
        }
        if(opts->SIGINT_trigger_flag==0 && opts->display_flag!=0 && opts->savefile_flag!=0) // 将捕获的数据包在屏幕显示和保存到pcap文件中
        {
            setSavePcapfile();
            while((pcap_loop(opts->handle, limit, dispatch,(u_char *)opts->pdumper))>0)
                ;
            raise(SIGINT);
        }
        if(opts->SIGINT_trigger_flag==0 && opts->display_flag==0 && opts->savefile_flag!=0) // 只将捕获的数据包保存到pcap文件中
        {
            setSavePcapfile();
            while((pcap_loop(opts->handle, limit, save_all_types_pcap_cb, (u_char *)opts->pdumper))>0)
                ;
            raise(SIGINT);
        }
    }
private:
    char errno_buf[BUFSIZE];
};

