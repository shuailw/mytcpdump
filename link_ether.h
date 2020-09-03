#pragma once
#include "util.h"

struct Ether_Header // 链路层帧头部
{
    Ether_Header(const u_char *packet)
    {
        data =packet;
        for(int i=0; i<6; ++i)
            dstMacAddr[i] = *(packet+i);
        for(int i=6; i<12; ++i)
            srcMacAddr[i] = *(packet+i);
        unsigned short int *ptr = (unsigned short int *)(packet+12);
        protocol = *ptr;
        protocol = ntohs(protocol);
        ether_header_init_flag = 1;
    }
    std::string get_src_mac_str() { return macAddr2str(srcMacAddr); }
    std::string get_dst_mac_str() { return macAddr2str(dstMacAddr); }
    bool isIP(unsigned int proto) { return proto == 0x0800; }
    bool hasInit() { return ether_header_init_flag !=0; }
    void print_packet_hex(const u_char *packet, int len)
    {
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
    }
    std::string macAddr2str(const u_char *macaddr)
    {
        std::string macaddrstr;
        for(int i=0; i<6; ++i)
        {
            char tmp[5];
            u_char val = *(macaddr+i);
            if(i!=5)
            {
                sprintf(tmp,"%02x::",val);
                macaddrstr += tmp;
            }
            else
            {
                sprintf(tmp, "%02x",val);
                macaddrstr += tmp;
            }
        }
        return macaddrstr;
    }
private:
    u_char dstMacAddr[6];
    u_char srcMacAddr[6];
    unsigned short int protocol;
    const u_char *data;
    unsigned int ether_header_init_flag = 0;
    
};
