#pragma once
#include "util.h"

struct Options
{
    static LL packet_count ; // 捕获并打印到屏幕上的数据包数量
    static LL packet_capture_count ; // 捕获并写入到文件中的数据包数量
    static LL packet_capture_limit ; // Tcpdump -c参数值,限定捕获的数据包数量
    static int packet_capture_limit_flag;
    static int close_flag ;
    static int filter_set_flag ;
    static int savefile_flag;
    static int display_flag ;
    static int device_set_flag;
    static int SIGINT_trigger_flag ;
    static pcap_t *handle; // 用于打开网络接口所使用的handle

    static int buffer_size;
    static int buffer_size_set_flag;

    

    static pcap_t *pd;
    static pcap_dumper_t *pdumper;
    static char savefilename[128];
    static char device[32];
    static char filter_string[256];
    static pcap_pkthdr header;

    static u_char *packet;

};

LL Options::packet_capture_count = 1;
LL Options::packet_count = 1;
LL Options::packet_capture_limit = 0;
int Options::close_flag = 0;
int Options::filter_set_flag = 0;
int Options::savefile_flag = 0;
int Options::display_flag = 0;
int Options::device_set_flag = 0;
int Options::packet_capture_limit_flag = 0;
int Options::SIGINT_trigger_flag = 0;
int Options::buffer_size = 0;
int Options::buffer_size_set_flag = 0;

pcap_t * Options::handle = NULL;
pcap_t *Options::pd = NULL;
pcap_dumper_t *Options::pdumper = NULL;

char Options::savefilename[128] = {'0'};
char Options::device[32] = {'0'};
char Options::filter_string[256] = {'0'};

u_char *Options::packet = NULL;

pcap_pkthdr Options::header;

Options opts;