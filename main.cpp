#include "packet_capture.h"

int main(int argc, char **argv)
{
    Packet_Capture capture;
    int opt = 0;
    while((opt = getopt(argc, argv, "i:w:f:c:b:v"))!=-1)
    {
        switch (opt)
        {
        case 'i':
            sprintf(opts.device,"%s",optarg);
            printf("device : %s\n", opts.device);
            opts.device_set_flag = 1;
            break;
        case 'w':
            sprintf(opts.savefilename,"%s",optarg);
            printf("save packets to %s\n",opts.savefilename);
            opts.savefile_flag = 1;
            break;
        case 'f':
            sprintf(opts.filter_string,"%s",optarg);
            printf("filter condition : %s\n", opts.filter_string);
            opts.filter_set_flag = 1;
            break;
        case 'v':
            opts.display_flag = 1;
            break;
        case 'c':
            opts.packet_capture_limit = str2LL(optarg);
            printf("packet capture number limit : %lld\n", opts.packet_capture_limit);
            opts.packet_capture_limit_flag = 1;
            break;
        case 'b':
            // 设置handle的buffer size, TODO
            opts.buffer_size = (int)str2LL(optarg); 
            opts.buffer_size_set_flag = 1;
        default:
            break;
        }
    }
    if(opts.device_set_flag==0 || (opts.display_flag==0 && opts.savefile_flag==0))
    {
        printf("usage : Tcpdump -i network_interface -w pcapfilename -v(print packet on screen) -f filter_conditon\n");
    }
    capture.startCapture(&opts);
    if(opts.close_flag==0)
    {
        if(opts.savefile_flag)
        {
            pcap_close(opts.pd);
            pcap_dump_close(opts.pdumper);
        }
        pcap_close(opts.handle);
    }
    return 0;
}