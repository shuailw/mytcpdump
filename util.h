#pragma once
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <string>
#include <libnet.h>
#include <assert.h>
#include <ctime>
#include <math.h>
#include <iostream>

#define BUFSIZE 2048
using LL = long long int;

void time2str(char *time_stamp, const struct timeval *t)
{
    struct tm *ts;
    ts = localtime(&t->tv_sec);
    strftime(time_stamp, 64, "%F %X",ts);
}

long long int str2LL(char *str) 
{
    int len = strlen(str);
    if(len==0) return 0;
    long long int num = 0;
    for(int j=0; j<len; ++j)
    {
        int index = len - 1-j;
        if(!('0'<=str[index] && '9'>=str[index]))
            return 0;
        long long int  val = (long long int)(str[index]-'0');
        num = val*(long long int)(pow(10,j)) + num;
    }
    return num;
}

