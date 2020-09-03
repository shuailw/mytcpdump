 # tcpdump的简单实现
 
 ## 安装
 
 ### 1. 安装libpcap
 
 [下载libpcap](https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz)
 ```
 tar xzvf libpcap-xxx.tar.gz
 cd libpcap-xxx
 ./configure
 sudo make && make install
 ```
 ### 2. 安装libnet
 [下载libnet](https://github.com/libnet/libnet/releases)
 ```
 tar xf libnet-x.y.z.tar.gz
 cd libnet-x.y.z/
 ./configure && make
 sudo make install
 ```
 ### 3. 编译Tcpdump
 
 `make`
 
 ## 使用
 
 目前只实现了tcpdump的4个选项
 * `-i`选项: 指定监听的网卡名, 网卡名称可以使用`ifconfig`命令查看
 * `-w`选项: 将捕获的数据包保存到pcap文件中
 * `-v`选择: 将捕获的数据包显示在屏幕上. 目前只做了ARP,TCP, UDP数据包的协议解析
 * `-f`选项: 设置数据包过滤条件, 例如过滤掉目的/源IP地址为127.0.0.1的数据包`-f "not host 127.0.0.1"
 
 运行前需要先设置一下动态链接器的动态链接库加载路径
 ```
 LD_LIBRARY_PATH=D_LIBRARY_PATH:/usr/local/lib
 export LD_LIBRARY_PATH
 ```
 使用例子
 1. 显示`lo`网卡数据包
 `./Tcpdump -i ens33 -v`
 2. 显示并将捕获的数据包写入到pcap文件
 `./Tcpdump -i lo -v -w 1.pcap`
 
 3. 不显示,仅仅将捕获的数据包写入到pcap文件
 `./Tcpdump -i ens33 -w  2.pcap`
 
 ![在ens33网口上监听并将数据包显示到屏幕上](https://github.com/shuailw/mytcpdump/blob/master/test/2.png)
 
 ## 测试
 
 1. 首先打开Tcpdump,让其在`lo`网卡上监听流量, 并把捕获的流量显示在屏幕上
 `./Tcpdump -i lo -v -f "not host 127.0.0.1`

 2. 然后使用`tcpreplay`命令, 可以将pcap文件回放到某个网卡上
 例如, 回放test/arp.pcapng到`lo`环回网卡上, -M参数指定回放数据包的速率(Mbps), -l参数指定回放pcap文件的次数
 ```
 tcpreplay -i lo -M 10 ./test/arp.pcapng`
 ```
 
 ![测试](https://github.com/shuailw/mytcpdump/blob/master/test/1.png)
 ## TODO
 1. 支持更多的tcpdump选项
 2. bug修复
 3. 更多类型的协议解析
 4. libpcap抓包性能不佳, 将底层的数据包捕获模块替换成`PF_RING`或者`dpdk`等
 
 
 
