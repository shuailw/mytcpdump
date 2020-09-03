Tcpdump : util.h ip.h tcp.h link_ether.h packet_capture.h main.cpp options.h udp.h 
	g++ util.h options.h  ip.h tcp.h  udp.h link_ether.h packet_capture.h main.cpp -lnet -lpcap -g -std=c++11 -o Tcpdump -fpermissive 
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
	export LD_LIBRARY_PATH
clear :
	\rm ./Tcpdump;
