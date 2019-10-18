# Lab 2 Part 1代码列表
- DEBUG.h: 定义dbg_printf宏；
- device.h: 定义了Device类和DeviceManager类；
- device.cpp: 主要实现Device类的函数，包含构造函数，析构函数等等；在构造函数中包含了构造新线程执行pcap_loop接收packet；
- packetio.cpp：主要实现send和myOnReceive函数