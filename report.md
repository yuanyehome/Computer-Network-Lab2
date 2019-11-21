# Lab2 Part3 报告

> 袁野
>
> 1700012821

- 处理TCP状态改变：
  - 我通过一个`DFA`的namespace来记录每一个`fd`当前的状态。
  - 当有一个新的packet到来时，在`TCP_handler`函数内做分发，决定该做什么处理。
  - 建立连接时
    - 主动端发送`SYN`，并进入`wait`函数等待对面的`SYN/ACK`返回，一旦受到返回立刻回复`ACK`，并解除阻塞，同时将自己的状态转为`ESTAB`；
    - 被动端收到一个`SYN`包时，首先判断有没有相应的`fd`在监听状态，如果有则压入其缓存队列中，如果没有则不理会；
    - 被动端调用`accept`函数时会试图从缓存队列中取出一个task并回复`SYN/ACK`并进入阻塞等待，如果队列为空则也进入阻塞等待队列有元素进入；
  - 读写：
    - `read`：为每一个建立了的连接建立一个读取缓冲区，当新进入一个包时优先进入缓冲区，在`read`时，如果缓冲区内容不足读取字节数，那么陷入等待，直到缓冲区内容足够为之；
    - `write`：直接发包并进入`wait`等待`ACK`；
  - 关闭连接时：
    - 主动端发送`FIN`并等待`ACK`；
    - 被动端收到`FIN`后立即回复`ACK`；
    - 未考虑不显式调用`close`函数的情况，即两端必须显式调用`close`函数结束自己的连接；
- 保持数据字节序：
  - 对hdr中赋值的所有大于1字节的部分都调用`htons`和`htonl`做字节序转换；
- 未实现部分：
  - 关于`RST`情况的判断与处理；
  - 关于`read`与`write`函数的测试；
  - 库打桩；
- 三次握手测试（两端都是自己的协议栈）：
  - `cd code; mkdir build`
  - `cmake ..; make clean; make`
  - 启动`vnetvtils`，建立两个虚拟网络`ns1, ns2`，通过`bypassKernel`和`bypassarp.sh`关闭`TCP/IP`和`ARP`协议栈（NOTE: 需要下载arptable: `sudo apt install arptables`）
  - 在一端启动`test_handshake`，另一端启动`test_connect`