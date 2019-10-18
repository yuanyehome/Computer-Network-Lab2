# Part 1测试说明
- 执行make，得到可执行文件test；
- 将test复制到vnetUtils/helper目录下；
- 建立examples中的虚拟网络；
- 进入vnetUtils/helper，在两个shell中分别执行sudo ./execNS vnetNS1 sudo ./test, sudo ./execNS2 sudo ./test即可看到两个host互相收发包的结果；
- 测试程序目前每五秒每个hosts的每个设备发一次包
