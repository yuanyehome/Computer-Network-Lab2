#include "device.h"

DeviceManager::~DeviceManager()
{
    for (auto& dev : device_list) {
        delete dev;
    }
}

dev_ID DeviceManager::addDevice(const std::string& dev_name)
{
    try {
        for (auto& dev : device_list) {
            if (dev->name == dev_name) {
                return dev->id;
            }
        }
        char mac_[30];
        if (get_mac(mac_, 30, dev_name) < 0) {
            dbg_printf("\033[31m[ERROR]\033[0m [addDevice] GetMac failed! \n");
            return -1;
        }
        dbg_printf("\033[32m[INFO]\033[0m Mac of device %s is %s \n", dev_name.c_str(), mac_);
        const std::string mac(mac_);
        Device* new_dev = new Device(device_list.size(), dev_name, mac);
        device_list.push_back(new_dev);
        return new_dev->id;
    } catch (const char* err_msg) {
        dbg_printf("\033[31m[ERROR]\033[0m [addDevice] %s\n", err_msg);
        return -1;
    }
}

dev_ID DeviceManager::findDevice(const std::string& dev_name)
{
    for (auto& dev : device_list) {
        if (dev->name == dev_name) {
            return dev->id;
        }
    }
    dbg_printf("\033[31m[ERROR]\033[0m [findDevice] No such device in device_list! \n");
    return -1;
}

Device* DeviceManager::findDevice(const ip_addr src)
{
    for (auto& dev_ptr : device_list) {
        if (dev_ptr->dev_ip.s_addr == src.s_addr) {
            return dev_ptr;
        }
    }
    return NULL;
}