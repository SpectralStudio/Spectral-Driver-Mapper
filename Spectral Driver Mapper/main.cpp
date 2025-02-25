#include "Windows.h"
#include "bsmi.h"
#include <string>
#include <chrono>

#define READ_CTLCODE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x539, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WRITE_CTLCODE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x540, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ATTACH_CTLCODE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x541, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SHUTDOWN_CTLCODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x542, METHOD_BUFFERED, FILE_ANY_ACCESS) 

// shalom I love high interest compound loans and money
HANDLE driver_ioctl_handle;

std::wstring generate_random_driver_name()
{
    static bool seeded = (srand(std::chrono::system_clock::now().time_since_epoch().count()), true);

    const std::wstring chars = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int length = rand() % 20 + 10;
    std::wstring driver_name;

    for (int i = 0; i < length; ++i) {
        driver_name += chars[rand() % chars.size()];
    }

    return driver_name; 
}

bool open_communication()
{
    driver_ioctl_handle = CreateFileA("\\\\.\\BSMI", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    


	return (driver_ioctl_handle != INVALID_HANDLE_VALUE);
}

void MmGetPhysicalAddressCTL()
{
    BOOL success = DeviceIoControl(driver_ioctl_handle, 3, 0, sizeof(0), 0, 0, nullptr, nullptr);
}

void main()
{
    printf("[+] SPECTRAL DRIVER MAPPER LOADED!\n");

    std::wstring driver_name = generate_random_driver_name();


    if (!bsmi_load(driver_name)) 
    {
        printf("[!] FAILED TO LOAD DRIVER!\n");
    }

    bool com = open_communication();

    if (!com)
    {
        printf("[!] FAILED TO OPEN COMMUNICATION TO DRIVER\n");
    }

    if (!bsmi_unload(driver_name ))
    {
        printf("[!] FAILED TO UNLOAD DRIVER\n");
    }
	
    system("pause");
}