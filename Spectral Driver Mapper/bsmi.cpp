#include "bsmi.h"
#include <ctime>
#include <string>
#include <chrono>
#include <Windows.h>
#include <winternl.h>

#ifdef _DEBUG
#define SPECTRAL_DEBUG
#endif

typedef NTSTATUS(*NtLoadDriverT)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*NtUnloadDriverT)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(*RtlAdjustPrivilegeT)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);



bool IsRunning() {
    const HANDLE file_handle = CreateFileW(L"\\\\.\\BSMI", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file_handle);
        return true;
    }
    return false;
}

bool RegisterAndStart(const std::wstring& driver_path, const std::wstring& driver_name) {
    const static DWORD ServiceTypeKernel = 1;
    const static DWORD ErrorControl = 1;
    const static DWORD Start = 1;
    const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
    const std::wstring nPath = L"\\??\\" + driver_path;

    HKEY dservice;
    LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
    if (status != ERROR_SUCCESS) {
        printf("[-] Can't create service key\n");
        return false;
    }

    status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(dservice);
        printf("[-] Can't create 'ImagePath' registry value\n");
        return false;
    }

    status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(dservice);
        printf("[-] Can't create 'Type' registry value\n");
        return false;
    }


    status = RegSetKeyValueW(dservice, NULL, L"ErrorControl", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(dservice);
        printf("[-] Can't create 'ErrorControl' registry value\n");
        return false;
    }


    status = RegSetKeyValueW(dservice, NULL, L"Start", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
    if (status != ERROR_SUCCESS) {
        RegCloseKey(dservice);
        printf("[-] Can't create 'Start' registry value\n");
        return false;
    }

    RegCloseKey(dservice);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }

    auto RtlAdjustPrivilege = (RtlAdjustPrivilegeT)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    auto NtLoadDriver = (NtLoadDriverT)GetProcAddress(ntdll, "NtLoadDriver");

    ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
    BOOLEAN SeLoadDriverWasEnabled;
    NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
    if (!NT_SUCCESS(Status)) {
        printf("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
        return false;
    }

    std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
    UNICODE_STRING serviceStr;
    RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

    Status = NtLoadDriver(&serviceStr);

    printf("[+] NtLoadDriver Status 0x%p\n", Status);

    if (Status == 0xC0000603) { //STATUS_IMAGE_CERT_REVOKED
        printf("[-] Your vulnerable driver list is enabled and have blocked the driver loading, you must disable vulnerable driver list to use kdmapper with intel driver\n");
        printf("[-] Registry path to disable vulnerable driver list: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\n");
        printf("[-] Set 'VulnerableDriverBlocklistEnable' as dword to 0\n");
    }
    else if (Status == 0xC0000022 || Status == 0xC000009A) { //STATUS_ACCESS_DENIED and STATUS_INSUFFICIENT_RESOURCES
        printf("[-] Access Denied or Insufficient Resources (0x%p), Probably some anticheat or antivirus running blocking the load of vulnerable driver\n", Status);
    }

    //Never should occur since kdmapper checks for "IsRunning" driver before
    if (Status == 0xC000010E) { // STATUS_IMAGE_ALREADY_LOADED
        return true;
    }

    return NT_SUCCESS(Status);
}

bool StopAndRemove(const std::wstring& driver_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL)
        return false;

    std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
    UNICODE_STRING serviceStr;
    RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

    HKEY driver_service;
    std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
    LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            return true;
        }
        return false;
    }
    RegCloseKey(driver_service);

    auto RtlAdjustPrivilege = (RtlAdjustPrivilegeT)GetProcAddress(ntdll, "RtlAdjustPrivilege");

    ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
    BOOLEAN SeLoadDriverWasEnabled;
    NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
    if (!NT_SUCCESS(Status)) {
        printf("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n");
        return false;
    }

    auto NtUnloadDriver = (NtUnloadDriverT)GetProcAddress(ntdll, "NtUnloadDriver");
    NTSTATUS st = NtUnloadDriver(&serviceStr);
    printf("[+] NtUnloadDriver Status 0x%p\n", st);
    if (st != 0x0) {
        printf("[-] Driver Unload Failed!!\n");
        status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
        return false; //lets consider unload fail as error because can cause problems with anti cheats later
    }


    status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
    if (status != ERROR_SUCCESS) {
        return false;
    }
    return true;
}

BOOL RegisterDriverService(const std::wstring& serviceName, const std::wstring& driverPath) {
    // Open a handle to the Service Control Manager (SCM)
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (scmHandle == nullptr) {
        printf("SCM MANAGER FAILED RAHH\n");
        return FALSE;
    }

    // Create the service in the SCM
    SC_HANDLE serviceHandle = CreateService(
        scmHandle,               // SCM handle
        serviceName.c_str(),     // Name of the service
        serviceName.c_str(),     // Display name of the service
        SERVICE_ALL_ACCESS,      // Access to service
        SERVICE_KERNEL_DRIVER,   // Service type (Kernel driver)
        SERVICE_DEMAND_START,    // Service start type (Demand Start)
        SERVICE_ERROR_NORMAL,    // Error control
        driverPath.c_str(),     // Path to the driver executable
        nullptr,                 // No load ordering group
        nullptr,                 // No tag ID
        nullptr,                 // No dependencies
        nullptr,                 // No account name
        nullptr                  // No password
    );

    if (serviceHandle == nullptr) {
        CloseServiceHandle(scmHandle);
        printf("SERVICE HANDLE NULL PTR %d\n", GetLastError());
        return FALSE;
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return TRUE;
}

BOOL DeleteDriverService(const std::wstring& serviceName) {
    // Open a handle to the Service Control Manager (SCM)
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scmHandle == nullptr) {
        return FALSE;
    }

    // Open the service handle
    SC_HANDLE serviceHandle = OpenService(scmHandle, serviceName.c_str(), DELETE);
    if (serviceHandle == nullptr) {
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    // Delete the service
    if (!DeleteService(serviceHandle)) {
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return TRUE;
}



bool bsmi_load(std::wstring name)
{
    return (RegisterDriverService(name, L"C:\\BSMI.sys") && RegisterAndStart(L"C:\\BSMI.sys", name));
};


bool bsmi_unload(std::wstring name)
{
    return (StopAndRemove(name) && DeleteDriverService(name));
};

bool bsmi_isrunning()
{
    return IsRunning();
}