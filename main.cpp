#include "utils.h"

int main() {

    // Load NtQuerySystemInformation dynamically
    PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        std::cerr << "Failed to locate NtQuerySystemInformation." << std::endl;
        return 1;
    }

    PVOID processBuffer = nullptr;
    NTSTATUS status;
    ULONG returnLength = 0;

    // Retrieve the standard process list
    do {
        processBuffer = VirtualAlloc(NULL, processBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!processBuffer) {
            std::cerr << "Failed to allocate process buffer." << std::endl;
            return 1;
        }
        status = NtQuerySystemInformation(SystemProcessInformation, processBuffer, processBufferSize, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(processBuffer, 0, MEM_RELEASE);

            // increase buffer size and retry
            processBufferSize = returnLength + 0x1000;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(status)) {
        std::cerr << "NtQuerySystemInformation(SystemProcessInformation) failed with " << status << std::endl;
        if (processBuffer)
            VirtualFree(processBuffer, 0, MEM_RELEASE);
        return 1;
    }

    // Parse the process list and record unique PIDs
    std::unordered_set<ULONG_PTR> processPIDs;
    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)processBuffer;
    while (true) {
        ULONG_PTR pid = (ULONG_PTR)spi->UniqueProcessId;
        processPIDs.insert(pid);
        if (spi->NextEntryOffset == 0)
            break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
    }
    VirtualFree(processBuffer, 0, MEM_RELEASE);

    PVOID handleBuffer = nullptr;

    // Retrieve the handle list using SystemExtendedHandleInformation
    do {
        handleBuffer = VirtualAlloc(NULL, handleBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!handleBuffer) {
            std::cerr << "Failed to allocate handle buffer." << std::endl;
            return 1;
        }
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleBuffer, handleBufferSize, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(handleBuffer, 0, MEM_RELEASE);

            // increase buffer size and retry
            handleBufferSize = returnLength + 0x1000; 
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(status)) {
        std::cerr << "NtQuerySystemInformation(SystemExtendedHandleInformation) failed with " << status << std::endl;
        if (handleBuffer)
            VirtualFree(handleBuffer, 0, MEM_RELEASE);
        return 1;
    }

    // Parse the handle list and save unique PIDs owning at least one handle
    std::unordered_set<ULONG_PTR> handlePIDs;
    PSYSTEM_HANDLE_INFORMATION_EX shi = (PSYSTEM_HANDLE_INFORMATION_EX)handleBuffer;
    ULONG_PTR handleCount = shi->NumberOfHandles;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = shi->Handles;
    for (ULONG_PTR i = 0; i < handleCount; i++) {
        ULONG_PTR pid = handleEntry[i].UniqueProcessId;
        handlePIDs.insert(pid);
    }
    VirtualFree(handleBuffer, 0, MEM_RELEASE);

    // Compare the sets
    std::cout << "Suspicious PIDs:" << std::endl;
    bool foundSuspicious = false;
    for (auto pid : handlePIDs) {
        if (processPIDs.find(pid) == processPIDs.end()) {
            std::cout << "PID: " << pid << std::endl;
            foundSuspicious = true;
        }
    }
    if (!foundSuspicious) {
        std::cout << "No suspicious process IDs found." << std::endl;
    }

    return 0;
}