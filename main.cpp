#include "utils.h"
#include <future>

// Function to query process PIDs from the system
std::unordered_set<ULONG_PTR> queryProcessPIDs(PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation) {
    PVOID processBuffer = nullptr;
    NTSTATUS status;
    ULONG returnLength = 0;
    ULONG bufferSize = processBufferSize;

    // Keep resizing buffer until it fits all process info or an error occurs
    do {
        processBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!processBuffer) {
            throw std::runtime_error("Failed to allocate process buffer.");
        }
        status = NtQuerySystemInformation(SystemProcessInformation, processBuffer, bufferSize, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(processBuffer, 0, MEM_RELEASE);
            bufferSize = returnLength + 0x1000; // Increase size with some padding
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        if (processBuffer) VirtualFree(processBuffer, 0, MEM_RELEASE);
        throw std::runtime_error("NtQuerySystemInformation(SystemProcessInformation) failed.");
    }

    // Parse process info into a set of unique PIDs
    std::unordered_set<ULONG_PTR> processPIDs;
    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)processBuffer;
    while (true) {
        ULONG_PTR pid = (ULONG_PTR)spi->UniqueProcessId;
        processPIDs.insert(pid);
        if (spi->NextEntryOffset == 0) break; // End of list
        spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset); // Move to next entry
    }
    VirtualFree(processBuffer, 0, MEM_RELEASE);
    return processPIDs;
}

// Function to query PIDs that own handles from the system
std::unordered_set<ULONG_PTR> queryHandlePIDs(PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation) {
    PVOID handleBuffer = nullptr;
    NTSTATUS status;
    ULONG returnLength = 0;
    ULONG bufferSize = handleBufferSize;

    // Allocate and resize buffer until it fits all handle info
    do {
        handleBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!handleBuffer) {
            throw std::runtime_error("Failed to allocate handle buffer.");
        }
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleBuffer, bufferSize, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(handleBuffer, 0, MEM_RELEASE);
            bufferSize = returnLength + 0x1000; // Add padding to suggested size
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        if (handleBuffer) VirtualFree(handleBuffer, 0, MEM_RELEASE);
        throw std::runtime_error("NtQuerySystemInformation(SystemExtendedHandleInformation) failed.");
    }

    // Extract unique PIDs from handle information
    std::unordered_set<ULONG_PTR> handlePIDs;
    PSYSTEM_HANDLE_INFORMATION_EX shi = (PSYSTEM_HANDLE_INFORMATION_EX)handleBuffer;
    ULONG_PTR handleCount = shi->NumberOfHandles;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = shi->Handles;
    for (ULONG_PTR i = 0; i < handleCount; i++) {
        ULONG_PTR pid = handleEntry[i].UniqueProcessId;
        handlePIDs.insert(pid); // Add PID if it owns a handle
    }
    VirtualFree(handleBuffer, 0, MEM_RELEASE);
    return handlePIDs;
}

int main() {
    // Load NtQuerySystemInformation dynamically from ntdll.dll
    PFN_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation =
        (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        std::cerr << "Failed to locate NtQuerySystemInformation." << std::endl;
        return 1;
    }

    try {
        // Thread 1: "PreHandleProcessScanner" - Scans processes just before handle query
        auto preHandleFuture = std::async(std::launch::async, queryProcessPIDs, NtQuerySystemInformation);

        // Main Thread: Query handle-owning PIDs while PreHandleProcessScanner runs
        auto handlePIDs = queryHandlePIDs(NtQuerySystemInformation);

        // Retrieve results from PreHandleProcessScanner
        auto preHandleProcessPIDs = preHandleFuture.get();

        // Thread 2: "PostHandleProcessScanner" - Scans processes just after handle query
        auto postHandleFuture = std::async(std::launch::async, queryProcessPIDs, NtQuerySystemInformation);

        // Retrieve results from PostHandleProcessScanner
        auto postHandleProcessPIDs = postHandleFuture.get();

        // Combine PIDs from both process scans to account for processes around handle query time
        std::unordered_set<ULONG_PTR> validPIDs = preHandleProcessPIDs;
        validPIDs.insert(postHandleProcessPIDs.begin(), postHandleProcessPIDs.end()); // Union of both sets

        // Identify suspicious PIDs: those in handlePIDs but not in either process scan
        std::cout << "Suspicious PIDs:" << std::endl;
        bool foundSuspicious = false;
        for (auto pid : handlePIDs) {
            if (validPIDs.find(pid) == validPIDs.end()) {
                std::cout << "PID: " << pid << std::endl;
                foundSuspicious = true;
            }
        }
        if (!foundSuspicious) {
            std::cout << "No suspicious process IDs found." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
