# Hidden Process Detection

This proof-of-concept demonstrates a user-mode technique for detecting hidden processes on Windows by leveraging NtQuerySystemInformation. The idea behind this project is simple: by comparing the standard process list with the PIDs obtained from enumerating all open handles, we can detect discrepancies that may indicate malicious process hiding.

## How It Works

Every running process in Windows is represented by an internal EPROCESS structure that is linked together in a doubly linked list (used by tools like Task Manager). Meanwhile, every open handle on the system is associated with a PID. In this project, we perform two separate enumerations:

- **Process Enumeration:** We use `NtQuerySystemInformation` with `SystemProcessInformation` to obtain the active list of processes.
- **Handle Enumeration:** We call `NtQuerySystemInformation` with `SystemExtendedHandleInformation` to collect all open handles and find their corresponding PIDs.

By comparing the set of PIDs from the handle table against those in the active process list, any PID found only in the handle enumeration suggests that its process may have been unlinked (hidden) from the normal process list, which is a common technique used by rootkits and malware authors.

## Disclaimer

This proof-of-concept is provided strictly for educational purposes. It demonstrates a method to detect processes that have been unlinked from the standard process list. Please note that the technique depends on NtQuerySystemInformation returning unaltered data. If NtQuerySystemInformation was hooked, the detection mechanism will not work.
