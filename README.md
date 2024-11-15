A high-performance shared memory buffer driver compatible with Windows 11+ on modern x86-64 CPUs, designed for kernel reverse engineering, memory manipulation, and basic external operations. The driver features an intuitive EDK, organized for a wide range of use cases.

Key Features:

**Root Logger**: Robust kernel debugging with a Root Logger, allowing event logging to user mode even on anti-cheat systems (e.g., EAC EOS) that hook DbgPrintEx.
**Trace Flushing**: Ensures seamless cleanup of traces and system modifications, including those left by the mapper, after user-mode exit or failure.
**Thread Hiding**: Hides the communication thread by creating a gadget, unlinking, removing it from the CID table, and cloning attributes from a legitimate system thread.
**NMI Data Spoofing**: Employs an NMI callback to spoof communication thread data, preventing anti-cheats from stack-walking the thread and identifying the driver in PsLoadedDriverList.
**Page Table (PT) Manager**: Features advanced PT operations, including walking and caching entries, and finding free entries for page mapping, critical for injection tasks.
We have decided to publish this source since it fell into wrong hands, compromising its exclusivity.

credits: leproxy, neox, vmstruct
