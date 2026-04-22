---
title: "Mastering Process Injections: DLL Injections I"
description: "Understanding DLL injections from a traditional perspective."
date: 2026-04-22
tags: ["DLL Injections", "Process Injections", "Reverse Engineering", "Malware Analysis"]
---

Hi everyone, and welcome to my first blog entry.

My name is Iván, I'm a Telecommunications Engineering student and an aspiring cybersecurity professional. I'll use this blog to document my research, projects, and my learning path in the cybersecurity world.

In this first post I'll be covering one of the most famous techniques in Windows environments: DLL injection. Given how huge this topic is, I want to build a series exploring different injection methods, detection techniques, and real-world cases. This first part focuses on one of the most well-known approaches — the CreateRemoteThread method and some of its variations. Let's get into it.

# 1. What Is DLL Injection?

At its core, DLL injection is a technique where a process forces a separate, already-running process to load an arbitrary Dynamic-Link Library (DLL). There are two key points to this method: the first is that, instead of running the malicious code as a standalone process — which could trigger process-based defenses — the code runs directly within the allocated memory of a legitimate one. The second is that using DLLs instead of shellcode or other primitives gives attackers an important advantage in terms of code reusability and direct access to the Windows API of the host process.

<img src="/images/Image-1.png" alt="Image-1.png" width="638" height="340">

The picture above shows the before and after of a legitimate process when a DLL injection is performed. The malicious DLL gets allocated in the target process's virtual memory space and spawns a thread that inherits its full security context, meaning the injected code doesn't run in isolation, but directly within the target's address space, with access to its privileges, handles, and security tokens. In practice, this allows attackers to execute malicious code through a legitimate process, making it considerably less suspicious than a standalone process that has no business running in the first place.

# 2. A Classic Approach: The CreateRemoteThread Method
CreateRemoteThread (CRT) is the Win32 API function that the entire method is built around. As the name suggests, it allows a process to create a thread in the address space of another. This is exactly where what we covered in the previous section becomes relevant: by spawning a thread inside a legitimate process, the injector can force it to load and execute a malicious DLL without ever appearing as a suspicious standalone process.

At a high level, the workflow for this methodology is the following:

1. Obtaining a handle to the target process
2. Allocating memory within the target's address space
3. Writing the path of the malicious DLL into that allocated region
4. Spawning a remote thread to force the loading of the DLL

As mentioned, CreateRemoteThread is a native Win32 API function, and what makes this method interesting is that every step in the workflow above can be carried out exclusively using Win32 API calls. At this point I recommend checking out an implementation of this technique that I published on GitHub ([Link](https://github.com/ivancedo/DLLInjector)). Let's go through each step.

#### **Step 1: Gaining Process Access**
The procedure begins with `OpenProcess()`, which returns a handle to the target process. This isn't trivial — the injector must request specific access rights: `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, and `PROCESS_VM_WRITE`. These permissions are prerequisites for everything that follows. If the injector doesn't have the required permissions — for example, when attempting to access a SYSTEM process — the call will fail here before anything else happens.

#### **Step 2: Memory Allocation**
With a valid handle in hand, the injector calls `VirtualAllocEx()` to reserve a region inside the target process's virtual memory. The region only needs to be large enough to hold the full path of the DLL. Memory protection is typically set to `PAGE_READWRITE` — at this stage, we're just writing a string, not executing code.

#### **Step 3: Writing the DLL Path**
`WriteProcessMemory()` copies the DLL path from the injector's address space into the buffer allocated in the previous step. The accuracy of this string matters — it will be passed directly to `LoadLibraryA()` in the next step, so any error in the path, whether a missing character or a wrong directory, will cause an error during thread execution.

#### **Step 4: Remote Thread Creation and Execution**
This is where the injection actually fires, and the step that gives the method its name. The injector calls `CreateRemoteThread()`, specifying `LoadLibraryA()` — which lives in `kernel32.dll` — as the thread's entry point, and the address of the previously written DLL path as its argument. When the new thread initializes inside the target process, it calls `LoadLibraryA()`, maps the DLL into memory, and executes `DllMain`. At that point, the attacker has code running inside the target's context.

# 3. Beyond the Win32 API: Evading EDR at the Native Layer
The functions we've covered so far are all part of the Win32 API, but that's only one layer of the picture. The Win32 API should be understood as an abstraction layer — when a process calls `CreateRemoteThread()`, the call doesn't go directly to the kernel. Instead, it travels through a chain of wrappers that eventually resolves to `NtCreateThreadEx()`, exported by `ntdll.dll`. This indirection is precisely where EDRs plant their hooks.

By calling `NtCreateThreadEx()` directly — resolving it at runtime via `GetProcAddress()` or by walking the PEB to parse `ntdll`'s Export Address Table manually — an attacker skips the monitored Win32 wrappers entirely, producing a different call signature that many user-mode EDR sensors miss.

This forces defenders to move instrumentation deeper: kernel callbacks and ETW providers are two common options. Detection of this technique, especially when obfuscation comes into play, is a topic large enough to deserve its own post, so I'll leave that for later in the series.

# 4. Case Study: BadHatch
To close this post, let's look at a real-world implementation of everything discussed above. BadHatch is a backdoor attributed to FIN8 — a financially motivated threat actor that has been conducting targeted intrusions since at least 2019. The decompiled function below comes from a BadHatch sample (SHA256: `32863daa615afbb3e90e3dad35ad47199050333a2aaed57e5065131344206fe1`) and shows the full CRT injection chain condensed into a single routine.

<img src="/images/Image-2.png" alt="Image-1.png" width="638" height="340">

As you can see in the picture, I placed four markers to show where each step of the chain lands in the actual code. There are other details worth pointing out that I left unmarked though. Before the CRT chain begins, the function calls `RtlAdjustPrivilege` to enable `SeDebugPrivilege`, which is what allows `OpenProcess` to work against processes outside the current user's session. From there the injection follows the familiar sequence: `OpenProcess` (1) acquires a handle to the target process, `VirtualAllocEx` (2) reserves a region in its memory, and `WriteProcessMemory` (3) deposits the DLL path into that memory region. Before moving on to thread creation, the sample also calls `IsWow64Process` and aborts if the target turns out to be a WoW64 process — injecting a mismatched-bitness DLL produces an immediate crash, so this is a hard requirement rather than an optional check.

The thread creation step is where things get interesting. Instead of calling `CreateRemoteThread`, the sample uses `RtlCreateUserThread` (4) — exactly what we talked about in section 3 — bypassing the Win32 layer where most user-mode EDR hooks are planted. There is also a neat memory management detail: rather than allocating the target region as executable from the start, the sample first allocates it as writable, writes the payload, and only then calls `VirtualProtectEx` to flip the permissions to `PAGE_EXECUTE_READWRITE`. Allocating RWX memory upfront is a well-known behavioral indicator that many security tools flag, and this two-phase approach avoids triggering those detections cleanly.

That's everything for today. In the next entry in this series, I'll be looking at detection techniques for this type of procedure and bringing some experiments along with it. 

Thanks for reading :)