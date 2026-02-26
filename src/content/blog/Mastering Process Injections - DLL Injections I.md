---
title: "Mastering Process Injections - DLL Injections I"
description: "Understanding DLL injection from a traditional perspective."
date: 2025-02-26
tags: ["DLL Injections", "Process Injections"]
---


Hi everyone, and welcome to my first post.

My name is Iván, I'm a Telecommunications Engineering student and an aspiring cybersecurity professional. In this blog I'll be exploring technical cybersecurity topics with a practical and analytical approach.

I want to begin with one of the classic techniques used for privilege escalation and defense evasion: process injection. In this first part of the series, I'll explain how DLL injection is typically performed, walk through a real-world malware sample that uses it, and close with detection strategies from a defensive perspective.

# 1\. What is DLL Injection?

DLL injection is a specialized code injection technique where a process — the injector — compels a remote running process — the target — to load a Dynamic-Link Library (DLL). Instead of dropping and executing a standalone malicious binary, the attacker hijacks an existing process to host the payload inside it.

The fundamental concept here is execution context. When the target process loads the library, the injected code doesn't run in isolation — it executes within the target's virtual address space, inheriting its privileges, handles, and security tokens. In practice, this means malicious logic can operate under the guise of a legitimate process, significantly reducing its forensic footprint and bypassing basic security controls.

<img src="/images/Image-1.png" alt="Image-1.png" width="638" height="340" class="jop-noMdConv">

This is why DLL injection is such a recurring primitive in privilege escalation, persistence, and defense evasion. By blending into trusted system activity rather than appearing as a suspicious new process, the attacker makes the defender's job considerably harder — the resulting behavior appears to originate from a verified application, not from the malware itself.

# 2\. The Classic DLL Injection: The CreateRemoteThread Method

The CreateRemoteThread (CRT) method is perhaps the most documented and widely implemented injection technique on Windows. Its effectiveness doesn't come from exploiting a memory corruption vulnerability — it comes from weaponizing standard, documented Win32 API calls. The operating system's own functionality becomes the attack primitive.

At a high level, the workflow consists of four steps:

1.  Obtaining a handle to the target process
2.  Allocating memory within the target's address space
3.  Writing the path of the malicious DLL into that allocated region
4.  Spawning a remote thread to force the loading of the DLL

### Step 1: Gaining Process Access

The procedure begins with `OpenProcess()`, which returns a handle to the target. This isn't trivial — the injector must request specific access rights: `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, and `PROCESS_VM_WRITE`. These permissions are prerequisites for everything that follows. If the injector is running at medium integrity and attempts to target a SYSTEM-level process, the call will fail here before anything else happens.

### Step 2: Memory Allocation

With a valid handle in hand, the injector calls `VirtualAllocEx()` to reserve a region inside the target's virtual memory. The region only needs to be large enough to hold the full filesystem path of the DLL. Memory protection is typically set to `PAGE_READWRITE` — at this stage, we're just writing a string, not executing code.

### Step 3: Writing the DLL Path

`WriteProcessMemory()` copies the DLL path from the injector's address space into the buffer we just allocated in the target. The accuracy of this string matters. It will be passed directly to `LoadLibraryA()` in the next step, so any error in the path — a missing character, a wrong directory — will either cause a silent failure or surface as an error during thread execution.

### Step 4: Remote Thread Creation and Execution

This is where the injection actually fires. The injector calls `CreateRemoteThread()`, specifying `LoadLibraryA()` — which lives in `kernel32.dll` — as the thread's entry point, and the address of the previously written DLL path as its argument. When the new thread initializes inside the target process, it calls `LoadLibraryA()`, maps the DLL into memory, and executes `DllMain`. At that point, the attacker has code running inside the target's context.

A working, educational implementation of this technique is available in my GitHub repository: [github.com/ivancedo/DLLInjector](https://github.com/ivancedo/DLLInjector). The project simulates the full procedure in a controlled environment.

# 3\. Beyond the Win32 API: Evading EDR Telemetry at the Native Layer

The Win32 API is fundamentally an abstraction layer. When you call `CreateRemoteThread()`, the call doesn't go directly to the kernel — it travels through a chain of wrappers that eventually resolves to `NtCreateThreadEx()`, exported by `ntdll.dll`. This indirection is precisely where EDRs plant their hooks.

User-mode EDR hooks work by patching the first few bytes of monitored Win32 functions with a jump instruction that redirects execution to the vendor's inspection routine before the original code runs. This is known as inline hooking or trampolining. The problem for defenders is structural: these hooks live entirely in user space, which means they can be bypassed.

By calling `NtCreateThreadEx()` directly — resolving it at runtime via `GetProcAddress()` or by walking the PEB to parse `ntdll`'s Export Address Table manually — an attacker skips the hooked Win32 wrapper entirely, producing a different call stack signature that many user-mode sensors miss. `RtlCreateRemoteThread()` achieves a similar result through a slightly different code path.

This forces defenders to move instrumentation deeper: kernel callbacks registered via `PsSetCreateThreadNotifyRoutine()`, or ETW providers like `Microsoft-Windows-Threat-Intelligence`, which operates at a level that user-mode tampering cannot reach. The pattern is consistent across the offensive-defensive landscape — every time attackers descend a layer, defenders must follow. Understanding where your telemetry sits in that stack is not optional; it determines what you can and cannot see.

# 4\. Case Study: BadHatch

BadHatch is a backdoor attributed to the FIN8 threat group, observed in operations since at least 2019. It has been deployed in targeted intrusions against organizations in the insurance, retail, technology, and chemical sectors across the United States, Canada, South Africa, Panama, and Italy — making it a useful real-world reference for the techniques discussed above.

I analyzed a BadHatch sample that implements the CRT method directly. A few implementation details stand out as representative of how professional malware handles this technique, beyond the textbook version. In the

<img src="/images/Image-2.png" alt="Image-2.png" width="757" height="456">

First, API functions are never imported transparently. Instead, BadHatch uses dynamic symbol resolution — calling `GetProcAddress()` and `LoadLibrary()` at runtime to locate the functions it needs. This obscures the import table and complicates static analysis.

Second, before attempting injection, the sample calls `IsWow64Process()` to validate the target's architecture. This is a practical necessity: injecting a 32-bit DLL into a 64-bit process, or vice versa, will cause an immediate crash. Real-world tooling handles this check explicitly; skipping it is a common mistake in proof-of-concept implementations.

Third, and perhaps most interestingly, the sample calls `RtlAdjustPrivilege()` to programmatically enable `SeDebugPrivilege` before touching any other process. This privilege allows the process to interact with processes owned by other users, including SYSTEM — without it, `OpenProcess()` calls against high-integrity targets will fail. Legitimate software rarely needs this privilege, which makes it a useful behavioral indicator on its own.

# 5\. Detecting the CreateRemoteThread Method with Sysmon

In the previous sections, we broke the CRT technique into four primitives:

1.  `OpenProcess()`
2.  `VirtualAllocEx()`
3.  `WriteProcessMemory()`
4.  `CreateRemoteThread()` → `LoadLibraryA()`

From a defender's perspective, the question is straightforward: which of these steps generates observable telemetry, and at which layer?

Sysmon gives us three vantage points:

- **Event ID 8** — CreateRemoteThread
- **Event ID 10** — ProcessAccess
- **Event ID 7** — ImageLoad

Individually, each signal is noisy. Correlated, they reconstruct the injection chain almost completely.

Before getting into the rules, it's worth being explicit about the gaps. Steps 2 and 3 — `VirtualAllocEx()` and `WriteProcessMemory()` — produce no native Sysmon telemetry. Detecting remote memory allocation and writes requires kernel-level instrumentation, such as the `Microsoft-Windows-Threat-Intelligence` ETW provider consumed by commercial EDR kernel drivers. Sysmon cannot see these primitives. This isn't a configuration failure; it's an architectural boundary, and being honest about it matters when assessing your actual detection coverage.

### Event ID 10 — ProcessAccess: The Pre-Injection Indicator

Step 1 of the CRT chain requires the injector to open a handle to the target process with a specific set of access rights. Event ID 10 captures this handle request, making it the earliest observable signal in the chain — logged before any memory is touched or any thread is spawned.

The field to focus on is `GrantedAccess`. For CRT injection to succeed, the injector needs at minimum `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE`, which resolves to the access mask `0x42A`. Less careful tooling skips the minimum-rights approach entirely and just requests full access (`0x1fffff`), which is even louder. Both are worth catching.

```xml
<!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]-->
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">

        <!-- T1055.001 - Classic CRT injection access mask -->
        <!-- PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE = 0x42A -->
        <!-- Full access (0x1fffff) is requested by less careful tooling -->
        <GrantedAccess name="T1055.001,CRT-Injection-AccessMask" condition="is">0x1fffff</GrantedAccess>
        <GrantedAccess name="T1055.001,CRT-Injection-AccessMask" condition="is">0x1F0FFF</GrantedAccess>
        <GrantedAccess name="T1055.001,CRT-Injection-AccessMask" condition="is">0x42A</GrantedAccess>

        <!-- Targeting high-value processes specifically -->
        <TargetImage name="T1055,LSASS-Access" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
        <TargetImage name="T1055,HighValue-Target" condition="is">C:\Windows\system32\explorer.exe</TargetImage>

    </ProcessAccess>
</RuleGroup>

<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="exclude">
        <!-- Security tooling legitimately accesses many processes -->
        <SourceImage condition="begin with">C:\ProgramData\Microsoft\Windows Defender\Platform\</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\lsass.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\werfault.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\taskmgr.exe</SourceImage>
        <!-- Read-only access patterns pose no injection risk -->
        <GrantedAccess condition="is">0x1000</GrantedAccess> <!-- PROCESS_QUERY_LIMITED_INFORMATION -->
        <GrantedAccess condition="is">0x100000</GrantedAccess> <!-- SYNCHRONIZE only -->

    </ProcessAccess>
</RuleGroup>
```

One practical note: `0x42A` alone will produce some noise from legitimate debugging tools and software updaters. Before escalating an alert, correlate the source process path and its integrity level. The same access mask originating from a process in `C:\Users\` is a materially different situation than the same mask from a known security agent.

### Event ID 8 — CreateRemoteThread: The Injection Signature

This is the most direct signal in the chain. Event ID 8 fires when a process spawns a thread in another process's address space, capturing the source process, the target process, and — most usefully — the `StartAddress` and `StartFunction` of the new thread.

That last field is where the detection becomes precise. When the injector calls `CreateRemoteThread()` with `LoadLibraryA` as the entry point, Sysmon resolves the symbol and logs the function name. A remote thread whose start address resolves to `LoadLibraryA` or `LoadLibraryW` inside `kernel32.dll` is the canonical CRT injection signature — there are very few legitimate reasons for this to happen.

One important note about the default SwiftOnSecurity configuration: it blanket-excludes all events where `StartModule` is `kernel32.dll`. The intention is noise reduction, but the effect is that it silently suppresses exactly the signal we're looking for. The rules below replace that approach with a targeted include for `LoadLibrary` invocations, which is far more surgical.

```xml
<!--SYSMON EVENT ID 8 : REMOTE THREAD CREATED [CreateRemoteThread]-->
<RuleGroup name="" groupRelation="or">
    <CreateRemoteThread onmatch="include">

        <!-- T1055.001 - DLL Injection via LoadLibrary -->
        <!-- Thread entry point resolving to LoadLibraryA/W is the canonical CRT injection signature -->
        <StartFunction name="T1055.001,DLL-Injection" condition="contains">LoadLibrary</StartFunction>

        <!-- Thread starting in an anonymous memory region (no module backing) -->
        <!-- Indicates shellcode or reflective injection - StartModule field will be empty -->
        <StartModule name="T1055,Shellcode-Injection" condition="is"></StartModule>

        <!-- Remote threads targeting high-value processes regardless of start function -->
        <TargetImage name="T1055,HighValue-Target" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
        <TargetImage name="T1055,HighValue-Target" condition="is">C:\Windows\system32\explorer.exe</TargetImage>
        <TargetImage name="T1055,HighValue-Target" condition="is">C:\Windows\system32\svchost.exe</TargetImage>

    </CreateRemoteThread>
</RuleGroup>

<RuleGroup name="" groupRelation="or">
    <CreateRemoteThread onmatch="exclude">
        <!-- Legitimate Windows internals -->
        <SourceImage condition="is">C:\Windows\system32\wbem\WmiPrvSE.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\wininit.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\csrss.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\services.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\winlogon.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\audiodg.exe</SourceImage>
        <!-- Chrome renderer processes use CreateRemoteThread internally for legitimate purposes -->
        <SourceImage condition="begin with">C:\Program Files\Google\Chrome\Application\</SourceImage>
        <SourceImage condition="begin with">C:\Program Files (x86)\Google\Chrome\Application\</SourceImage>

        <!-- NOTE: svchost.exe is intentionally NOT excluded as a source.
             It is a common injection host in malware chains. Accept the noise and tune per environment. -->

    </CreateRemoteThread>
</RuleGroup>
```

The empty `StartModule` rule is worth calling out specifically. In classic CRT injection, the thread's start address points to `LoadLibraryA` inside a known, named module. In reflective DLL injection or shellcode injection, the thread starts executing from a manually allocated region with no backing module — so `StartModule` resolves to nothing. This single rule catches both the textbook technique and its more sophisticated variants.

### Event ID 7 — ImageLoad: The Payload Confirmation

If Event ID 10 is the pre-injection indicator and Event ID 8 is the injection signature, Event ID 7 is the confirmation: the DLL has been successfully mapped into the target process and is now executing. This event fires when `LoadLibraryA` completes, logging the loading process, the DLL's full path, its hash, and its signing status.

Event ID 7 is disabled by default in Sysmon because enabling it globally generates significant volume. The strategy here is surgical includes rather than a blanket capture — we focus on the load characteristics that actually indicate malicious activity.

```xml
<!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]-->
<!--NOTE: Enabling this section activates ImageLoad monitoring globally. 
    Deploy incrementally and baseline before enabling the Signed=false catch-all. -->
<RuleGroup name="" groupRelation="or">
    <ImageLoad onmatch="include">

        <!-- DLLs loaded from user-writable or temporary locations -->
        <!-- Legitimate software rarely loads DLLs from these paths -->
        <ImageLoaded name="T1055.001,Unsigned-DLL-UserPath" condition="begin with">C:\Users</ImageLoaded>
        <ImageLoaded name="T1055.001,Unsigned-DLL-Temp" condition="begin with">C:\Windows\Temp</ImageLoaded>
        <ImageLoaded name="T1055.001,Unsigned-DLL-ProgramData" condition="begin with">C:\ProgramData</ImageLoaded>

        <!-- AppData is a common staging location for dropped implants -->
        <ImageLoaded name="T1055.001,Suspicious-AppData" condition="contains">AppData\Local\Temp</ImageLoaded>
        <ImageLoaded name="T1055.001,Suspicious-AppData" condition="contains">AppData\Roaming</ImageLoaded>

        <!-- Unsigned image loads - highest volume, deploy last after baselining path-based rules -->
        <Signed name="T1055.001,Unsigned-Load" condition="is">false</Signed>

    </ImageLoad>
</RuleGroup>

<RuleGroup name="" groupRelation="or">
    <ImageLoad onmatch="exclude">
        <!-- Suppress .NET JIT and assembly loads which are unsigned by design -->
        <ImageLoaded condition="begin with">C:\Windows\assembly\</ImageLoaded>
        <ImageLoaded condition="begin with">C:\Windows\Microsoft.NET\</ImageLoaded>

        <!-- Exclude DLLs loaded from trusted system directories -->
        <ImageLoaded condition="begin with">C:\Windows\System32\</ImageLoaded>
        <ImageLoaded condition="begin with">C:\Windows\SysWOW64\</ImageLoaded>

        <!-- Suppress volume from known application directories -->
        <!-- Expand or remove per environment based on baseline -->
        <ImageLoaded condition="begin with">C:\Program Files\</ImageLoaded>
        <ImageLoaded condition="begin with">C:\Program Files (x86)\</ImageLoaded>

    </ImageLoad>
</RuleGroup>
```

The path-based rules are your highest-fidelity signal. An unsigned DLL loading from `C:\Users\` or `C:\Windows\Temp\` into a production process is a strong indicator regardless of what else you're seeing. The `Signed=false` catch-all is useful as a broader net, but in environments with third-party software that ships unsigned binaries, it will generate substantial volume — enable it last, only after the path-based rules have been baselined and your exclusions are stable.

### Correlating the CRT Chain

Each of these three events has analytical value on its own. But the real power comes from treating them as a sequence rather than independent alerts. A complete CRT injection will produce the following observable chain within a short time window:

1.  **Event ID 10** — Process A opens a handle to Process B with `GrantedAccess: 0x42A` or `0x1fffff`
2.  **Event ID 8** — Process A creates a remote thread in Process B with `StartFunction: LoadLibraryA`
3.  **Event ID 7** — Process B loads a DLL from an unsigned or anomalous path

Any one of these events in isolation might have a benign explanation. All three together, correlated by source process, target process, and timestamp, reconstruct the injection chain with high confidence. In a SIEM environment, a correlation rule combining all three — same source image, same target image, within a 30-second window — will produce very few false positives while reliably catching the full technique.

In fact, if you execute the code from my repository and configure Sysmon with the rules discussed above, this is what you will observe in the Windows Event Viewer (the highlighted events correspond to the injector process performing the DLL injection into the target process).

<img src="/images/Image-1.png" alt="Image-3.png" width="757" height="456">

### Operational Considerations

A few practical points before deploying these rules in production.

Event ID 7 will noticeably increase your log volume. Start with the path-based include rules, baseline for a week or two, then add the `Signed=false` catch-all once your exclusion list is stable. Rolling everything out at once without baselining will overwhelm analysts, and the rules will get disabled — which is the worst outcome you can have.

The access mask rules in Event ID 10 will generate some noise from debuggers, software updaters, and certain security agents. Rather than pre-emptively excluding broad categories of software, build your exclude list from the false positives you actually observe in your environment.

Finally, `svchost.exe` is intentionally left in scope as both a source and target. It is one of the most abused processes in malware injection chains, and excluding it creates a real blind spot. Keep it in scope, expect some noise, and correlate against other signals before acting on it.

### Defensive Depth and Evasion Considerations

Earlier in this post, we discussed how attackers can bypass user-mode EDR hooks by calling `NtCreateThreadEx()` directly instead of going through `CreateRemoteThread()`.

Sysmon is not affected by this evasion.

Because Sysmon relies on kernel callbacks and ETW rather than user-mode hooks, it observes thread creation regardless of whether the call originated from `CreateRemoteThread()` or `NtCreateThreadEx()`. Bypassing the Win32 wrapper changes the call stack — it does not change the kernel event.

This is the core lesson of this entire section: when attackers descend the API stack to evade user-mode instrumentation, defenders need telemetry that already operates below that layer. If your visibility depends entirely on user-mode hooks, native API calls are enough to blind you. If your telemetry is kernel-backed, the underlying primitive remains observable regardless of which API path was taken to get there.

That distinction is not a theoretical concern. It is the difference between a detection that survives adversarial pressure and one that doesn't.