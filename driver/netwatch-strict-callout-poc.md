# NetWatch Strict Upload Driver

This directory contains the WDK/KMDF implementation and its acceptance gates. The driver now has the bounded per-group/global pending queue, asynchronous classify pend, IPv4/IPv6 transport reinjection pump, epoch/timeout checks, flow cancellation, live queued-byte accounting, and timer/DPC/unload cleanup. The current Release build passes the installed WDK compiler and Inf2Cat signability generation.

The driver deliberately still advertises capability mask zero. StrictService therefore creates the four dynamic WFP objects disabled and rejects enable requests. This is fail-closed until all acceptance evidence exists:

- install a Microsoft-accepted signed SYS/CAT package on a controlled Windows test machine;
- observe the real four WFP filters enabled and hit while exercising multiple IPv4/IPv6 TCP/UDP flows;
- run flow close, session replacement, service stop and driver unload races under Driver Verifier and collect Code Integrity/Verifier evidence;
- run the receiver-side dual-process scenarios from `tools\StrictThroughput` and compare baseline/limited runs using independent receiver byte counters.

`tools\build-strict-driver.ps1` is the fail-fast unsigned development build gate. `tools\strict-driver-signature.ps1` is a separate release handoff gate and rejects unsigned, test-signed or self-signed artifacts. `tools\strict-platform-status.ps1`, `tools\strict-driver-verifier.ps1`, and `tools\strict-driver-package.ps1` report or perform the explicitly requested machine operations; none of those install, reset, verifier-configuration, or security-policy-changing operations were run in this session.

`NetWatch.Core.Wfp.BlockManager` is a separate user-mode WFP manager for ALE block filters. It cannot delay, queue, or reinject packets.

The host harnesses remain intentionally narrower: they cover token-bucket math, queue bounds, ABI/layout and snapshot validation. They do not simulate kernel WFP callbacks, filter hits, packet injection, or Driver Verifier.

VPN, proxy, and tunnel traffic can only be attributed to the process visible at the WFP classify layer. The application must not claim that the original application is covered when a separate tunnel process owns the outbound flow.

Production distribution still requires a Microsoft-accepted driver signature and testing with Secure Boot and Memory Integrity enabled. Publishing `publish\NetWatch.exe` alone cannot provide strict aggregate limiting.
