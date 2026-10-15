# NetWatch Strict Upload WFP Callout

This directory contains the kernel control-device and callout-registration proof of concept. It is intentionally not included in the normal `publish\NetWatch.exe` build.

## Current status

The classify callback contains ALE/AppId matching and a bounded outbound-transport queue path. On an over-limit packet the driver clones the NBL, acquires/pends the classify request, absorbs the original, and retains the metadata needed for IPv4/IPv6 transport reinjection. A periodic DPC pump applies the shared token bucket, rejects stale generations/expired packets, and calls `FwpsInjectTransportSendAsync1`; injection completion releases the clone, original NBL reference, classify state, metadata and flow reference. Queue limits and live queued bytes are tracked per group, and flow delete/session replacement/unload paths drain or cancel pending packets.

The data-plane implementation is compiled by the WDK project. The driver reports the full capability mask only after the control device, both transport injection handles, timer/DPC, all four callouts, and the IO queue are initialized successfully. StrictService still keeps management filters disabled until the complete signed-driver, Secure Boot/HVCI, live-filter, Driver Verifier, teardown-race and receiver-side throughput gates have passed on a test machine. Do not install the current unsigned package expecting production strict shaping.

`build\NetWatchStrict.sys` and `package\NetWatchStrict.sys` are unsigned POC binaries; `package\netwatchstrict.cat` only passed catalog signability generation and is not a production signature. No driver has been installed or loaded. `tools/strict-service-install.ps1`, `strict-service-uninstall.ps1`, and `strict-service-status.ps1` manage and inspect only the SCM control service.

`NetWatch.Core.Wfp.BlockManager` is a separate user-mode WFP manager for ALE block filters. It cannot delay, queue, or reinject packets.

## Remaining acceptance work

- Keep StrictService fail-closed until a signed package is installed, platform status is passed, and the four real filters are observed enabled and hit on a controlled Windows test machine.
- Run Driver Verifier through `tools\strict-driver-verifier.ps1` while exercising flow close, session replacement, service stop and driver unload; collect verifier/Code Integrity events and dumps.
- Run the four independent receiver-side TCP/UDP IPv4/IPv6 scenarios from `tools\StrictThroughput`; the tool measures transport behavior only and does not enable WFP shaping itself.
- Obtain and verify the Microsoft-accepted kernel signature with `tools\strict-driver-signature.ps1`; local unsigned/test/self-signed artifacts are not release evidence.

VPN, proxy, and tunnel traffic can only be attributed to the process visible at the WFP classify layer. The application must not claim that the original application is covered when a separate tunnel process owns the outbound flow.

The production `token_bucket.c` is also built by the host harness at `driver\tests\token_bucket_test.c`; the shim replaces only kernel locking/interlocked APIs. The harness covers shared burst, fractional refill accumulation, overflow drops, and 64-thread aggregate consumption. It does not simulate WFP classification, asynchronous queueing, packet reinjection, or network throughput.


The WDK project uses KMDF 1.33 and the Windows 10.0.26100 SDK. The committed build gate keeps signing explicitly off for reproducible development output and fails when any required WDK validator is missing or returns nonzero. `tools\build-strict-driver.ps1` runs `Rebuild`, `InfVerif /w /v`, `Inf2Cat`, and `ApiValidator` for the declared x64 targets, then emits a source/package hash manifest and raw logs. It never creates a certificate or enables test signing. `tools\strict-driver-signature.ps1` is a separate release handoff gate: it requires `signtool verify /kp /all` for both `.sys` and `.cat`, rejects test/self-signed output, and records signed-package hashes. The existing generated `.sys` and `.cat` files remain unsigned and are not release evidence. Do not disable Spectre mitigation or any Windows security policy to bypass a missing prerequisite.

## Build, signing, platform, and install gates

Run these from an elevated Windows PowerShell. The status/signature gates are read-only; build may require elevation because `Inf2Cat` can require Administrator rights; install, uninstall, and Driver Verifier configuration/reset also require elevation.

- `powershell -File tools\build-strict-driver.ps1` discovers MSBuild and the WDK tools, fails fast if `InfVerif.exe`, `Inf2Cat.exe`, `ApiValidator.exe`, or the matching x64 `UniversalDDIs.xml` is unavailable, and writes JSON/text logs under `driver\artifacts\build`.
- `powershell -File tools\strict-driver-signature.ps1 -PackageDirectory <signed-package> -ManifestPath <build-manifest> -RequireTimestamp` validates Microsoft-accepted kernel policy signatures. The repository does not create certificates; obtain the signed package through the Microsoft Hardware Dev Center/Partner Center process or provide an externally signed package.
- `powershell -File tools\strict-platform-status.ps1 -RequireSecureBoot -RequireHvcI` reports Secure Boot, HVCI/Memory Integrity, driver/service/device state, and Code Integrity events. Missing evidence is `notCovered`, never a pass.
- `powershell -File tools\strict-driver-verifier.ps1 -Action Query` or `-Action Collect` is read-only. `-Action Configure -ArmVerifier` and `-Action Reset -ConfirmReset` are explicit, elevated test-machine operations and may require a reboot; these scripts never disable Secure Boot/HVCI or change boot-signing policy.
- `powershell -File tools\strict-driver-package.ps1 -Action Install -PackageDirectory <signed-package> -SignatureReportPath <signature-gate.json>` requires the passed signature gate before `pnputil /add-driver /install`. `-Action Status` is read-only. Uninstall requires both `-PublishedInf oem#.inf` from a reviewed `pnputil /enum-drivers` result and `-ConfirmUninstall`; it never guesses a package identity.

The package policy is recorded in `driver\package-manifest.json`: amd64 only, Windows 10/11 x64 target identifiers, Microsoft-accepted kernel signature required, no test signing, and no repository certificate generation. No install, Driver Verifier, reset, or platform-changing command was run while adding these gates.

Production distribution requires a Microsoft-accepted driver signature and testing with Secure Boot and Memory Integrity enabled. Publishing `publish\\NetWatch.exe` alone cannot provide strict aggregate limiting.
