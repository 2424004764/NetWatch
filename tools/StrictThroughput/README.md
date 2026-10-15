# StrictThroughput

Windows-only, receiver-measured TCP/UDP throughput harness targeting .NET 8. The coordinator runs one receiver and exactly two independent sender processes for every protocol/address-family/label scenario. TCP/UDP and IPv4/IPv6 can be selected explicitly. Each scenario records receiver payload bytes and rate; UDP also records sequence-based received, dropped, and duplicate datagrams. Warmup traffic is excluded from receiver throughput totals.

The coordinator binds to IPv4/IPv6 loopback by default. Non-loopback operation requires both `--bind-address <concrete-IP>` and `--remote`; wildcard binds and hostnames as bind addresses are rejected. Use only on a network you control. This harness generates test traffic; it does not install drivers, activate filters, enable WFP shaping, or claim that the `limited` label has been rate-limited. Arrange any external limiting separately and treat the label as report metadata.

## Run

```powershell
dotnet run --project tools/StrictThroughput -- coordinator --protocol both --family both --labels baseline,limited --duration-seconds 10 --warmup-seconds 2 --output strict-throughput-report.json
```

One scenario:

```powershell
dotnet run --project tools/StrictThroughput -- coordinator --protocol udp --family ipv6 --labels baseline --duration-seconds 15 --warmup-seconds 3 --udp-pps 500 --payload-bytes 1200
```

Run `dotnet run --project tools/StrictThroughput -- --help` for all options and the independent sender/receiver role syntax. `scripts/run-loopback.ps1` is a convenience wrapper for the default safe loopback run. Build with `dotnet build tools/StrictThroughput/StrictThroughput.csproj -c Release`.
