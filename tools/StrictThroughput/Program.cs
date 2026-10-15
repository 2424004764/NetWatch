using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetWatch.StrictThroughput;

internal static class Program
{
    private const int WireMagic = 0x53544852;
    private const int SenderCount = 2;
    private const int TcpHeaderLength = 17;
    private const int UdpHeaderLength = 18;
    private const int MaxPayloadBytes = 60_000;
    private const int MaxDurationSeconds = 3_600;
    private const int MaxWarmupSeconds = 300;
    private const int MaxUdpPacketsPerSecond = 10_000;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
    private static readonly JsonSerializerOptions CompactJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        if (args.Length == 0 || args.Contains("--help", StringComparer.OrdinalIgnoreCase) || args.Contains("-h"))
        {
            PrintHelp();
            return args.Length == 0 ? 2 : 0;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("StrictThroughput is Windows-only.");
            return 2;
        }

        try
        {
            var role = args[0].ToLowerInvariant();
            var options = Arguments.Parse(args[1..]);
            return role switch
            {
                "coordinator" => await RunCoordinatorAsync(options).ConfigureAwait(false),
                "receiver" => await RunReceiverAsync(options).ConfigureAwait(false),
                "sender" => await RunSenderAsync(options).ConfigureAwait(false),
                _ => throw new ArgumentException($"Unknown role '{args[0]}'. Use --help for usage."),
            };
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Cancelled.");
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static async Task<int> RunCoordinatorAsync(Arguments options)
    {
        var config = HarnessConfig.From(options);
        var protocols = ParseChoices(options.Get("protocol", "both"), "protocol", "tcp", "udp");
        var families = ParseChoices(options.Get("family", "both"), "family", "ipv4", "ipv6");
        var labels = ParseLabels(options.Get("labels", "baseline,limited"));
        var bindText = options.Optional("bind-address");
        var remote = options.Flag("remote");

        if (bindText is not null)
        {
            var explicitAddress = ParseAddress(bindText);
            var inferredFamily = explicitAddress.AddressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6";
            if (families.Count != 1 || families[0] != inferredFamily)
                throw new ArgumentException("A concrete --bind-address requires one matching --family ipv4 or ipv6.");
            if (!IPAddress.IsLoopback(explicitAddress) && !remote)
                throw new ArgumentException("A non-loopback --bind-address requires --remote.");
            if (IPAddress.Any.Equals(explicitAddress) || IPAddress.IPv6Any.Equals(explicitAddress))
                throw new ArgumentException("Wildcard binds are not supported; specify one concrete interface address.");
        }
        else if (remote)
        {
            throw new ArgumentException("--remote requires a concrete --bind-address.");
        }

        var outputPath = Path.GetFullPath(options.Get("output", "strict-throughput-report.json"));
        var results = new List<ScenarioResult>();
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;
        try
        {
            foreach (var protocolText in protocols)
            foreach (var familyText in families)
            foreach (var label in labels)
            {
                var protocol = protocolText == "tcp" ? WireProtocol.Tcp : WireProtocol.Udp;
                var family = familyText == "ipv4" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                var bindAddress = bindText is null
                    ? family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback
                    : ParseAddress(bindText);

                Console.WriteLine($"[{label}] {protocolText.ToUpperInvariant()}/{familyText} receiver={bindAddress}");
                var result = await RunScenarioAsync(protocol, family, bindAddress, label, config, cancellation.Token)
                    .ConfigureAwait(false);
                results.Add(result);
                Console.WriteLine($"  receiver bytes={result.ReceiverBytes:N0}, rate={result.ReceiverMegabitsPerSecond:F3} Mbit/s, " +
                                  $"UDP received={result.ReceivedDatagrams:N0}/{result.ExpectedDatagrams:N0}, drops={result.DroppedDatagrams:N0}");
            }
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }

        var report = new HarnessReport
        {
            CreatedUtc = DateTimeOffset.UtcNow,
            OperatingSystem = Environment.OSVersion.ToString(),
            ToolVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown",
            ScopeNotice = "Receiver-side measurement only. This harness does not install drivers, configure WFP, enable shaping, or claim that the limited label was rate-limited. Arrange any external condition separately.",
            SenderProcessCountPerScenario = SenderCount,
            Results = results,
        };
        var outputDirectory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrWhiteSpace(outputDirectory)) Directory.CreateDirectory(outputDirectory);
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(report, JsonOptions), cancellation.Token)
            .ConfigureAwait(false);
        Console.WriteLine($"JSON report: {outputPath}");
        Console.WriteLine("The limited pass is a label only; no WFP or other limiter was activated by this tool.");
        return 0;
    }

    private static async Task<ScenarioResult> RunScenarioAsync(
        WireProtocol protocol,
        AddressFamily family,
        IPAddress bindAddress,
        string label,
        HarnessConfig config,
        CancellationToken cancellationToken)
    {
        var receiverArguments = new List<string>
        {
            "receiver",
            "--protocol", protocol.ToString().ToLowerInvariant(),
            "--family", family == AddressFamily.InterNetwork ? "ipv4" : "ipv6",
            "--bind-address", bindAddress.ToString(),
            "--port", "0",
            "--data-port", "0",
            "--warmup-seconds", config.WarmupSeconds.ToString(),
            "--duration-seconds", config.DurationSeconds.ToString(),
            "--payload-bytes", config.PayloadBytes.ToString(),
            "--udp-pps", config.UdpPacketsPerSecond.ToString(),
        };
        var isRemote = !IPAddress.IsLoopback(bindAddress);
        if (isRemote) receiverArguments.Add("--remote");

        using var receiver = StartChild(receiverArguments);
        using var receiverOutput = receiver.StandardOutput;
        using var receiverError = receiver.StandardError;
        var receiverErrorTask = receiverError.ReadToEndAsync();
        var readyLine = await receiverOutput.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (readyLine is null || !readyLine.StartsWith("READY ", StringComparison.Ordinal))
        {
            TryKill(receiver);
            throw new InvalidOperationException("Receiver did not become ready: " + await receiverErrorTask.ConfigureAwait(false));
        }
        var ready = ParseReady(readyLine);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(config.DurationSeconds + config.WarmupSeconds + 30));
        using var scenarioCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        var senderCancellation = scenarioCancellation.Token;
        var senderTasks = Enumerable.Range(0, SenderCount).Select(senderId =>
        {
            var senderArguments = new List<string>
            {
                "sender",
                "--protocol", protocol.ToString().ToLowerInvariant(),
                "--family", family == AddressFamily.InterNetwork ? "ipv4" : "ipv6",
                "--host", bindAddress.ToString(),
                "--port", ready.ControlPort.ToString(),
                "--data-port", ready.DataPort.ToString(),
                "--sender-id", senderId.ToString(),
            };
            if (isRemote) senderArguments.Add("--remote");
            return RunSenderProcessAsync(senderArguments.ToArray(), senderCancellation);
        }).ToArray();
        string? resultJson = null;
        try
        {
            while (!timeout.IsCancellationRequested)
            {
                string? line;
                try
                {
                    line = await receiverOutput.ReadLineAsync(timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                if (line is null) break;
                if (line.StartsWith("RESULT ", StringComparison.Ordinal))
                {
                    resultJson = line[7..];
                    break;
                }
                Console.WriteLine("  receiver: " + line);
            }

            if (resultJson is null)
            {
                TryKill(receiver);
                throw new TimeoutException("Receiver did not return a result before the scenario timeout.");
            }

            var receiverResult = JsonSerializer.Deserialize<ReceiverResult>(resultJson, JsonOptions)
                ?? throw new InvalidDataException("Receiver returned invalid JSON.");
            var senderResults = await Task.WhenAll(senderTasks).WaitAsync(TimeSpan.FromSeconds(30), cancellationToken)
                .ConfigureAwait(false);
            await receiver.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var receiverErrorText = await receiverErrorTask.ConfigureAwait(false);
            if (receiver.ExitCode != 0)
                throw new InvalidOperationException("Receiver failed: " + receiverErrorText);
            var failedSenders = senderResults.Where(item => item.ExitCode != 0).ToArray();
            if (failedSenders.Length != 0)
                throw new InvalidOperationException("Sender failed: " + string.Join(" | ", failedSenders.Select(item => item.Error)));

            return new ScenarioResult
            {
                Label = label,
                Protocol = protocol,
                AddressFamily = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6",
                BindAddress = bindAddress.ToString(),
                DurationSeconds = config.DurationSeconds,
                WarmupSeconds = config.WarmupSeconds,
                PayloadBytes = config.PayloadBytes,
                UdpPacketsPerSecondPerSender = protocol == WireProtocol.Udp ? config.UdpPacketsPerSecond : null,
                SenderProcessCount = SenderCount,
                ReceiverBytes = receiverResult.ReceiverBytes,
                ReceiverMegabitsPerSecond = receiverResult.ReceiverMegabitsPerSecond,
                ReceivedDatagrams = receiverResult.ReceivedDatagrams,
                ExpectedDatagrams = receiverResult.ExpectedDatagrams,
                DroppedDatagrams = receiverResult.DroppedDatagrams,
                DuplicateDatagrams = receiverResult.DuplicateDatagrams,
                PerSender = receiverResult.PerSender,
            };
        }
        finally
        {
            scenarioCancellation.Cancel();
            if (!receiver.HasExited) TryKill(receiver);
            try { await Task.WhenAll(senderTasks).WaitAsync(TimeSpan.FromSeconds(5)); }
            catch { }
        }
    }

    private static async Task<int> RunReceiverAsync(Arguments options)
    {
        var protocol = ParseProtocol(options.Get("protocol", "tcp"));
        var family = ParseFamily(options.Get("family", "ipv4"));
        var bindAddress = ParseAddress(options.Get("bind-address", family == AddressFamily.InterNetwork ? "127.0.0.1" : "::1"));
        ValidateAddress(bindAddress, family, options.Flag("remote"));
        var config = HarnessConfig.From(options);
        var controlPort = options.GetInt("port", 0, 0, 65_535);
        var dataPort = options.GetInt("data-port", 0, 0, 65_535);

        using var controlListener = CreateSocket(family, SocketType.Stream, ProtocolType.Tcp);
        controlListener.Bind(new IPEndPoint(bindAddress, controlPort));
        controlListener.Listen(SenderCount);
        using var dataSocket = protocol == WireProtocol.Udp
            ? CreateSocket(family, SocketType.Dgram, ProtocolType.Udp)
            : null;
        if (dataSocket is not null)
        {
            dataSocket.Bind(new IPEndPoint(bindAddress, dataPort));
            dataPort = ((IPEndPoint)dataSocket.LocalEndPoint!).Port;
        }
        controlPort = ((IPEndPoint)controlListener.LocalEndPoint!).Port;
        Console.WriteLine($"READY controlPort={controlPort} dataPort={(dataSocket is null ? controlPort : dataPort)}");
        Console.Out.Flush();

        var clients = new List<ControlClient>(SenderCount);
        var senderIds = new HashSet<int>();
        try
        {
            for (var index = 0; index < SenderCount; index++)
            {
                var socket = await controlListener.AcceptAsync().ConfigureAwait(false);
                var stream = new NetworkStream(socket, ownsSocket: true);
                var magic = await ReadInt32Async(stream).ConfigureAwait(false);
                var senderId = await ReadInt32Async(stream).ConfigureAwait(false);
                if (magic != WireMagic || senderId < 0 || senderId >= SenderCount || !senderIds.Add(senderId))
                    throw new InvalidDataException("Sender handshake is invalid or sender IDs are not unique.");
                clients.Add(new ControlClient(senderId, stream));
            }

            var start = Stopwatch.StartNew();
            foreach (var client in clients)
            {
                await WriteConfigAsync(client.Stream, config, dataSocket is null ? 0 : dataPort).ConfigureAwait(false);
                await client.Stream.FlushAsync().ConfigureAwait(false);
            }

            ReceiverResult result = protocol == WireProtocol.Tcp
                ? await ReceiveTcpAsync(clients, start, config).ConfigureAwait(false)
                : await ReceiveUdpAsync(clients, dataSocket!, start, config).ConfigureAwait(false);
            Console.WriteLine("RESULT " + JsonSerializer.Serialize(result, CompactJsonOptions));
            Console.Out.Flush();
            return 0;
        }
        finally
        {
            foreach (var client in clients) await client.Stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<ReceiverResult> ReceiveTcpAsync(
        IReadOnlyList<ControlClient> clients,
        Stopwatch start,
        HarnessConfig config)
    {
        var tasks = clients.Select(client => ReceiveTcpSenderAsync(client, start, config)).ToArray();
        var perSender = await Task.WhenAll(tasks).ConfigureAwait(false);
        var bytes = perSender.Sum(item => item.ReceiverBytes);
        return new ReceiverResult
        {
            ReceiverBytes = bytes,
            ReceiverMegabitsPerSecond = RateMbps(bytes, config.DurationSeconds),
            PerSender = perSender,
        };
    }

    private static async Task<SenderResult> ReceiveTcpSenderAsync(
        ControlClient client,
        Stopwatch start,
        HarnessConfig config)
    {
        long bytes = 0;
        long frames = 0;
        var header = new byte[TcpHeaderLength];
        var payload = new byte[config.PayloadBytes];
        while (true)
        {
            var first = await client.Stream.ReadAsync(header.AsMemory(0, 1)).ConfigureAwait(false);
            if (first == 0) break;
            await ReadExactlyAsync(client.Stream, header.AsMemory(1)).ConfigureAwait(false);
            var kind = header[0];
            var sequence = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(1, 8));
            var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(9, 4));
            var magic = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(13, 4));
            if (magic != WireMagic || kind > 1 || payloadLength < 1 || payloadLength > config.PayloadBytes)
                throw new InvalidDataException("TCP sender frame is invalid.");
            await ReadExactlyAsync(client.Stream, payload.AsMemory(0, payloadLength)).ConfigureAwait(false);
            if (kind == 1 && start.ElapsedMilliseconds < config.TotalMilliseconds + 1_000)
            {
                bytes += payloadLength;
                frames++;
            }
            _ = sequence;
        }
        return new SenderResult
        {
            SenderId = client.SenderId,
            ReceiverBytes = bytes,
            ReceivedFrames = frames,
        };
    }

    private static async Task<ReceiverResult> ReceiveUdpAsync(
        IReadOnlyList<ControlClient> clients,
        Socket dataSocket,
        Stopwatch start,
        HarnessConfig config)
    {
        var summaries = new SenderSummary?[SenderCount];
        var summaryTasks = clients.Select(async client =>
        {
            var magic = await ReadInt32Async(client.Stream).ConfigureAwait(false);
            var senderId = await ReadInt32Async(client.Stream).ConfigureAwait(false);
            var datagrams = await ReadInt64Async(client.Stream).ConfigureAwait(false);
            var bytes = await ReadInt64Async(client.Stream).ConfigureAwait(false);
            if (magic != WireMagic || senderId != client.SenderId || datagrams < 0 || bytes < 0)
                throw new InvalidDataException("UDP sender summary is invalid.");
            summaries[senderId] = new SenderSummary(datagrams, bytes);
        }).ToArray();

        var seen = new[] { new HashSet<long>(), new HashSet<long>() };
        var perSenderBytes = new long[SenderCount];
        long duplicates = 0;
        var packet = new byte[UdpHeaderLength + config.PayloadBytes];
        var endpoint = dataSocket.AddressFamily == AddressFamily.InterNetwork
            ? (EndPoint)new IPEndPoint(IPAddress.Any, 0)
            : new IPEndPoint(IPAddress.IPv6Any, 0);
        var stopAfter = config.TotalMilliseconds + 2_000;
        var drainUntil = (long?)null;
        while (start.ElapsedMilliseconds < stopAfter)
        {
            if (summaryTasks.All(task => task.IsCompleted) && start.ElapsedMilliseconds >= config.TotalMilliseconds)
            {
                drainUntil ??= Stopwatch.GetTimestamp() + Stopwatch.Frequency / 3;
                if (Stopwatch.GetTimestamp() >= drainUntil.Value) break;
            }
            if (!dataSocket.Poll(100_000, SelectMode.SelectRead)) continue;
            var received = await dataSocket.ReceiveFromAsync(packet.AsMemory(), SocketFlags.None, endpoint)
                .ConfigureAwait(false);
            endpoint = received.RemoteEndPoint;
            var length = received.ReceivedBytes;
            if (!TryParseUdpFrame(packet, length, out var senderId, out var kind,
                    out var sequence, out var payloadLength))
                continue;
            if (kind != 1) continue;
            if (!seen[senderId].Add(sequence))
            {
                duplicates++;
                continue;
            }
            perSenderBytes[senderId] += payloadLength;
        }
        await Task.WhenAll(summaryTasks).ConfigureAwait(false);

        var perSender = new List<SenderResult>(SenderCount);
        long totalBytes = 0;
        long expectedDatagrams = 0;
        long receivedDatagrams = 0;
        for (var senderId = 0; senderId < SenderCount; senderId++)
        {
            var expected = summaries[senderId]?.Datagrams ?? seen[senderId].Count;
            var received = seen[senderId].Count;
            var dropped = Math.Max(0, expected - received);
            totalBytes += perSenderBytes[senderId];
            expectedDatagrams += expected;
            receivedDatagrams += received;
            perSender.Add(new SenderResult
            {
                SenderId = senderId,
                ReceiverBytes = perSenderBytes[senderId],
                SenderReportedBytes = summaries[senderId]?.Bytes,
                ExpectedDatagrams = expected,
                ReceivedDatagrams = received,
                DroppedDatagrams = dropped,
            });
        }
        return new ReceiverResult
        {
            ReceiverBytes = totalBytes,
            ReceiverMegabitsPerSecond = RateMbps(totalBytes, config.DurationSeconds),
            ExpectedDatagrams = expectedDatagrams,
            ReceivedDatagrams = receivedDatagrams,
            DroppedDatagrams = Math.Max(0, expectedDatagrams - receivedDatagrams),
            DuplicateDatagrams = duplicates,
            PerSender = perSender,
        };
    }

    private static int ReceiveDatagram(Socket socket, byte[] buffer, ref EndPoint endpoint)
        => socket.ReceiveFrom(buffer, ref endpoint);

    private static bool TryParseUdpFrame(
        byte[] packet,
        int length,
        out int senderId,
        out int kind,
        out long sequence,
        out int payloadLength)
    {
        senderId = 0;
        kind = 0;
        sequence = 0;
        payloadLength = 0;
        if (length < UdpHeaderLength) return false;
        var frame = packet.AsSpan(0, length);
        var magic = BinaryPrimitives.ReadInt32LittleEndian(frame[..4]);
        senderId = frame[4];
        kind = frame[5];
        sequence = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(6, 8));
        payloadLength = BinaryPrimitives.ReadInt32LittleEndian(frame.Slice(14, 4));
        return magic == WireMagic && senderId >= 0 && senderId < SenderCount && kind <= 1
            && payloadLength >= 1 && payloadLength == length - UdpHeaderLength;
    }

    private static async Task<int> RunSenderAsync(Arguments options)
    {
        var protocol = ParseProtocol(options.Get("protocol", "tcp"));
        var family = ParseFamily(options.Get("family", "ipv4"));
        var host = options.Get("host", family == AddressFamily.InterNetwork ? "127.0.0.1" : "::1");
        var address = await ResolveAddressAsync(host, family).ConfigureAwait(false);
        if (!IPAddress.IsLoopback(address) && !options.Flag("remote"))
            throw new ArgumentException("A non-loopback --host requires --remote.");
        var controlPort = options.GetInt("port", 0, 1, 65_535);
        var dataPort = options.GetInt("data-port", 0, 0, 65_535);
        var senderId = options.GetInt("sender-id", -1, 0, SenderCount - 1);
        if (senderId < 0) throw new ArgumentException("--sender-id must be 0 or 1.");

        using var control = CreateSocket(family, SocketType.Stream, ProtocolType.Tcp);
        await control.ConnectAsync(new IPEndPoint(address, controlPort)).ConfigureAwait(false);
        using var stream = new NetworkStream(control, ownsSocket: false);
        await WriteInt32Async(stream, WireMagic).ConfigureAwait(false);
        await WriteInt32Async(stream, senderId).ConfigureAwait(false);
        await stream.FlushAsync().ConfigureAwait(false);
        var config = await ReadConfigAsync(stream).ConfigureAwait(false);
        if (protocol == WireProtocol.Tcp)
            await SendTcpAsync(stream, config).ConfigureAwait(false);
        else
            await SendUdpAsync(stream, senderId, address, dataPort == 0 ? config.DataPort : dataPort, family, config)
                .ConfigureAwait(false);
        Console.WriteLine($"Sender {senderId} complete.");
        return 0;
    }

    private static async Task SendTcpAsync(NetworkStream stream, WireConfig config)
    {
        var payload = new byte[config.PayloadBytes];
        Random.Shared.NextBytes(payload);
        var frame = new byte[TcpHeaderLength + payload.Length];
        payload.CopyTo(frame, TcpHeaderLength);
        var stopwatch = Stopwatch.StartNew();
        long sequence = 0;
        while (stopwatch.ElapsedMilliseconds < config.TotalMilliseconds)
        {
            frame[0] = stopwatch.ElapsedMilliseconds < config.WarmupMilliseconds ? (byte)0 : (byte)1;
            BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(1, 8), sequence++);
            BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(9, 4), payload.Length);
            BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(13, 4), WireMagic);
            await stream.WriteAsync(frame).ConfigureAwait(false);
        }
    }

    private static async Task SendUdpAsync(
        NetworkStream control,
        int senderId,
        IPAddress address,
        int dataPort,
        AddressFamily family,
        WireConfig config)
    {
        if (dataPort is < 1 or > 65_535) throw new InvalidDataException("Receiver supplied an invalid UDP data port.");
        using var socket = CreateSocket(family, SocketType.Dgram, ProtocolType.Udp);
        var endpoint = new IPEndPoint(address, dataPort);
        var payload = new byte[config.PayloadBytes];
        Random.Shared.NextBytes(payload);
        var packet = new byte[UdpHeaderLength + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, 4), WireMagic);
        packet[4] = (byte)senderId;
        payload.CopyTo(packet, UdpHeaderLength);
        var stopwatch = Stopwatch.StartNew();
        var intervalTicks = Math.Max(1L, Stopwatch.Frequency / config.UdpPacketsPerSecond);
        var nextSend = stopwatch.ElapsedTicks;
        long measuredSequence = 0;
        long measuredBytes = 0;
        while (stopwatch.ElapsedMilliseconds < config.TotalMilliseconds)
        {
            var measured = stopwatch.ElapsedMilliseconds >= config.WarmupMilliseconds;
            packet[5] = measured ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(6, 8), measured ? measuredSequence++ : 0);
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(14, 4), payload.Length);
            await socket.SendToAsync(packet, SocketFlags.None, endpoint).ConfigureAwait(false);
            if (measured) measuredBytes += payload.Length;

            nextSend += intervalTicks;
            var remainingTicks = nextSend - stopwatch.ElapsedTicks;
            if (remainingTicks > Stopwatch.Frequency / 500)
            {
                var delayMs = Math.Max(1, (int)(remainingTicks * 1_000 / Stopwatch.Frequency));
                await Task.Delay(delayMs).ConfigureAwait(false);
            }
            else if (remainingTicks > 0)
            {
                Thread.SpinWait(20);
            }
        }
        await WriteInt32Async(control, WireMagic).ConfigureAwait(false);
        await WriteInt32Async(control, senderId).ConfigureAwait(false);
        await WriteInt64Async(control, measuredSequence).ConfigureAwait(false);
        await WriteInt64Async(control, measuredBytes).ConfigureAwait(false);
        await control.FlushAsync().ConfigureAwait(false);
    }

    private static async Task<ChildResult> RunSenderProcessAsync(string[] arguments, CancellationToken cancellationToken)
    {
        using var process = StartChild(arguments);
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            TryKill(process);
            throw;
        }
        return new ChildResult(process.ExitCode, (await outputTask.ConfigureAwait(false)).Trim(),
            (await errorTask.ConfigureAwait(false)).Trim());
    }

    private static Process StartChild(IEnumerable<string> arguments)
    {
        var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate the current process.");
        var startInfo = new ProcessStartInfo(processPath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        if (Path.GetFileNameWithoutExtension(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var assemblyPath = Assembly.GetEntryAssembly()?.Location;
            if (string.IsNullOrWhiteSpace(assemblyPath))
                throw new InvalidOperationException("Cannot locate the running assembly for a child process.");
            startInfo.ArgumentList.Add(assemblyPath);
        }
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        if (!process.Start()) throw new InvalidOperationException("Could not start child process.");
        return process;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { }
    }

    private static ReadyPorts ParseReady(string line)
    {
        var values = line[6..].Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.Split('=', 2))
            .Where(item => item.Length == 2)
            .ToDictionary(item => item[0], item => item[1], StringComparer.OrdinalIgnoreCase);
        if (!int.TryParse(values.GetValueOrDefault("controlPort"), out var controlPort) ||
            !int.TryParse(values.GetValueOrDefault("dataPort"), out var dataPort))
            throw new InvalidDataException("Receiver emitted a malformed READY line.");
        return new ReadyPorts(controlPort, dataPort);
    }

    private static List<string> ParseChoices(string value, string optionName, params string[] allowed)
    {
        if (value.Equals("both", StringComparison.OrdinalIgnoreCase)) return allowed.ToList();
        var values = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.ToLowerInvariant()).Distinct().ToList();
        if (values.Count == 0 || values.Any(item => !allowed.Contains(item, StringComparer.Ordinal)))
            throw new ArgumentException($"Invalid --{optionName} value '{value}'. Use {string.Join(", ", allowed)} or both.");
        return values;
    }

    private static List<string> ParseLabels(string value)
    {
        var labels = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.ToLowerInvariant()).Distinct().ToList();
        if (labels.Count == 0 || labels.Any(item => item is not ("baseline" or "limited")))
            throw new ArgumentException("--labels must contain baseline, limited, or both comma-separated.");
        return labels;
    }

    private static IPAddress ParseAddress(string value) => IPAddress.TryParse(value, out var address)
        ? address
        : throw new ArgumentException($"'{value}' is not a numeric IPv4 or IPv6 address.");

    private static async Task<IPAddress> ResolveAddressAsync(string host, AddressFamily family)
    {
        if (IPAddress.TryParse(host, out var address))
        {
            if (address.AddressFamily != family) throw new ArgumentException("--host does not match --family.");
            return address;
        }
        var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
        return addresses.FirstOrDefault(item => item.AddressFamily == family)
            ?? throw new ArgumentException($"No {family} address found for '{host}'.");
    }

    private static void ValidateAddress(IPAddress address, AddressFamily family, bool remote)
    {
        if (address.AddressFamily != family) throw new ArgumentException("--bind-address does not match --family.");
        if (!IPAddress.IsLoopback(address) && !remote)
            throw new ArgumentException("A non-loopback receiver bind requires --remote.");
        if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address))
            throw new ArgumentException("Wildcard binds are not supported; specify one concrete address.");
    }

    private static Socket CreateSocket(AddressFamily family, SocketType type, ProtocolType protocol)
    {
        var socket = new Socket(family, type, protocol);
        if (family == AddressFamily.InterNetworkV6) socket.DualMode = false;
        return socket;
    }

    private static WireProtocol ParseProtocol(string value) => value.ToLowerInvariant() switch
    {
        "tcp" => WireProtocol.Tcp,
        "udp" => WireProtocol.Udp,
        _ => throw new ArgumentException("--protocol must be tcp or udp."),
    };

    private static AddressFamily ParseFamily(string value) => value.ToLowerInvariant() switch
    {
        "ipv4" => AddressFamily.InterNetwork,
        "ipv6" => AddressFamily.InterNetworkV6,
        _ => throw new ArgumentException("--family must be ipv4 or ipv6."),
    };

    private static double RateMbps(long bytes, int seconds) => seconds <= 0 ? 0 : bytes * 8d / seconds / 1_000_000d;

    private static async Task<int> ReadInt32Async(Stream stream)
    {
        var bytes = new byte[4];
        await ReadExactlyAsync(stream, bytes).ConfigureAwait(false);
        return BinaryPrimitives.ReadInt32LittleEndian(bytes);
    }

    private static async Task<long> ReadInt64Async(Stream stream)
    {
        var bytes = new byte[8];
        await ReadExactlyAsync(stream, bytes).ConfigureAwait(false);
        return BinaryPrimitives.ReadInt64LittleEndian(bytes);
    }

    private static async Task WriteInt32Async(Stream stream, int value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
        await stream.WriteAsync(bytes).ConfigureAwait(false);
    }

    private static async Task WriteInt64Async(Stream stream, long value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        await stream.WriteAsync(bytes).ConfigureAwait(false);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> memory)
    {
        while (!memory.IsEmpty)
        {
            var count = await stream.ReadAsync(memory).ConfigureAwait(false);
            if (count == 0) throw new EndOfStreamException("Peer disconnected during a wire message.");
            memory = memory[count..];
        }
    }

    private static async Task WriteConfigAsync(Stream stream, HarnessConfig config, int dataPort)
    {
        await WriteInt32Async(stream, WireMagic).ConfigureAwait(false);
        await WriteInt32Async(stream, config.WarmupSeconds * 1_000).ConfigureAwait(false);
        await WriteInt32Async(stream, config.DurationSeconds * 1_000).ConfigureAwait(false);
        await WriteInt32Async(stream, config.PayloadBytes).ConfigureAwait(false);
        await WriteInt32Async(stream, config.UdpPacketsPerSecond).ConfigureAwait(false);
        await WriteInt32Async(stream, dataPort).ConfigureAwait(false);
    }

    private static async Task<WireConfig> ReadConfigAsync(Stream stream)
    {
        var magic = await ReadInt32Async(stream).ConfigureAwait(false);
        var warmup = await ReadInt32Async(stream).ConfigureAwait(false);
        var duration = await ReadInt32Async(stream).ConfigureAwait(false);
        var payload = await ReadInt32Async(stream).ConfigureAwait(false);
        var packetsPerSecond = await ReadInt32Async(stream).ConfigureAwait(false);
        var dataPort = await ReadInt32Async(stream).ConfigureAwait(false);
        if (magic != WireMagic || warmup < 0 || duration <= 0 || payload is < 64 or > MaxPayloadBytes ||
            packetsPerSecond is < 1 or > MaxUdpPacketsPerSecond)
            throw new InvalidDataException("Receiver supplied invalid run settings.");
        return new WireConfig(warmup, duration, payload, packetsPerSecond, dataPort);
    }

    private static void PrintHelp()
    {
        Console.WriteLine("StrictThroughput - Windows-only receiver-side TCP/UDP throughput harness");
        Console.WriteLine();
        Console.WriteLine("Coordinator (safe loopback default):");
        Console.WriteLine("  dotnet run --project tools/StrictThroughput -- coordinator [options]");
        Console.WriteLine("  --protocol tcp|udp|both       --family ipv4|ipv6|both");
        Console.WriteLine("  --labels baseline,limited     --duration-seconds N (default 10)");
        Console.WriteLine("  --warmup-seconds N (default 2) --payload-bytes N (default 1200)");
        Console.WriteLine("  --udp-pps N (default 1000)    --output PATH");
        Console.WriteLine("  --bind-address IP --remote    explicit concrete non-loopback interface mode");
        Console.WriteLine();
        Console.WriteLine("Independent roles:");
        Console.WriteLine("  StrictThroughput receiver --protocol tcp|udp --family ipv4|ipv6 --bind-address IP --port N");
        Console.WriteLine("  StrictThroughput sender --protocol tcp|udp --family ipv4|ipv6 --host IP --port N --sender-id 0|1");
        Console.WriteLine();
        Console.WriteLine("Each scenario starts one receiver and exactly two independent sender processes.");
        Console.WriteLine("Receiver bytes, duration, warmup, and UDP sequence/drop counts are written to JSON.");
        Console.WriteLine("The limited label is metadata only; this tool does not enable or claim WFP shaping.");
    }

    private sealed record ReadyPorts(int ControlPort, int DataPort);
    private sealed record ControlClient(int SenderId, NetworkStream Stream);
    private sealed record SenderSummary(long Datagrams, long Bytes);
    private sealed record ChildResult(int ExitCode, string Output, string Error);
}

internal sealed class Arguments
{
    private readonly Dictionary<string, string?> values = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> flags = new(StringComparer.OrdinalIgnoreCase);

    public static Arguments Parse(string[] args)
    {
        var result = new Arguments();
        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException($"Unexpected argument '{token}'. Options use --name value.");
            var name = token[2..];
            if (name.Equals("remote", StringComparison.OrdinalIgnoreCase))
                result.flags.Add(name);
            else
            {
                if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException($"Option --{name} requires a value.");
                result.values[name] = args[++index];
            }
        }
        return result;
    }

    public bool Flag(string name) => flags.Contains(name);
    public string Get(string name, string defaultValue) => values.TryGetValue(name, out var value) ? value! : defaultValue;
    public string? Optional(string name) => values.GetValueOrDefault(name);

    public int GetInt(string name, int defaultValue, int min, int max)
    {
        var text = Get(name, defaultValue.ToString());
        if (!int.TryParse(text, out var value) || value < min || value > max)
            throw new ArgumentException($"--{name} must be an integer from {min} to {max}.");
        return value;
    }
}

internal sealed record HarnessConfig(int DurationSeconds, int WarmupSeconds, int PayloadBytes, int UdpPacketsPerSecond)
{
    public int TotalMilliseconds => checked((DurationSeconds + WarmupSeconds) * 1_000);

    public static HarnessConfig From(Arguments options)
    {
        return new HarnessConfig(
            options.GetInt("duration-seconds", 10, 1, 3_600),
            options.GetInt("warmup-seconds", 2, 0, 300),
            options.GetInt("payload-bytes", 1_200, 64, 60_000),
            options.GetInt("udp-pps", 1_000, 1, 10_000));
    }
}

internal enum WireProtocol
{
    Tcp,
    Udp,
}

internal sealed class WireConfig
{
    public WireConfig(int warmupMilliseconds, int durationMilliseconds, int payloadBytes, int udpPacketsPerSecond, int dataPort)
    {
        WarmupMilliseconds = warmupMilliseconds;
        DurationMilliseconds = durationMilliseconds;
        PayloadBytes = payloadBytes;
        UdpPacketsPerSecond = udpPacketsPerSecond;
        DataPort = dataPort;
    }

    public int WarmupMilliseconds { get; }
    public int DurationMilliseconds { get; }
    public int PayloadBytes { get; }
    public int UdpPacketsPerSecond { get; }
    public int DataPort { get; }
    public int TotalMilliseconds => checked(WarmupMilliseconds + DurationMilliseconds);
}

internal sealed class SenderResult
{
    public int SenderId { get; init; }
    public long ReceiverBytes { get; init; }
    public long? SenderReportedBytes { get; init; }
    public long ReceivedFrames { get; init; }
    public long? ExpectedDatagrams { get; init; }
    public long ReceivedDatagrams { get; init; }
    public long? DroppedDatagrams { get; init; }
    public long DuplicateDatagrams { get; init; }
}

internal sealed class ReceiverResult
{
    public long ReceiverBytes { get; init; }
    public double ReceiverMegabitsPerSecond { get; init; }
    public long ReceivedFrames { get; init; }
    public long ExpectedDatagrams { get; init; }
    public long ReceivedDatagrams { get; init; }
    public long DroppedDatagrams { get; init; }
    public long DuplicateDatagrams { get; init; }
    public IReadOnlyList<SenderResult> PerSender { get; init; } = Array.Empty<SenderResult>();
}

internal sealed class ScenarioResult
{
    public required string Label { get; init; }
    public required WireProtocol Protocol { get; init; }
    public required string AddressFamily { get; init; }
    public required string BindAddress { get; init; }
    public required int DurationSeconds { get; init; }
    public required int WarmupSeconds { get; init; }
    public required int PayloadBytes { get; init; }
    public int? UdpPacketsPerSecondPerSender { get; init; }
    public required int SenderProcessCount { get; init; }
    public required long ReceiverBytes { get; init; }
    public required double ReceiverMegabitsPerSecond { get; init; }
    public required long ReceivedDatagrams { get; init; }
    public required long ExpectedDatagrams { get; init; }
    public required long DroppedDatagrams { get; init; }
    public required long DuplicateDatagrams { get; init; }
    public required IReadOnlyList<SenderResult> PerSender { get; init; }
}

internal sealed class HarnessReport
{
    public required DateTimeOffset CreatedUtc { get; init; }
    public required string OperatingSystem { get; init; }
    public required string ToolVersion { get; init; }
    public required string ScopeNotice { get; init; }
    public required int SenderProcessCountPerScenario { get; init; }
    public required IReadOnlyList<ScenarioResult> Results { get; init; }
}
