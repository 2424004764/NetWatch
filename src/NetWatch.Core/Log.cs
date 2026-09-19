using System.IO;

namespace NetWatch.Core;

public static class Log
{
    private static readonly object Gate = new();
    public static readonly string LogFile = Path.Combine(Path.GetTempPath(), "netwatch.log");

    public static void Info(string msg) => Write("INFO ", msg);
    public static void Error(string msg) => Write("ERROR", msg);

    private static void Write(string level, string msg)
    {
        lock (Gate)
        {
            try
            {
                File.AppendAllText(LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {msg}{Environment.NewLine}");
            }
            catch { }
        }
    }
}
