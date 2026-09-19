namespace NetWatch.Core;

public static class Fmt
{
    private static readonly string[] Units = { "B", "KB", "MB", "GB", "TB", "PB" };

    public static string Bytes(double v)
    {
        if (v < 0) v = 0;
        int i = 0;
        while (v >= 1024 && i < Units.Length - 1) { v /= 1024; i++; }
        return (i == 0 || v >= 100 ? v.ToString("0") : v.ToString("0.##")) + " " + Units[i];
    }

    public static string Speed(double bytesPerSec) => Bytes(bytesPerSec) + "/s";
}
