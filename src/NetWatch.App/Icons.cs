using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using ImageSource = System.Windows.Media.ImageSource;

namespace NetWatch.App;

/// <summary>运行时绘制应用图标（深色圆底 + 上传/下载双箭头）。</summary>
public static class Icons
{
    public static Icon TrayIcon() => Icon.FromHandle(AppBitmap().GetHicon());

    public static ImageSource WindowIcon() => ToImageSource(AppBitmap());

    private static Bitmap AppBitmap()
    {
        var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);
        using (var bg = new SolidBrush(Color.FromArgb(255, 34, 40, 56)))
            g.FillEllipse(bg, 1, 1, 30, 30);
        using (var penUp = new Pen(Color.FromArgb(255, 240, 178, 90), 4.2f)
               { CustomEndCap = new AdjustableArrowCap(2.6f, 2.6f, true), StartCap = LineCap.Round })
            g.DrawLine(penUp, 10.5f, 22.5f, 10.5f, 9.5f);
        using (var penDn = new Pen(Color.FromArgb(255, 124, 201, 139), 4.2f)
               { CustomEndCap = new AdjustableArrowCap(2.6f, 2.6f, true), StartCap = LineCap.Round })
            g.DrawLine(penDn, 21.5f, 9.5f, 21.5f, 22.5f);
        return bmp;
    }

    public static ImageSource ToImageSource(Bitmap bmp)
    {
        IntPtr hBitmap = bmp.GetHbitmap();
        try
        {
            var result = Imaging.CreateBitmapSourceFromHBitmap(
                hBitmap, IntPtr.Zero, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            result.Freeze();
            return result;
        }
        finally { DeleteObject(hBitmap); }
    }

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);
}
