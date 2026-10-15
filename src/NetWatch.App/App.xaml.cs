using System;
using System.Windows;
using NetWatch.Core;

namespace NetWatch.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Log.Info($"NetWatch 启动，日志文件：{Log.LogFile}");
        Exit += (_, _) => CleanupUploadLimits();
        SessionEnding += (_, _) => CleanupUploadLimits();
        DispatcherUnhandledException += (_, ex) =>
        {
            Log.Error("未处理异常：" + ex.Exception);
            CleanupUploadLimits();
            MessageBox.Show("发生错误：" + ex.Exception.Message +
                            "\n\n详情已写入日志：" + Log.LogFile,
                            "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            ex.Handled = true;
        };
    }

    private static void CleanupUploadLimits()
    {
        foreach (Window window in Current.Windows)
            if (window is MainWindow main)
            {
                try { main.CleanupUploadLimits(); } catch (Exception ex) { Log.Error("退出时清理上传限速失败：" + ex.Message); }
                return;
            }
    }
}
