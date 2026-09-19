using System.Windows;
using NetWatch.Core;

namespace NetWatch.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        Log.Info($"NetWatch 启动，日志文件：{Log.LogFile}");
        DispatcherUnhandledException += (_, ex) =>
        {
            Log.Error("未处理异常：" + ex.Exception);
            MessageBox.Show("发生错误：" + ex.Exception.Message +
                            "\n\n详情已写入日志：" + Log.LogFile,
                            "NetWatch", MessageBoxButton.OK, MessageBoxImage.Warning);
            ex.Handled = true;
        };
    }
}
