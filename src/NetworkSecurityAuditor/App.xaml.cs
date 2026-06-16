using System.Runtime.InteropServices;
using System.Windows;

namespace NetworkSecurityAuditor;

public partial class App : Application
{
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessDPIAware();

    protected override void OnStartup(StartupEventArgs e)
    {
        SetProcessDPIAware();
        base.OnStartup(e);
    }
}
