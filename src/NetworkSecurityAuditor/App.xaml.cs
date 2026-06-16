using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
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

        var noElevate = e.Args.Any(a => a.Equals("--no-elevate", StringComparison.OrdinalIgnoreCase));

        if (!noElevate && !IsRunningAsAdmin())
        {
            try
            {
                var exePath = System.Environment.ProcessPath;
                if (exePath is not null)
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = exePath,
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    foreach (var arg in e.Args)
                        psi.ArgumentList.Add(arg);

                    Process.Start(psi);
                    Shutdown(0);
                    return;
                }
            }
            catch
            {
                // User declined UAC or elevation failed — continue without admin
            }
        }

        base.OnStartup(e);
    }

    private static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
