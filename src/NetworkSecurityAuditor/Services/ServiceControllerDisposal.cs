namespace NetworkSecurityAuditor.Services;

using System.ServiceProcess;

internal static class ServiceControllerDisposal
{
    public static void DisposeAll(ServiceController[] services)
    {
        foreach (var service in services)
        {
            service.Dispose();
        }
    }
}
