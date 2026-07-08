namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Reflection;

public static class ActiveDirectoryValueConverter
{
    public static long GetLargeIntegerValue(object? value)
    {
        if (value is null) return 0;
        if (value is long longValue) return longValue;
        if (value is int intValue) return intValue;

        try
        {
            var type = value.GetType();
            var highPart = Convert.ToInt32(type.InvokeMember(
                "HighPart",
                BindingFlags.GetProperty,
                binder: null,
                target: value,
                args: null));
            var lowPart = Convert.ToInt32(type.InvokeMember(
                "LowPart",
                BindingFlags.GetProperty,
                binder: null,
                target: value,
                args: null));

            return ((long)highPart << 32) | (uint)lowPart;
        }
        catch
        {
            return 0;
        }
    }

    public static DateTime? GetFileTimeUtc(object? value)
    {
        var fileTime = GetLargeIntegerValue(value);
        if (fileTime <= 0) return null;

        try
        {
            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch
        {
            return null;
        }
    }
}
