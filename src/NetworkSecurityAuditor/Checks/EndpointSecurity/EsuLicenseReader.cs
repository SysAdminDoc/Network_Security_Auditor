namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;

/// <summary>
/// Reads the Windows 10 Extended Security Updates add-on licenses. SoftwareLicensingProduct is readable
/// without elevation; a licensed ESU year shows up with LicenseStatus 1.
/// </summary>
internal static class EsuLicenseReader
{
    internal const string Query =
        "SELECT ID, Name, LicenseStatus FROM SoftwareLicensingProduct WHERE LicenseStatus = 1 AND PartialProductKey IS NOT NULL";

    public static (EsuEnrollment Enrollment, DateOnly? CoversUntil, string Detail) ReadWindows10Esu(CancellationToken ct)
    {
        var licensed = new List<(string Id, string Name)>();
        try
        {
            using var searcher = new ManagementObjectSearcher(Query);
            using var results = searcher.Get();
            foreach (ManagementObject product in results)
            {
                using (product)
                {
                    ct.ThrowIfCancellationRequested();
                    licensed.Add((product["ID"]?.ToString() ?? "", product["Name"]?.ToString() ?? ""));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return (EsuEnrollment.Unknown, null, $"couldn't read licenses ({ex.Message.Trim()})");
        }

        return Evaluate(licensed);
    }

    /// <summary>Picks the latest ESU year among licensed products, by activation ID or an ESU product name.</summary>
    internal static (EsuEnrollment Enrollment, DateOnly? CoversUntil, string Detail) Evaluate(IEnumerable<(string Id, string Name)> licensed)
    {
        (int Year, DateOnly Until)? best = null;
        foreach (var (id, name) in licensed)
        {
            (int Year, DateOnly Until)? match = null;
            if (Guid.TryParse(id, out var guid) && LifecycleTable.Windows10EsuYears.FirstOrDefault(y => y.ActivationId == guid) is { Year: > 0 } byId)
                match = (byId.Year, byId.CoversUntil);
            else if (Regex.Match(name, @"\bESU\b.*?Year\s*(\d)", RegexOptions.IgnoreCase) is { Success: true } m &&
                     LifecycleTable.Windows10EsuYears.FirstOrDefault(y => y.Year == int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)) is { Year: > 0 } byName)
                match = (byName.Year, byName.CoversUntil);

            if (match is { } found && (best is null || found.Year > best.Value.Year))
                best = found;
        }

        return best is { } b
            ? (EsuEnrollment.Enrolled, b.Until, $"ESU Year {b.Year} licensed, covers until {LifecycleVerdict.Format(b.Until)}")
            : (EsuEnrollment.NotEnrolled, null, "no ESU license found");
    }
}
