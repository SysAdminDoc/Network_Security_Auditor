using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using NetworkSecurityAuditor.Checks;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.Services;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor;

public partial class App : Application
{
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessDPIAware();

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    protected override void OnStartup(StartupEventArgs e)
    {
        SetProcessDPIAware();

        var args = ParseArgs(e.Args);

        if (!args.NoElevate && !IsRunningAsAdmin())
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
            catch { }
        }

        if (args.Silent)
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunSilentAsync(args);
            return;
        }

        base.OnStartup(e);
        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    private async Task RunSilentAsync(CliArgs args)
    {
        AttachConsole(-1);

        Console.WriteLine();
        Console.WriteLine($"Network Security Auditor v{VersionInfo.Version} - Silent Mode");
        Console.WriteLine($"Profile: {args.ScanProfile} | ReadOnly: true");
        Console.WriteLine();

        var env = EnvironmentDetector.Detect();
        Console.WriteLine($"Host: {env.ComputerName} | OS: {env.OSCaption} | Admin: {env.IsAdmin} | Domain: {env.IsDomainJoined}");

        var options = new AuditOptions
        {
            Silent = true,
            ScanProfile = args.ScanProfile,
            OutputPath = args.OutputPath,
            NoInternet = args.NoInternet,
            Client = args.Client.Length > 0 ? args.Client : env.ComputerName,
            Auditor = args.Auditor.Length > 0 ? args.Auditor : System.Environment.UserName
        };

        var allChecks = CheckRegistry.GetAllChecks();
        var runner = new CheckRunner(allChecks);
        var completed = 0;
        var profileIds = ScanProfiles.Resolve(args.ScanProfile);

        var progress = new Progress<(string checkId, CheckResult result)>(update =>
        {
            completed++;
            var symbol = update.result.Status switch
            {
                CheckStatus.Pass => "PASS",
                CheckStatus.Partial => "PART",
                CheckStatus.Fail => "FAIL",
                CheckStatus.NA => "N/A ",
                _ => "----"
            };
            Console.WriteLine($"  [{completed}/{profileIds.Length}] [{symbol}] {update.checkId}");
        });

        Console.WriteLine($"Running {profileIds.Length} checks...");
        Console.WriteLine();

        var results = await runner.RunAsync(env, options, progress, CancellationToken.None);

        var checkVms = new System.Collections.ObjectModel.ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.OrderBy(m => m.Id))
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            if (results.TryGetValue(meta.Id, out var result))
            {
                vm.Status = result.Status;
                vm.Findings = result.Findings;
                vm.Evidence = result.Evidence;
            }
            checkVms.Add(vm);
        }

        WaiverStore? waiverStore = null;
        if (args.WaiversPath.Length > 0)
        {
            waiverStore = await WaiverStore.LoadFromFileAsync(args.WaiversPath);
            var expired = waiverStore.GetExpired();
            if (expired.Count > 0)
            {
                Console.WriteLine($"  WARNING: {expired.Count} expired waiver(s):");
                foreach (var ew in expired)
                    Console.WriteLine($"    {ew.CheckId}: expired {ew.ExpirationDate:yyyy-MM-dd} ({ew.Justification})");
            }
            var activeCount = 0;
            foreach (var vm in checkVms)
            {
                var waiver = waiverStore.GetActive(vm.Id);
                if (waiver is not null)
                {
                    vm.Notes = $"[ACCEPTED RISK] {waiver.Justification} (approved by {waiver.ApprovedBy}{(waiver.ExpirationDate.HasValue ? $", expires {waiver.ExpirationDate:yyyy-MM-dd}" : "")})";
                    activeCount++;
                }
            }
            Console.WriteLine($"  Waivers: {activeCount} active, {expired.Count} expired");
        }

        var (score, grade) = RiskScoreEngine.Calculate(checkVms);
        var (rwScore, rwGrade) = RansomwareReadinessEngine.Calculate(checkVms);
        var (dmScore, dmGrade, _) = DomainMaturityEngine.Calculate(checkVms);
        var passCount = checkVms.Count(c => c.Status == CheckStatus.Pass);
        var failCount = checkVms.Count(c => c.Status == CheckStatus.Fail);
        var partialCount = checkVms.Count(c => c.Status == CheckStatus.Partial);

        Console.WriteLine();
        Console.WriteLine($"  Score: {score}% (Grade: {grade})");
        Console.WriteLine($"  Ransomware Readiness: {rwScore}% ({rwGrade})");
        Console.WriteLine($"  Domain Maturity: {dmScore}% ({dmGrade})");
        Console.WriteLine($"  Pass: {passCount} | Fail: {failCount} | Partial: {partialCount}");

        if (args.PrivacyMode)
        {
            var redactor = new PrivacyRedactor(true, env.ComputerName, env.DomainName,
                System.Environment.UserName, options.Client);
            foreach (var vm in checkVms)
            {
                vm.Findings = redactor.Redact(vm.Findings);
                vm.Evidence = redactor.Redact(vm.Evidence);
            }
            Console.WriteLine("  Privacy mode: PII redacted with SHA256 pseudonyms");
        }

        var outputDir = args.OutputPath.Length > 0
            ? Path.GetDirectoryName(args.OutputPath) ?? System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop)
            : System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop);
        Directory.CreateDirectory(outputDir);

        var baseName = $"SecurityAudit_{options.Client}_{DateTime.Now:yyyy-MM-dd_HHmm}";

        var jsonPath = Path.Combine(outputDir, $"{baseName}_findings.json");
        var json = JsonExporter.Export(checkVms, env, score, grade, rwScore, rwGrade, args.ScanProfile, dmScore, dmGrade);
        await File.WriteAllTextAsync(jsonPath, json);
        Console.WriteLine($"  JSON: {jsonPath}");

        var htmlPath = Path.Combine(outputDir, $"{baseName}.html");
        var html = HtmlReportGenerator.Generate(checkVms, env, score, grade, rwScore, rwGrade, dmScore, dmGrade, tier: args.ReportTier);
        await File.WriteAllTextAsync(htmlPath, html);
        Console.WriteLine($"  HTML: {htmlPath}");

        if (args.ExportCsv)
        {
            var csvPath = Path.Combine(outputDir, $"{baseName}.csv");
            await File.WriteAllTextAsync(csvPath, CsvExporter.Export(checkVms, env, score, grade));
            Console.WriteLine($"  CSV: {csvPath}");
        }

        if (args.ExportJsonl)
        {
            var jsonlPath = Path.Combine(outputDir, $"{baseName}_siem.jsonl");
            await File.WriteAllTextAsync(jsonlPath, JsonlExporter.Export(checkVms, env, score, grade, args.ScanProfile));
            Console.WriteLine($"  JSONL: {jsonlPath}");
        }

        if (args.ExportDefectDojo)
        {
            var ddPath = Path.Combine(outputDir, $"{baseName}_defectdojo.json");
            await File.WriteAllTextAsync(ddPath, DefectDojoExporter.Export(checkVms, env, score, grade));
            Console.WriteLine($"  DefectDojo: {ddPath}");
        }

        if (args.ExportNavigator)
        {
            var navPath = Path.Combine(outputDir, $"{baseName}_navigator.json");
            await File.WriteAllTextAsync(navPath, NavigatorExporter.Export(checkVms));
            Console.WriteLine($"  Navigator: {navPath}");
        }

        if (args.ExportSarif)
        {
            var sarifPath = Path.Combine(outputDir, $"{baseName}.sarif");
            await File.WriteAllTextAsync(sarifPath, SarifExporter.Export(checkVms, env));
            Console.WriteLine($"  SARIF: {sarifPath}");
        }

        if (args.ExportOcsf)
        {
            var ocsfPath = Path.Combine(outputDir, $"{baseName}_ocsf.jsonl");
            await File.WriteAllTextAsync(ocsfPath, OcsfExporter.Export(checkVms, env, score, grade, args.ScanProfile.ToString()));
            Console.WriteLine($"  OCSF: {ocsfPath}");
        }

        if (args.ExportOscal)
        {
            var oscalPath = Path.Combine(outputDir, $"{baseName}_oscal.json");
            await File.WriteAllTextAsync(oscalPath, OscalExporter.Export(checkVms, env, score, grade));
            Console.WriteLine($"  OSCAL: {oscalPath}");
        }

        if (args.ExportIntune)
        {
            var intunePath = Path.Combine(outputDir, $"{baseName}_intune.json");
            await File.WriteAllTextAsync(intunePath, IntuneExporter.Export(checkVms, env, score, grade, rwScore, rwGrade));
            Console.WriteLine($"  Intune: {intunePath}");
        }

        if (args.ExportComplianceSummary)
        {
            var summaryPath = Path.Combine(outputDir, $"{baseName}_summary.json");
            await File.WriteAllTextAsync(summaryPath, ComplianceSummaryExporter.Export(checkVms, env, score, grade, rwScore, rwGrade, dmScore, dmGrade));
            Console.WriteLine($"  Summary: {summaryPath}");
        }

        if (args.ExportPdf)
        {
            var pdfPath = Path.Combine(outputDir, $"{baseName}.pdf");
            var (pdfOk, pdfMsg) = await PdfExporter.ExportAsync(htmlPath, pdfPath);
            Console.WriteLine(pdfOk ? $"  PDF: {pdfPath}" : $"  PDF: {pdfMsg}");
        }

        Console.WriteLine();

        var exitCode = ExitCode.Green;
        if (score < 60 || rwScore < 40)
            exitCode = ExitCode.ImmediateAlert;
        else if (HasFrameworkBelowThreshold(checkVms, 60))
            exitCode = ExitCode.ComplianceAlert;
        else if (failCount > 0)
            exitCode = ExitCode.ReviewNeeded;

        Console.WriteLine($"  Exit code: {(int)exitCode}");
        Shutdown((int)exitCode);
    }

    private static bool HasFrameworkBelowThreshold(
        System.Collections.ObjectModel.ObservableCollection<CheckItemViewModel> checks, int threshold)
    {
        var statusLookup = checks.ToDictionary(c => c.Id, c => c.Status, StringComparer.OrdinalIgnoreCase);
        foreach (var (_, selector) in Data.FrameworkDefinitions.All)
        {
            var mapped = Data.FrameworkMappings.All
                .Where(kv => selector(kv.Value) is not null)
                .Select(kv => kv.Key)
                .ToList();
            int total = 0, passing = 0;
            foreach (var checkId in mapped)
            {
                if (!statusLookup.TryGetValue(checkId, out var status)) continue;
                if (status is Models.CheckStatus.NA or Models.CheckStatus.NotAssessed) continue;
                total++;
                if (status is Models.CheckStatus.Pass or Models.CheckStatus.Partial)
                    passing++;
            }
            if (total > 0 && (double)passing / total * 100 < threshold)
                return true;
        }
        return false;
    }

    private static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static CliArgs ParseArgs(string[] args)
    {
        var result = new CliArgs();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg.Equals("--silent", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Silent", StringComparison.OrdinalIgnoreCase))
                result.Silent = true;
            else if (arg.Equals("--no-elevate", StringComparison.OrdinalIgnoreCase))
                result.NoElevate = true;
            else if (arg.Equals("--no-internet", StringComparison.OrdinalIgnoreCase) || arg.Equals("-NoInternet", StringComparison.OrdinalIgnoreCase))
                result.NoInternet = true;
            else if (arg.Equals("--privacy", StringComparison.OrdinalIgnoreCase) || arg.Equals("-PrivacyMode", StringComparison.OrdinalIgnoreCase))
                result.PrivacyMode = true;
            else if ((arg.Equals("--profile", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ScanProfile", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
            {
                if (Enum.TryParse<ScanProfileType>(args[++i], true, out var profile))
                    result.ScanProfile = profile;
            }
            else if ((arg.Equals("--output", StringComparison.OrdinalIgnoreCase) || arg.Equals("-OutputPath", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                result.OutputPath = args[++i];
            else if ((arg.Equals("--client", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Client", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                result.Client = args[++i];
            else if ((arg.Equals("--auditor", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Auditor", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                result.Auditor = args[++i];
            else if ((arg.Equals("--report-tier", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ReportTier", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
            {
                if (Enum.TryParse<ReportTier>(args[++i], true, out var rt))
                    result.ReportTier = rt;
            }
            else if ((arg.Equals("--waivers", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Waivers", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                result.WaiversPath = args[++i];
            else if (arg.Equals("--export-csv", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportCSV", StringComparison.OrdinalIgnoreCase))
                result.ExportCsv = true;
            else if (arg.Equals("--export-jsonl", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportJSONL", StringComparison.OrdinalIgnoreCase))
                result.ExportJsonl = true;
            else if (arg.Equals("--export-defectdojo", StringComparison.OrdinalIgnoreCase))
                result.ExportDefectDojo = true;
            else if (arg.Equals("--export-sarif", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportSARIF", StringComparison.OrdinalIgnoreCase))
                result.ExportSarif = true;
            else if (arg.Equals("--export-navigator", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportNavigator", StringComparison.OrdinalIgnoreCase))
                result.ExportNavigator = true;
            else if (arg.Equals("--export-ocsf", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportOCSF", StringComparison.OrdinalIgnoreCase))
                result.ExportOcsf = true;
            else if (arg.Equals("--export-oscal", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportOSCAL", StringComparison.OrdinalIgnoreCase))
                result.ExportOscal = true;
            else if (arg.Equals("--export-intune", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportIntune", StringComparison.OrdinalIgnoreCase))
                result.ExportIntune = true;
            else if (arg.Equals("--export-pdf", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportPDF", StringComparison.OrdinalIgnoreCase))
                result.ExportPdf = true;
            else if (arg.Equals("--export-compliance-summary", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportComplianceSummary", StringComparison.OrdinalIgnoreCase))
                result.ExportComplianceSummary = true;
            else if (arg.Equals("--export-all", StringComparison.OrdinalIgnoreCase))
            {
                result.ExportCsv = true;
                result.ExportJsonl = true;
                result.ExportDefectDojo = true;
                result.ExportSarif = true;
                result.ExportNavigator = true;
                result.ExportOcsf = true;
                result.ExportOscal = true;
                result.ExportIntune = true;
                result.ExportComplianceSummary = true;
            }
        }

        return result;
    }

    private sealed class CliArgs
    {
        public bool Silent;
        public bool NoElevate;
        public bool NoInternet;
        public bool PrivacyMode;
        public bool ExportCsv;
        public bool ExportJsonl;
        public bool ExportDefectDojo;
        public bool ExportSarif;
        public bool ExportNavigator;
        public bool ExportOcsf;
        public bool ExportOscal;
        public bool ExportIntune;
        public bool ExportPdf;
        public bool ExportComplianceSummary;
        public ScanProfileType ScanProfile = ScanProfileType.Full;
        public ReportTier ReportTier = ReportTier.All;
        public string OutputPath = "";
        public string Client = "";
        public string Auditor = "";
        public string WaiversPath = "";
    }
}
