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
        Console.WriteLine($"Network Security Auditor v5.0.0 - Silent Mode");
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

        var (score, grade) = RiskScoreEngine.Calculate(checkVms);
        var (rwScore, rwGrade) = RansomwareReadinessEngine.Calculate(checkVms);
        var passCount = checkVms.Count(c => c.Status == CheckStatus.Pass);
        var failCount = checkVms.Count(c => c.Status == CheckStatus.Fail);
        var partialCount = checkVms.Count(c => c.Status == CheckStatus.Partial);

        Console.WriteLine();
        Console.WriteLine($"  Score: {score}% (Grade: {grade})");
        Console.WriteLine($"  Ransomware Readiness: {rwScore}% ({rwGrade})");
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
        var json = JsonExporter.Export(checkVms, env, score, grade, rwScore, rwGrade, args.ScanProfile);
        await File.WriteAllTextAsync(jsonPath, json);
        Console.WriteLine($"  JSON: {jsonPath}");

        var htmlPath = Path.Combine(outputDir, $"{baseName}.html");
        var html = HtmlReportGenerator.Generate(checkVms, env, score, grade, rwScore, rwGrade);
        await File.WriteAllTextAsync(htmlPath, html);
        Console.WriteLine($"  HTML: {htmlPath}");

        var csvPath = Path.Combine(outputDir, $"{baseName}.csv");
        var csv = CsvExporter.Export(checkVms, env, score, grade);
        await File.WriteAllTextAsync(csvPath, csv);
        Console.WriteLine($"  CSV: {csvPath}");

        var jsonlPath = Path.Combine(outputDir, $"{baseName}_siem.jsonl");
        var jsonl = JsonlExporter.Export(checkVms, env, score, grade, args.ScanProfile);
        await File.WriteAllTextAsync(jsonlPath, jsonl);
        Console.WriteLine($"  JSONL: {jsonlPath}");

        Console.WriteLine();

        int exitCode;
        if (score < 60 || rwScore < 40)
            exitCode = 1;
        else if (failCount > 0)
            exitCode = 2;
        else
            exitCode = 0;

        Console.WriteLine($"  Exit code: {exitCode}");
        Shutdown(exitCode);
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
        }

        return result;
    }

    private sealed class CliArgs
    {
        public bool Silent;
        public bool NoElevate;
        public bool NoInternet;
        public bool PrivacyMode;
        public ScanProfileType ScanProfile = ScanProfileType.Full;
        public string OutputPath = "";
        public string Client = "";
        public string Auditor = "";
    }
}
