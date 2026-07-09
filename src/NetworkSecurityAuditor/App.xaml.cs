using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
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
    private bool _headlessMode;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessDPIAware();

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    protected override void OnStartup(StartupEventArgs e)
    {
        SetProcessDPIAware();

        var args = ParseArgs(e.Args);
        _headlessMode = args.Dashboard || args.Silent;
        RegisterGlobalExceptionHandlers();
        var isRunningAsAdmin = IsRunningAsAdmin();

        if (ShouldAttemptSelfElevation(args, isRunningAsAdmin))
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
                        Verb = "runas",
                        WorkingDirectory = System.Environment.CurrentDirectory
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
        else if (ShouldWarnHeadlessWithoutElevation(args, isRunningAsAdmin))
        {
            AttachParentConsoleIfAvailable();
            Console.Error.WriteLine("WARNING: Headless mode is running without elevation; checks requiring administrator rights may return limited evidence.");
        }

        if (_headlessMode && args.ParseWarnings.Count > 0)
        {
            AttachParentConsoleIfAvailable();
            foreach (var warning in args.ParseWarnings)
                Console.Error.WriteLine($"WARNING: {warning}");
        }

        if (args.Dashboard)
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunHeadlessAndShutdownAsync("Dashboard", () => RunDashboardAsync(args));
            return;
        }

        if (args.Silent)
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunHeadlessAndShutdownAsync("Silent", () => RunSilentAsync(args));
            return;
        }

        if (args.RenderScreenshotPath.Length > 0)
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            var screenshotWindow = CreateMainWindow(args);
            MainWindow = screenshotWindow;
            screenshotWindow.Show();
            _ = CaptureWindowAndShutdownAsync(screenshotWindow, args.RenderScreenshotPath);
            return;
        }

        base.OnStartup(e);
        var window = CreateMainWindow(args);
        MainWindow = window;
        window.Show();
    }

    private async Task CaptureWindowAndShutdownAsync(Window window, string path)
    {
        await Task.Delay(TimeSpan.FromSeconds(5));
        try
        {
            await window.Dispatcher.InvokeAsync(
                () => SaveWindowScreenshot(window, path),
                DispatcherPriority.Render);
        }
        finally
        {
            Shutdown(0);
        }
    }

    private static MainWindow CreateMainWindow(CliArgs args)
    {
        var window = new MainWindow();
        if (args.UiaBackground)
        {
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.Left = -32000;
            window.Top = -32000;
            window.ShowActivated = false;
            window.ShowInTaskbar = false;
        }

        return window;
    }

    private static void SaveWindowScreenshot(Window window, string path)
    {
        var targetPath = Path.GetFullPath(System.Environment.ExpandEnvironmentVariables(path));
        var directory = Path.GetDirectoryName(targetPath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var width = Math.Max(1, (int)Math.Ceiling(window.ActualWidth));
        var height = Math.Max(1, (int)Math.Ceiling(window.ActualHeight));
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(targetPath);
        encoder.Save(stream);
    }

    private void RegisterGlobalExceptionHandlers()
    {
        DispatcherUnhandledException += (_, e) =>
        {
            e.Handled = true;
            HandleGlobalException(e.Exception, "DispatcherUnhandledException", canContinue: !_headlessMode);
            if (_headlessMode)
                Shutdown((int)ExitCode.ImmediateAlert);
        };

        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            HandleGlobalException(e.Exception, "TaskScheduler.UnobservedTaskException", canContinue: true);
            e.SetObserved();
        };

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception ex)
                HandleGlobalException(ex, "AppDomain.UnhandledException", canContinue: false);
        };
    }

    private void HandleGlobalException(Exception exception, string source, bool canContinue)
    {
        var logPath = CrashLogWriter.Write(exception, source);

        if (_headlessMode)
        {
            AttachParentConsoleIfAvailable();
            Console.Error.WriteLine($"ERROR: {source}: {exception.Message}");
            Console.Error.WriteLine($"Crash log: {logPath}");
            return;
        }

        var message = canContinue
            ? $"An unexpected error was handled. Your current audit state is still open.\n\nCrash log: {logPath}"
            : $"A fatal error occurred and was written to the crash log.\n\nCrash log: {logPath}";
        MessageBox.Show(message, "Network Security Auditor", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private async Task RunHeadlessAndShutdownAsync(string modeName, Func<Task<int>> runModeAsync)
    {
        AttachParentConsoleIfAvailable();
        var exitCode = await RunHeadlessWithExitHandlingAsync(modeName, runModeAsync, Console.Error);
        Shutdown(exitCode);
    }

    private static void AttachParentConsoleIfAvailable()
    {
        if (!AttachConsole(-1))
            Debug.WriteLine("Parent console attachment was unavailable or already attached.");
    }

    internal static async Task<int> RunHeadlessWithExitHandlingAsync(
        string modeName,
        Func<Task<int>> runModeAsync,
        TextWriter errorWriter)
    {
        try
        {
            return await runModeAsync();
        }
        catch (Exception ex)
        {
            await errorWriter.WriteLineAsync($"ERROR: {modeName} mode failed: {ex.Message}");
            await errorWriter.WriteLineAsync(ex.ToString());
            return (int)ExitCode.ImmediateAlert;
        }
    }

    internal static bool ShouldAttemptSelfElevation(CliArgs args, bool isRunningAsAdmin)
    {
        if (isRunningAsAdmin || args.NoElevate)
            return false;

        return !args.Silent && !args.Dashboard;
    }

    internal static bool ShouldWarnHeadlessWithoutElevation(CliArgs args, bool isRunningAsAdmin) =>
        !isRunningAsAdmin && !args.NoElevate && (args.Silent || args.Dashboard);

    private async Task<int> RunDashboardAsync(CliArgs args)
    {
        Console.WriteLine();
        Console.WriteLine($"Network Security Auditor v{VersionInfo.Version} - Dashboard Mode");

        var inputDir = args.InputDir.Length > 0
            ? args.InputDir
            : System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop);

        if (!Directory.Exists(inputDir))
        {
            Console.WriteLine($"  ERROR: Input directory not found: {inputDir}");
            return (int)ExitCode.InputPathUnavailable;
        }

        Console.WriteLine($"  Input: {inputDir}");
        Console.WriteLine($"  Stale threshold: {args.StaleDays} days");

        var html = await DashboardGenerator.GenerateAsync(inputDir, args.StaleDays);

        var outputDir = ResolveOutputDirectory(args.OutputPath, inputDir);
        Directory.CreateDirectory(outputDir);

        var dashPath = Path.Combine(outputDir, $"SecurityDashboard_{DateTime.Now:yyyy-MM-dd_HHmm}.html");
        await File.WriteAllTextAsync(dashPath, html);
        Console.WriteLine($"  Dashboard: {dashPath}");

        var csvPath = Path.ChangeExtension(dashPath, ".csv");
        var csv = await DashboardGenerator.GenerateCsvAsync(inputDir, args.StaleDays);
        await File.WriteAllTextAsync(csvPath, csv);
        Console.WriteLine($"  CSV: {csvPath}");

        Console.WriteLine();
        return 0;
    }

    private async Task<int> RunSilentAsync(CliArgs args)
    {
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
        var applicableIds = CheckRunner.ResolveApplicableCheckIds(env, options);

        if (profileIds.Length == 0)
        {
            Console.WriteLine($"Profile {args.ScanProfile} is not available in this preview.");
            Console.WriteLine("No local or Active Directory checks were run. Use the production PowerShell artifact for the current cloud assessment path.");
            return (int)ExitCode.ReviewNeeded;
        }

        if (applicableIds.Length == 0)
        {
            Console.WriteLine($"No checks in the {args.ScanProfile} profile apply to this host/environment.");
            Console.WriteLine("No local or Active Directory checks were run.");
            return (int)ExitCode.NoScorableChecks;
        }

        void WriteProgress((string checkId, CheckResult result) update)
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
            Console.WriteLine($"  [{completed}/{applicableIds.Length}] [{symbol}] {update.checkId}");
        }

        Console.WriteLine($"Running {applicableIds.Length} checks...");
        Console.WriteLine();

        var results = await runner.RunAsync(
            env,
            options,
            progress: null,
            ct: CancellationToken.None,
            completedCallback: WriteProgress);

        var checkVms = new System.Collections.ObjectModel.ObservableCollection<CheckItemViewModel>();
        foreach (var meta in CheckCatalog.All.Values.OrderBy(m => m.Id))
        {
            var vm = CheckItemViewModel.FromMetadata(meta);
            if (results.TryGetValue(meta.Id, out var result))
            {
                vm.Status = result.Status;
                vm.Findings = result.Findings;
                vm.Evidence = result.Evidence;
                vm.DurationMs = result.Duration.TotalMilliseconds;
            }
            checkVms.Add(vm);
        }

        WaiverStore? waiverStore = null;
        var activeWaivedCheckIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
                    activeWaivedCheckIds.Add(vm.Id);
                    activeCount++;
                }
            }
            Console.WriteLine($"  Waivers: {activeCount} active, {expired.Count} expired");
        }

        IntuneStigAuditImport? intuneStigAudit = null;
        if (args.IntuneStigImportPath.Length > 0)
        {
            intuneStigAudit = await IntuneStigAuditImporter.LoadAsync(args.IntuneStigImportPath);
            Console.WriteLine($"  Intune STIG import: {intuneStigAudit.ImportStatus} ({intuneStigAudit.Findings.Count} row(s))");
        }

        var scoredCheckVms = ExcludeWaivedChecksFromScoring(checkVms, activeWaivedCheckIds);
        var scoringWaivedCount = checkVms.Count - scoredCheckVms.Count;
        var (score, grade) = RiskScoreEngine.Calculate(scoredCheckVms);
        var (rwScore, rwGrade) = RansomwareReadinessEngine.Calculate(scoredCheckVms);
        var (dmScore, dmGrade, _) = DomainMaturityEngine.Calculate(scoredCheckVms);
        var passCount = scoredCheckVms.Count(c => c.Status == CheckStatus.Pass);
        var failCount = scoredCheckVms.Count(c => c.Status == CheckStatus.Fail);
        var partialCount = scoredCheckVms.Count(c => c.Status == CheckStatus.Partial);
        var hasScorableChecks = passCount + failCount + partialCount > 0;

        Console.WriteLine();
        Console.WriteLine($"  Score: {score}% (Grade: {grade})");
        Console.WriteLine($"  Ransomware Readiness: {rwScore}% ({rwGrade})");
        Console.WriteLine($"  Domain Maturity: {dmScore}% ({dmGrade})");
        Console.WriteLine($"  Pass: {passCount} | Fail: {failCount} | Partial: {partialCount}");
        if (scoringWaivedCount > 0)
            Console.WriteLine($"  Waived findings excluded from scoring: {scoringWaivedCount}");
        if (!hasScorableChecks)
            Console.WriteLine("  No scorable checks produced Pass, Partial, or Fail evidence.");

        var redactor = PrivacyExportSanitizer.CreateRedactor(
            args.PrivacyMode,
            env,
            System.Environment.UserName,
            options.Client);
        var exportEnv = PrivacyExportSanitizer.RedactEnvironment(env, redactor);
        var exportChecks = PrivacyExportSanitizer.RedactChecks(checkVms, redactor);
        var exportWaivers = PrivacyExportSanitizer.RedactActiveWaivers(waiverStore, redactor);
        var exportIntuneStigAudit = PrivacyExportSanitizer.RedactIntuneStigAudit(intuneStigAudit, redactor);
        var exportClient = redactor.Redact(options.Client);
        var exportAuditor = redactor.Redact(options.Auditor);
        if (args.PrivacyMode)
            Console.WriteLine("  Privacy mode: PII redacted with SHA256 pseudonyms");

        var outputDir = ResolveOutputDirectory(
            args.OutputPath,
            System.Environment.GetFolderPath(System.Environment.SpecialFolder.Desktop));
        Directory.CreateDirectory(outputDir);

        var baseName = $"SecurityAudit_{SafeFileNameSegment(exportClient, "Client")}_{DateTime.Now:yyyy-MM-dd_HHmm}";

        var jsonPath = Path.Combine(outputDir, $"{baseName}_findings.json");
        var json = JsonExporter.Export(exportChecks, exportEnv, score, grade, rwScore, rwGrade, args.ScanProfile, dmScore, dmGrade, client: exportClient, auditor: exportAuditor, intuneStigAudit: exportIntuneStigAudit);
        await File.WriteAllTextAsync(jsonPath, json);
        Console.WriteLine($"  JSON: {jsonPath}");

        BrandingConfig? branding = null;
        if (args.BrandingPath.Length > 0)
        {
            branding = await BrandingConfig.LoadAsync(args.BrandingPath);
            if (branding is not null)
                Console.WriteLine($"  Branding: {branding.CompanyName}");
            else
                Console.WriteLine($"  WARNING: Branding config not found: {args.BrandingPath}");
        }

        var htmlPath = Path.Combine(outputDir, $"{baseName}.html");
        var html = HtmlReportGenerator.Generate(exportChecks, exportEnv, score, grade, rwScore, rwGrade, dmScore, dmGrade, tier: args.ReportTier, branding: branding, intuneStigAudit: exportIntuneStigAudit);
        await File.WriteAllTextAsync(htmlPath, html);
        Console.WriteLine($"  HTML: {htmlPath}");

        if (args.ExportCsv)
        {
            var csvPath = Path.Combine(outputDir, $"{baseName}.csv");
            await File.WriteAllTextAsync(csvPath, CsvExporter.Export(exportChecks, exportEnv, score, grade, exportIntuneStigAudit));
            Console.WriteLine($"  CSV: {csvPath}");
        }

        if (args.ExportJsonl)
        {
            var jsonlPath = Path.Combine(outputDir, $"{baseName}_siem.jsonl");
            await File.WriteAllTextAsync(jsonlPath, JsonlExporter.Export(exportChecks, exportEnv, score, grade, args.ScanProfile));
            Console.WriteLine($"  JSONL: {jsonlPath}");
        }

        if (args.ExportDefectDojo)
        {
            var ddPath = Path.Combine(outputDir, $"{baseName}_defectdojo.json");
            await File.WriteAllTextAsync(ddPath, DefectDojoExporter.Export(exportChecks, exportEnv, score, grade));
            Console.WriteLine($"  DefectDojo: {ddPath}");
        }

        if (args.ExportNavigator)
        {
            var navPath = Path.Combine(outputDir, $"{baseName}_navigator.json");
            await File.WriteAllTextAsync(navPath, NavigatorExporter.Export(exportChecks));
            Console.WriteLine($"  Navigator: {navPath}");
        }

        if (args.ExportSarif)
        {
            var sarifPath = Path.Combine(outputDir, $"{baseName}.sarif");
            await File.WriteAllTextAsync(sarifPath, SarifExporter.Export(exportChecks, exportEnv));
            Console.WriteLine($"  SARIF: {sarifPath}");
        }

        if (args.ExportOcsf)
        {
            var ocsfPath = Path.Combine(outputDir, $"{baseName}_ocsf.jsonl");
            await File.WriteAllTextAsync(ocsfPath, OcsfExporter.Export(exportChecks, exportEnv, score, grade, args.ScanProfile.ToString()));
            Console.WriteLine($"  OCSF: {ocsfPath}");
        }

        if (args.ExportOscal)
        {
            var oscalPath = Path.Combine(outputDir, $"{baseName}_oscal.json");
            await File.WriteAllTextAsync(oscalPath, OscalExporter.Export(exportChecks, exportEnv, score, grade, exportIntuneStigAudit));
            Console.WriteLine($"  OSCAL: {oscalPath}");
        }

        if (args.ExportOscalPoam)
        {
            var oscalPoamPath = Path.Combine(outputDir, $"{baseName}_oscal_poam.json");
            await File.WriteAllTextAsync(oscalPoamPath, OscalPoamExporter.Export(exportChecks, exportEnv, exportWaivers));
            Console.WriteLine($"  OSCAL POA&M: {oscalPoamPath}");
        }

        if (args.ExportIntune)
        {
            var intunePath = Path.Combine(outputDir, $"{baseName}_intune.json");
            await File.WriteAllTextAsync(intunePath, IntuneExporter.Export(exportChecks, exportEnv, score, grade, rwScore, rwGrade));
            Console.WriteLine($"  Intune: {intunePath}");
        }

        if (args.ExportComplianceSummary)
        {
            var summaryPath = Path.Combine(outputDir, $"{baseName}_summary.json");
            await File.WriteAllTextAsync(summaryPath, ComplianceSummaryExporter.Export(exportChecks, exportEnv, score, grade, rwScore, rwGrade, dmScore, dmGrade));
            Console.WriteLine($"  Summary: {summaryPath}");
        }

        if (args.ExportSiem)
        {
            var siemDir = Path.Combine(outputDir, $"{baseName}_siem_configs");
            var siemFiles = SiemContentPackExporter.ExportAll(siemDir);
            Console.WriteLine($"  SIEM configs: {siemDir}");
        }

        if (args.ExportCmmc)
        {
            var cmmcHtmlPath = Path.Combine(outputDir, $"{baseName}_cmmc.html");
            await File.WriteAllTextAsync(cmmcHtmlPath, CmmcReportGenerator.ExportHtml(exportChecks, exportEnv, score, grade));
            Console.WriteLine($"  CMMC HTML: {cmmcHtmlPath}");

            var cmmcJsonPath = Path.Combine(outputDir, $"{baseName}_cmmc.json");
            await File.WriteAllTextAsync(cmmcJsonPath, CmmcReportGenerator.ExportJson(exportChecks, exportEnv));
            Console.WriteLine($"  CMMC JSON: {cmmcJsonPath}");
        }

        if (args.ExportPdf)
        {
            var pdfPath = Path.Combine(outputDir, $"{baseName}.pdf");
            var (pdfOk, pdfMsg) = await PdfExporter.ExportAsync(htmlPath, pdfPath);
            Console.WriteLine(pdfOk ? $"  PDF: {pdfPath}" : $"  PDF: {pdfMsg}");
        }

        Console.WriteLine();

        var exitCode = ExitCode.Green;
        if (!hasScorableChecks)
            exitCode = ExitCode.NoScorableChecks;
        else if (score < 60 || rwScore < 40)
            exitCode = ExitCode.ImmediateAlert;
        else if (HasFrameworkBelowThreshold(scoredCheckVms, 60))
            exitCode = ExitCode.ComplianceAlert;
        else if (failCount > 0)
            exitCode = ExitCode.ReviewNeeded;

        Console.WriteLine($"  Exit code: {(int)exitCode}");
        return (int)exitCode;
    }

    internal static System.Collections.ObjectModel.ObservableCollection<CheckItemViewModel> ExcludeWaivedChecksFromScoring(
        IEnumerable<CheckItemViewModel> checks,
        IReadOnlySet<string> activeWaivedCheckIds)
    {
        return new System.Collections.ObjectModel.ObservableCollection<CheckItemViewModel>(
            checks.Where(check =>
                !activeWaivedCheckIds.Contains(check.Id) ||
                check.Status is not (CheckStatus.Fail or CheckStatus.Partial)));
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

    internal static string ResolveOutputDirectory(string outputPath, string fallbackDirectory)
    {
        var directory = string.IsNullOrWhiteSpace(outputPath)
            ? fallbackDirectory
            : outputPath;

        return Path.GetFullPath(System.Environment.ExpandEnvironmentVariables(directory));
    }

    internal static string SafeFileNameSegment(string value, string fallback)
    {
        var segment = string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
        foreach (var invalid in Path.GetInvalidFileNameChars())
            segment = segment.Replace(invalid, '_');

        segment = segment.Replace(Path.DirectorySeparatorChar, '_')
            .Replace(Path.AltDirectorySeparatorChar, '_');
        return string.IsNullOrWhiteSpace(segment) ? fallback : segment;
    }

    private static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    internal static CliArgs ParseArgs(string[] args)
    {
        var result = new CliArgs();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg.Equals("--dashboard", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Dashboard", StringComparison.OrdinalIgnoreCase))
                result.Dashboard = true;
            else if (arg.Equals("--input-dir", StringComparison.OrdinalIgnoreCase) || arg.Equals("-InputDir", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.InputDir = value;
            }
            else if (arg.Equals("--stale-days", StringComparison.OrdinalIgnoreCase) || arg.Equals("-StaleDays", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value) && int.TryParse(value, out var sd))
                    result.StaleDays = sd;
                else if (i < args.Length && !result.ParseWarnings.Contains($"{arg} requires a value."))
                    result.ParseWarnings.Add($"{arg} must be an integer.");
            }
            else if (arg.Equals("--silent", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Silent", StringComparison.OrdinalIgnoreCase))
                result.Silent = true;
            else if (arg.Equals("--no-elevate", StringComparison.OrdinalIgnoreCase) || arg.Equals("-NoElevate", StringComparison.OrdinalIgnoreCase))
                result.NoElevate = true;
            else if (arg.Equals("--uia-background", StringComparison.OrdinalIgnoreCase))
                result.UiaBackground = true;
            else if (arg.Equals("--render-screenshot", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                {
                    result.UiaBackground = true;
                    result.RenderScreenshotPath = value;
                }
            }
            else if (arg.Equals("--no-internet", StringComparison.OrdinalIgnoreCase) || arg.Equals("-NoInternet", StringComparison.OrdinalIgnoreCase))
                result.NoInternet = true;
            else if (arg.Equals("--privacy", StringComparison.OrdinalIgnoreCase) || arg.Equals("-PrivacyMode", StringComparison.OrdinalIgnoreCase))
                result.PrivacyMode = true;
            else if (arg.Equals("--profile", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ScanProfile", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value) && Enum.TryParse<ScanProfileType>(value, true, out var profile))
                    result.ScanProfile = profile;
                else if (i < args.Length && !result.ParseWarnings.Contains($"{arg} requires a value."))
                    result.ParseWarnings.Add($"{arg} must be a valid scan profile.");
            }
            else if (arg.Equals("--output", StringComparison.OrdinalIgnoreCase) || arg.Equals("-OutputPath", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.OutputPath = value;
            }
            else if (arg.Equals("--client", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Client", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.Client = value;
            }
            else if (arg.Equals("--auditor", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Auditor", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.Auditor = value;
            }
            else if (arg.Equals("--report-tier", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ReportTier", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value) && Enum.TryParse<ReportTier>(value, true, out var rt))
                    result.ReportTier = rt;
                else if (i < args.Length && !result.ParseWarnings.Contains($"{arg} requires a value."))
                    result.ParseWarnings.Add($"{arg} must be a valid report tier.");
            }
            else if (arg.Equals("--waivers", StringComparison.OrdinalIgnoreCase) || arg.Equals("-Waivers", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.WaiversPath = value;
            }
            else if (arg.Equals("--branding", StringComparison.OrdinalIgnoreCase) || arg.Equals("-BrandingConfig", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.BrandingPath = value;
            }
            else if (arg.Equals("--intune-stig-import", StringComparison.OrdinalIgnoreCase) || arg.Equals("-IntuneStigImportPath", StringComparison.OrdinalIgnoreCase))
            {
                if (TryReadValue(args, ref i, arg, result, out var value))
                    result.IntuneStigImportPath = value;
            }
            else if (arg.Equals("--export-csv", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportCSV", StringComparison.OrdinalIgnoreCase))
                result.ExportCsv = true;
            else if (arg.Equals("--export-jsonl", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportJSONL", StringComparison.OrdinalIgnoreCase))
                result.ExportJsonl = true;
            else if (arg.Equals("--export-defectdojo", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportDefectDojo", StringComparison.OrdinalIgnoreCase))
                result.ExportDefectDojo = true;
            else if (arg.Equals("--export-sarif", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportSARIF", StringComparison.OrdinalIgnoreCase))
                result.ExportSarif = true;
            else if (arg.Equals("--export-navigator", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportNavigator", StringComparison.OrdinalIgnoreCase))
                result.ExportNavigator = true;
            else if (arg.Equals("--export-ocsf", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportOCSF", StringComparison.OrdinalIgnoreCase))
                result.ExportOcsf = true;
            else if (arg.Equals("--export-oscal", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportOSCAL", StringComparison.OrdinalIgnoreCase))
                result.ExportOscal = true;
            else if (arg.Equals("--export-oscal-poam", StringComparison.OrdinalIgnoreCase) || arg.Equals("--export-poam", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportOscalPoam", StringComparison.OrdinalIgnoreCase))
                result.ExportOscalPoam = true;
            else if (arg.Equals("--export-intune", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportIntune", StringComparison.OrdinalIgnoreCase))
                result.ExportIntune = true;
            else if (arg.Equals("--export-siem", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportSIEM", StringComparison.OrdinalIgnoreCase))
                result.ExportSiem = true;
            else if (arg.Equals("--export-cmmc", StringComparison.OrdinalIgnoreCase) || arg.Equals("-ExportCMMC", StringComparison.OrdinalIgnoreCase))
                result.ExportCmmc = true;
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
                result.ExportOscalPoam = true;
                result.ExportIntune = true;
                result.ExportComplianceSummary = true;
                result.ExportSiem = true;
                result.ExportCmmc = true;
                result.ExportPdf = true;
            }
            else if (LooksLikeFlag(arg))
            {
                result.ParseWarnings.Add($"Unknown argument ignored: {arg}");
            }
        }

        return result;
    }

    private static bool TryReadValue(string[] args, ref int index, string optionName, CliArgs result, out string value)
    {
        value = "";
        if (index + 1 >= args.Length || LooksLikeFlag(args[index + 1]))
        {
            result.ParseWarnings.Add($"{optionName} requires a value.");
            return false;
        }

        value = args[++index];
        return true;
    }

    private static bool LooksLikeFlag(string value) =>
        value.StartsWith("-", StringComparison.Ordinal);

    internal sealed class CliArgs
    {
        public bool Dashboard;
        public string InputDir = "";
        public int StaleDays = 30;
        public bool Silent;
        public bool NoElevate;
        public bool UiaBackground;
        public string RenderScreenshotPath = "";
        public bool NoInternet;
        public bool PrivacyMode;
        public bool ExportCsv;
        public bool ExportJsonl;
        public bool ExportDefectDojo;
        public bool ExportSarif;
        public bool ExportNavigator;
        public bool ExportOcsf;
        public bool ExportOscal;
        public bool ExportOscalPoam;
        public bool ExportIntune;
        public bool ExportSiem;
        public bool ExportCmmc;
        public bool ExportPdf;
        public bool ExportComplianceSummary;
        public ScanProfileType ScanProfile = ScanProfileType.Full;
        public ReportTier ReportTier = ReportTier.All;
        public string OutputPath = "";
        public string Client = "";
        public string Auditor = "";
        public string WaiversPath = "";
        public string BrandingPath = "";
        public string IntuneStigImportPath = "";
        public List<string> ParseWarnings = [];
    }
}
