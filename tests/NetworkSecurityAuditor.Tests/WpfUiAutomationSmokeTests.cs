using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Automation;

namespace NetworkSecurityAuditor.Tests;

[Collection(NonParallelTestCollection.Name)]
public class WpfUiAutomationSmokeTests
{
    private static readonly TimeSpan WindowTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ElementTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    public void Main_Window_Exposes_Accessible_Landmarks_In_Background_Mode()
    {
        var appPath = FindAppExecutable();
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(appPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(appPath) ?? FindRepoRoot(),
            },
        };
        process.StartInfo.ArgumentList.Add("--no-elevate");
        process.StartInfo.ArgumentList.Add("--uia-background");

        Assert.True(process.Start(), $"Failed to launch {appPath}.");
        try
        {
            TryWaitForInputIdle(process);

            var window = WaitForMainWindow(process, WindowTimeout);
            Assert.Equal("Network Security Auditor", window.Current.Name);
            Assert.Equal(ControlType.Window, window.Current.ControlType);
            Assert.False(window.Current.HasKeyboardFocus);
            Assert.True(
                window.Current.BoundingRectangle.Left <= -30000,
                $"Expected UIA background window to stay offscreen; actual bounds were {window.Current.BoundingRectangle}.");

            AssertNamedElement(window, "CategoryRail", "Category progress navigation", ControlType.List);
            AssertNamedElement(window, "PrivacyModeToggle", "Privacy mode", ControlType.CheckBox);
            AssertNamedElement(window, "ScanProfileSelector", "Scan profile selector", ControlType.ComboBox);
            AssertNamedElement(window, "ScanReadinessStatus", "Scan readiness", ControlType.Text);
            AssertNamedElement(window, "ScanProgressText", "Scan progress", ControlType.Text);

            var startButton = AssertNamedElement(window, "StartScanButton", "Start security scan", ControlType.Button);
            Assert.True(startButton.Current.IsEnabled);
            var stopButton = AssertNamedElement(window, "StopScanButton", "Stop running scan", ControlType.Button);
            Assert.False(stopButton.Current.IsEnabled);

            AssertNamedElement(window, "ExportFormatSelector", "Export format selector", ControlType.ComboBox);
            AssertNamedElement(window, "ExportOutputFolder", "Export output folder", ControlType.Edit);
            AssertNamedElement(window, "BrowseExportFolderButton", "Browse export folder", ControlType.Button);
            AssertNamedElement(window, "SaveAuditStateButton", "Save audit state", ControlType.Button);
            AssertNamedElement(window, "LoadAuditStateButton", "Load audit state", ControlType.Button);
            var exportButton = AssertNamedElement(window, "ExportSelectedFormatButton", "Export selected format", ControlType.Button);
            Assert.False(exportButton.Current.IsEnabled);
            Assert.False(string.IsNullOrWhiteSpace(exportButton.Current.HelpText));

            AssertNamedElement(window, "StatusFilter", "Status filter", ControlType.ComboBox);
            AssertNamedElement(window, "CheckSearchBox", "Search checks", ControlType.Edit);
            AssertNamedElement(window, "FilteredChecksList", "Filtered security checks", ControlType.List);
            AssertElementNameStartsWith(window, "InspectorStatusSelector", "Status for ", ControlType.ComboBox);
            AssertElementNameStartsWith(window, "InspectorFindingsTextBox", "Findings for ", ControlType.Edit);
            AssertElementNameStartsWith(window, "InspectorEvidenceTextBox", "Evidence for ", ControlType.Edit);
            AssertElementNameStartsWith(window, "InspectorNotesTextBox", "Remediation notes for ", ControlType.Edit);
            AssertElementNameStartsWith(window, "InspectorAssigneeTextBox", "Remediation assignee for ", ControlType.Edit);
            AssertElementNameStartsWith(window, "InspectorDueDateTextBox", "Remediation due date for ", ControlType.Edit);
            AssertNamedElement(window, "ActivityLogList", "Scan activity log");
            AssertNamedElement(window, "ExportAvailabilityText", "Export availability", ControlType.Text);
        }
        finally
        {
            CloseProcess(process);
        }
    }

    private static AutomationElement AssertNamedElement(
        AutomationElement root,
        string automationId,
        string expectedName,
        ControlType? expectedControlType = null)
    {
        var element = WaitForElement(root, automationId, ElementTimeout);
        Assert.Equal(expectedName, element.Current.Name);
        if (expectedControlType is not null)
            Assert.Equal(expectedControlType, element.Current.ControlType);
        return element;
    }

    private static AutomationElement AssertElementNameStartsWith(
        AutomationElement root,
        string automationId,
        string expectedPrefix,
        ControlType expectedControlType)
    {
        var element = WaitForElement(root, automationId, ElementTimeout);
        Assert.StartsWith(expectedPrefix, element.Current.Name, StringComparison.Ordinal);
        Assert.Equal(expectedControlType, element.Current.ControlType);
        return element;
    }

    private static AutomationElement WaitForMainWindow(Process process, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow.Add(timeout);
        while (DateTime.UtcNow < deadline)
        {
            if (process.HasExited)
                throw new InvalidOperationException($"NetworkSecurityAuditor exited early with code {process.ExitCode}.");

            process.Refresh();
            var handle = process.MainWindowHandle;
            if (handle == IntPtr.Zero)
                handle = FindTopLevelWindow(process.Id);
            if (handle != IntPtr.Zero)
                return AutomationElement.FromHandle(handle);

            Thread.Sleep(100);
        }

        throw new TimeoutException($"NetworkSecurityAuditor did not expose a main window within {timeout.TotalSeconds:N0} seconds.");
    }

    private static IntPtr FindTopLevelWindow(int processId)
    {
        IntPtr match = IntPtr.Zero;
        EnumWindows((handle, parameter) =>
        {
            GetWindowThreadProcessId(handle, out var windowProcessId);
            if (windowProcessId != (uint)processId || !IsWindowVisible(handle))
                return true;

            var title = GetWindowTitle(handle);
            if (!title.Contains("Network Security Auditor", StringComparison.OrdinalIgnoreCase))
                return true;

            match = handle;
            return false;
        }, IntPtr.Zero);

        return match;
    }

    private static string GetWindowTitle(IntPtr handle)
    {
        var buffer = new StringBuilder(256);
        _ = GetWindowText(handle, buffer, buffer.Capacity);
        return buffer.ToString();
    }

    private static AutomationElement WaitForElement(AutomationElement root, string automationId, TimeSpan timeout)
    {
        var condition = new PropertyCondition(AutomationElement.AutomationIdProperty, automationId);
        var deadline = DateTime.UtcNow.Add(timeout);
        while (DateTime.UtcNow < deadline)
        {
            var element = root.FindFirst(TreeScope.Descendants, condition);
            if (element is not null)
                return element;

            Thread.Sleep(100);
        }

        throw new TimeoutException($"Could not find UI Automation element '{automationId}' within {timeout.TotalSeconds:N0} seconds.");
    }

    private static void TryWaitForInputIdle(Process process)
    {
        try
        {
            process.WaitForInputIdle(5000);
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static void CloseProcess(Process process)
    {
        if (process.HasExited)
            return;

        try
        {
            process.CloseMainWindow();
            if (process.WaitForExit(5000))
                return;
        }
        catch (InvalidOperationException)
        {
            if (process.HasExited)
                return;
        }

        process.Kill(entireProcessTree: true);
        process.WaitForExit(5000);
    }

    private static string FindAppExecutable()
    {
        var repoRoot = FindRepoRoot();
        var configuration = AppContext.BaseDirectory.Contains($"{Path.DirectorySeparatorChar}Release{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
            ? "Release"
            : "Debug";
        var preferred = Path.Combine(
            repoRoot,
            "src",
            "NetworkSecurityAuditor",
            "bin",
            configuration,
            "net10.0-windows",
            "NetworkSecurityAuditor.exe");
        if (File.Exists(preferred))
            return preferred;

        var binRoot = Path.Combine(repoRoot, "src", "NetworkSecurityAuditor", "bin");
        if (!Directory.Exists(binRoot))
            throw new FileNotFoundException($"NetworkSecurityAuditor build output was not found under {binRoot}.");

        var candidate = Directory
            .EnumerateFiles(binRoot, "NetworkSecurityAuditor.exe", SearchOption.AllDirectories)
            .Where(path => path.Contains($"{Path.DirectorySeparatorChar}net10.0-windows{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(path => path.Contains($"{Path.DirectorySeparatorChar}{configuration}{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();

        return candidate ?? throw new FileNotFoundException($"NetworkSecurityAuditor.exe was not found under {binRoot}.");
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }

    private delegate bool EnumWindowsProc(IntPtr handle, IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr handle);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr handle, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr handle, StringBuilder text, int maxCount);
}
