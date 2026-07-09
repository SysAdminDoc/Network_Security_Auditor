using System.Diagnostics;
using System.IO;

namespace NetworkSecurityAuditor.Export;

public static class PdfExporter
{
    public static async Task<(bool Success, string Message)> ExportAsync(string htmlPath, string pdfPath)
    {
        var browserPath = FindBrowser();
        if (browserPath is null)
            return (false, "PDF export requires Microsoft Edge or Google Chrome. Neither was found.");

        var targetPath = Path.GetFullPath(pdfPath);
        var targetDirectory = Path.GetDirectoryName(targetPath);
        if (!string.IsNullOrWhiteSpace(targetDirectory))
            Directory.CreateDirectory(targetDirectory);
        if (File.Exists(targetPath))
            File.Delete(targetPath);

        var htmlUri = new Uri(Path.GetFullPath(htmlPath)).AbsoluteUri;

        var psi = new ProcessStartInfo
        {
            FileName = browserPath,
            ArgumentList =
            {
                "--headless",
                "--disable-gpu",
                $"--print-to-pdf={targetPath}",
                htmlUri
            },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
            RedirectStandardError = true
        };

        Process? process = null;
        try
        {
            process = Process.Start(psi);
            if (process is null)
                return (false, "Failed to start browser process.");

            var stderrTask = process.StandardError.ReadToEndAsync();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await process.WaitForExitAsync(cts.Token);

            if (process.ExitCode != 0)
            {
                var stderr = await stderrTask;
                return (false, $"Browser exited with code {process.ExitCode}: {stderr}");
            }

            return File.Exists(targetPath) && new FileInfo(targetPath).Length > 0
                ? (true, targetPath)
                : (false, "Browser completed but PDF file was not created.");
        }
        catch (OperationCanceledException)
        {
            try { process?.Kill(entireProcessTree: true); } catch { }
            return (false, "PDF generation timed out after 30 seconds.");
        }
        catch (Exception ex)
        {
            return (false, $"PDF export failed: {ex.Message}");
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static string? FindBrowser()
    {
        string[] candidates =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                @"Microsoft\Edge\Application\msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Microsoft\Edge\Application\msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                @"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Google\Chrome\Application\chrome.exe"),
        ];

        return candidates.FirstOrDefault(File.Exists);
    }
}
