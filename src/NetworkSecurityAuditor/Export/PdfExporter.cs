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

        var htmlUri = new Uri(Path.GetFullPath(htmlPath)).AbsoluteUri;

        var psi = new ProcessStartInfo
        {
            FileName = browserPath,
            ArgumentList =
            {
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                $"--print-to-pdf={Path.GetFullPath(pdfPath)}",
                htmlUri
            },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        try
        {
            using var process = Process.Start(psi);
            if (process is null)
                return (false, "Failed to start browser process.");

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await process.WaitForExitAsync(cts.Token);

            if (process.ExitCode != 0)
            {
                var stderr = await process.StandardError.ReadToEndAsync();
                return (false, $"Browser exited with code {process.ExitCode}: {stderr}");
            }

            return File.Exists(pdfPath)
                ? (true, pdfPath)
                : (false, "Browser completed but PDF file was not created.");
        }
        catch (OperationCanceledException)
        {
            return (false, "PDF generation timed out after 30 seconds.");
        }
        catch (Exception ex)
        {
            return (false, $"PDF export failed: {ex.Message}");
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
