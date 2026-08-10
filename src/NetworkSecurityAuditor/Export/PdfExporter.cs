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

        var tempPath = Path.Combine(
            targetDirectory ?? Path.GetTempPath(),
            $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}.tmp.pdf");

        var htmlUri = new Uri(Path.GetFullPath(htmlPath)).AbsoluteUri;

        var psi = new ProcessStartInfo
        {
            FileName = browserPath,
            ArgumentList =
            {
                "--headless",
                "--disable-gpu",
                $"--print-to-pdf={tempPath}",
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

            if (!File.Exists(tempPath) || new FileInfo(tempPath).Length == 0)
                return (false, "Browser completed but PDF file was not created.");

            CommitPdf(tempPath, targetPath);
            return (true, targetPath);
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
            try
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
            catch
            {
                // Best-effort cleanup; preserve the original export result.
            }
        }
    }

    internal static void CommitPdf(string tempPath, string targetPath)
    {
        if (!File.Exists(tempPath) || new FileInfo(tempPath).Length == 0)
            throw new InvalidDataException("Generated PDF is missing or empty.");

        File.Move(tempPath, Path.GetFullPath(targetPath), overwrite: true);
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
