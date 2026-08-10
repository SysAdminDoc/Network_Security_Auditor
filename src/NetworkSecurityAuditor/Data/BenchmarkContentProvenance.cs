using System.IO;
using System.Security.Cryptography;

namespace NetworkSecurityAuditor.Data;

public sealed record BenchmarkContentVerification(string Sha256, string VerificationStatus);

public static class BenchmarkContentProvenance
{
    public static BenchmarkContentVerification VerifyFile(string path, string? expectedSha256 = null)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A benchmark content path is required.", nameof(path));
        }

        using var stream = File.OpenRead(path);
        using var sha256 = SHA256.Create();
        var digest = Convert.ToHexString(sha256.ComputeHash(stream)).ToLowerInvariant();
        var expected = expectedSha256?.Trim() ?? string.Empty;

        if (expected.Length == 0)
        {
            return new BenchmarkContentVerification(digest, "unverified");
        }

        if (!IsSha256(expected))
        {
            return new BenchmarkContentVerification(digest, "invalid-expected-digest");
        }

        return new BenchmarkContentVerification(
            digest,
            digest.Equals(expected, StringComparison.OrdinalIgnoreCase) ? "verified" : "mismatch");
    }

    public static bool IsSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
        {
            return false;
        }

        return value.All(Uri.IsHexDigit);
    }
}
