using System;

namespace RepoTrustDoctor.Analyzers.Secrets;

internal static class SecretEvidenceRedactor
{
    public static string Redact(string rawValue)
    {
        if (string.IsNullOrEmpty(rawValue))
        {
            return "[redacted]";
        }

        // GitHub tokens: e.g. ghp_...
        if (rawValue.StartsWith("ghp_", StringComparison.OrdinalIgnoreCase))
        {
            return "ghp_[redacted]";
        }
        if (rawValue.StartsWith("gho_", StringComparison.OrdinalIgnoreCase))
        {
            return "gho_[redacted]";
        }
        if (rawValue.StartsWith("ghu_", StringComparison.OrdinalIgnoreCase))
        {
            return "ghu_[redacted]";
        }
        if (rawValue.StartsWith("ghs_", StringComparison.OrdinalIgnoreCase))
        {
            return "ghs_[redacted]";
        }
        if (rawValue.StartsWith("ghr_", StringComparison.OrdinalIgnoreCase))
        {
            return "ghr_[redacted]";
        }

        // AWS Access Keys: e.g. AKIA...
        if (rawValue.StartsWith("AKIA", StringComparison.OrdinalIgnoreCase) && rawValue.Length >= 4)
        {
            return "AKIA[redacted]";
        }

        // Slack webhooks: e.g. https://hooks.slack.com/services/...
        if (rawValue.StartsWith("https://hooks.slack.com/services/", StringComparison.OrdinalIgnoreCase))
        {
            return "https://hooks.slack.com/services/[redacted]";
        }

        // Discord webhooks: e.g. https://discord.com/api/webhooks/... or https://discordapp.com/api/webhooks/...
        if (rawValue.StartsWith("https://discord.com/api/webhooks/", StringComparison.OrdinalIgnoreCase))
        {
            return "https://discord.com/api/webhooks/[redacted]";
        }
        if (rawValue.StartsWith("https://discordapp.com/api/webhooks/", StringComparison.OrdinalIgnoreCase))
        {
            return "https://discordapp.com/api/webhooks/[redacted]";
        }

        // Connection string
        if (rawValue.Contains("Password", StringComparison.OrdinalIgnoreCase) ||
            rawValue.Contains("Pwd", StringComparison.OrdinalIgnoreCase) ||
            rawValue.Contains("User Id", StringComparison.OrdinalIgnoreCase) ||
            rawValue.Contains("Username", StringComparison.OrdinalIgnoreCase) ||
            rawValue.Contains("Uid", StringComparison.OrdinalIgnoreCase) ||
            rawValue.Contains("Server", StringComparison.OrdinalIgnoreCase) ||
            rawValue.Contains("Host", StringComparison.OrdinalIgnoreCase))
        {
            return "Server=[redacted];User Id=[redacted];Password=[redacted]";
        }

        return "[redacted]";
    }
}
