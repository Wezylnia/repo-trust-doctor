using System.Xml.Linq;
using RepoTrustDoctor.Analysis.Abstractions;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed partial class NuGetDependencyCollector
{
    private static void ReadNuGetSources(
        AnalysisContext context,
        string configPath,
        DependencyInventoryState state)
    {
        var relativePath = DependencyInventorySupport.Relative(context, configPath);
        if (!DependencyInventorySupport.TryLoadXml(configPath, state.Warnings, relativePath, out var document))
        {
            return;
        }

        foreach (var source in document.Descendants().Where(IsPackageSourceAddElement))
        {
            var name = DependencyInventorySupport.ReadXmlAttribute(source, "key");
            var value = DependencyInventorySupport.ReadXmlAttribute(source, "value");
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            AddSource(relativePath, name.Trim(), value.Trim(), state);
        }
    }

    private static void AddSource(
        string relativePath,
        string name,
        string sourceText,
        DependencyInventoryState state)
    {
        var sourceKind = ClassifySource(sourceText);
        var redacted = RedactUrl(sourceText);
        state.PackageSources.Add(new DependencyPackageSourceInfo(
            DependencyEcosystem.NuGet,
            name,
            redacted,
            relativePath,
            sourceKind.IsLocal,
            sourceKind.IsSecureTransport,
            new Dictionary<string, string> { ["kind"] = sourceKind.Kind }));

        if (!sourceKind.IsSecureTransport)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP013",
                "NuGet package source uses insecure transport",
                Severity.High,
                Confidence.High,
                $"NuGet package source `{name}` uses insecure HTTP transport.",
                "nuget-source",
                $"Package source `{name}` is `{redacted}`.",
                relativePath,
                "Use HTTPS package sources and avoid sending package metadata or credentials over plaintext transport."));
        }

        if (sourceKind.IsLocal)
        {
            state.Findings.Add(DependencyInventorySupport.CreateDependencyFinding(
                "TRUST-DEP014",
                "NuGet package source uses a local path",
                Severity.Low,
                Confidence.Medium,
                $"NuGet package source `{name}` points to a local path.",
                "nuget-source",
                $"Package source `{name}` is local.",
                relativePath,
                "Review local package sources because they can change package origin assumptions and may hide dependency confusion risk."));
        }
    }

    private static bool IsPackageSourceAddElement(XElement element) =>
        element.Name.LocalName == "add" &&
        element.Ancestors().Any(ancestor => ancestor.Name.LocalName == "packageSources");

    private static NuGetSourceKind ClassifySource(string source)
    {
        if (Uri.TryCreate(source, UriKind.Absolute, out var uri))
        {
            if (uri.IsFile)
            {
                return new NuGetSourceKind("local", true, true);
            }

            return new NuGetSourceKind(
                uri.Scheme,
                false,
                uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase));
        }

        return new NuGetSourceKind("local", true, true);
    }

    private static string RedactUrl(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.UserInfo))
        {
            var builder = new UriBuilder(uri) { UserName = "***", Password = "***" };
            return builder.Uri.ToString();
        }

        return value;
    }

    private sealed record NuGetSourceKind(string Kind, bool IsLocal, bool IsSecureTransport);
}
