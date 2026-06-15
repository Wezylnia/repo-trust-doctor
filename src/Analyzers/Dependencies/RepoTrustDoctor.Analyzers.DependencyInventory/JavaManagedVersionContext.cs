using System.Xml.Linq;
using RepoTrustDoctor.Domain;

namespace RepoTrustDoctor.Analyzers.DependencyInventory;

internal sealed record JavaManagementDecision(
    bool SuppressFinding,
    Confidence Confidence,
    string? VersionSource,
    string? ResolvedVersion = null);

internal sealed class MavenManagedVersionContext
{
    private readonly IReadOnlyDictionary<string, string> managedVersions;
    private readonly bool hasPotentialManagement;
    private readonly bool usesSpringBootParent;

    private MavenManagedVersionContext(
        IReadOnlyDictionary<string, string> managedVersions,
        bool hasPotentialManagement,
        bool usesSpringBootParent)
    {
        this.managedVersions = managedVersions;
        this.hasPotentialManagement = hasPotentialManagement;
        this.usesSpringBootParent = usesSpringBootParent;
    }

    public static MavenManagedVersionContext Create(
        XDocument document,
        IReadOnlyDictionary<string, string> properties)
    {
        var managedVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dependency in document
                     .Descendants()
                     .Where(element =>
                         element.Name.LocalName == "dependency" &&
                         element.Ancestors().Any(ancestor => ancestor.Name.LocalName == "dependencyManagement")))
        {
            var groupId = ReadChild(dependency, "groupId");
            var artifactId = ReadChild(dependency, "artifactId");
            var version = ResolveProperty(ReadChild(dependency, "version"), properties);
            if (!string.IsNullOrWhiteSpace(groupId) &&
                !string.IsNullOrWhiteSpace(artifactId) &&
                !string.IsNullOrWhiteSpace(version))
            {
                managedVersions[Coordinate(groupId, artifactId)] = version;
            }
        }

        var parent = document.Root?
            .Elements()
            .FirstOrDefault(element => element.Name.LocalName == "parent");
        var usesSpringBootParent =
            ReadChild(parent, "groupId")?.Equals("org.springframework.boot", StringComparison.OrdinalIgnoreCase) == true &&
            ReadChild(parent, "artifactId")?.Equals("spring-boot-starter-parent", StringComparison.OrdinalIgnoreCase) == true;
        var hasPotentialManagement =
            parent is not null ||
            document.Descendants().Any(element => element.Name.LocalName == "dependencyManagement");
        return new MavenManagedVersionContext(
            managedVersions,
            hasPotentialManagement,
            usesSpringBootParent);
    }

    public JavaManagementDecision Evaluate(string groupId, string artifactId)
    {
        if (managedVersions.TryGetValue(Coordinate(groupId, artifactId), out var version))
        {
            return new JavaManagementDecision(
                IsPinnedVersion(version),
                Confidence.High,
                "maven-dependency-management",
                version);
        }

        if (usesSpringBootParent &&
            (groupId.Equals("org.springframework", StringComparison.OrdinalIgnoreCase) ||
             groupId.StartsWith("org.springframework.", StringComparison.OrdinalIgnoreCase)))
        {
            return new JavaManagementDecision(true, Confidence.Medium, "maven-managed");
        }

        return hasPotentialManagement
            ? new JavaManagementDecision(false, Confidence.Medium, "maven-management-unverified")
            : new JavaManagementDecision(false, Confidence.High, null);
    }

    private static string Coordinate(string groupId, string artifactId) =>
        $"{groupId}:{artifactId}";

    private static string? ReadChild(XElement? element, string name) =>
        element?
            .Elements()
            .FirstOrDefault(child => child.Name.LocalName == name)?
            .Value
            .Trim();

    private static string? ResolveProperty(
        string? version,
        IReadOnlyDictionary<string, string> properties)
    {
        if (string.IsNullOrWhiteSpace(version) ||
            !version.StartsWith("${", StringComparison.Ordinal) ||
            !version.EndsWith('}'))
        {
            return version;
        }

        var name = version[2..^1];
        return properties.TryGetValue(name, out var resolved) ? resolved : null;
    }

    private static bool IsPinnedVersion(string version) =>
        !version.Contains("${", StringComparison.Ordinal) &&
        !version.Contains('+', StringComparison.Ordinal) &&
        !version.Contains('[', StringComparison.Ordinal) &&
        !version.Contains(']', StringComparison.Ordinal) &&
        !version.Contains('(', StringComparison.Ordinal) &&
        !version.Contains(')', StringComparison.Ordinal) &&
        !version.Equals("LATEST", StringComparison.OrdinalIgnoreCase) &&
        !version.Equals("RELEASE", StringComparison.OrdinalIgnoreCase);
}

internal sealed class GradleManagedVersionContext
{
    private readonly bool hasPotentialManagement;
    private readonly bool usesSpringBootManagement;

    private GradleManagedVersionContext(bool hasPotentialManagement, bool usesSpringBootManagement)
    {
        this.hasPotentialManagement = hasPotentialManagement;
        this.usesSpringBootManagement = usesSpringBootManagement;
    }

    public static GradleManagedVersionContext Create(string content)
    {
        var hasSpringBootPlugin = content.Contains(
            "org.springframework.boot",
            StringComparison.OrdinalIgnoreCase);
        var hasSpringDependencyManagement = content.Contains(
            "io.spring.dependency-management",
            StringComparison.OrdinalIgnoreCase);
        var hasPotentialManagement =
            hasSpringBootPlugin ||
            hasSpringDependencyManagement ||
            content.Contains("dependencyManagement", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("mavenBom", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("platform(", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("enforcedPlatform(", StringComparison.OrdinalIgnoreCase);
        return new GradleManagedVersionContext(
            hasPotentialManagement,
            hasSpringBootPlugin && hasSpringDependencyManagement);
    }

    public JavaManagementDecision Evaluate(string groupId, string? version)
    {
        if (IsPropertyVersion(version))
        {
            return new JavaManagementDecision(true, Confidence.Medium, "gradle-property");
        }

        if (!string.IsNullOrWhiteSpace(version))
        {
            return new JavaManagementDecision(false, Confidence.High, null);
        }

        if (usesSpringBootManagement &&
            (groupId.Equals("org.springframework", StringComparison.OrdinalIgnoreCase) ||
             groupId.StartsWith("org.springframework.", StringComparison.OrdinalIgnoreCase)))
        {
            return new JavaManagementDecision(true, Confidence.Medium, "gradle-managed");
        }

        return hasPotentialManagement
            ? new JavaManagementDecision(false, Confidence.Medium, "gradle-management-unverified")
            : new JavaManagementDecision(false, Confidence.High, null);
    }

    private static bool IsPropertyVersion(string? version) =>
        !string.IsNullOrWhiteSpace(version) &&
        (version.Contains("${", StringComparison.Ordinal) ||
         version.StartsWith("$", StringComparison.Ordinal) ||
         version.EndsWith("Version", StringComparison.OrdinalIgnoreCase));
}
