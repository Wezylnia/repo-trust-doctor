namespace RepoTrustDoctor.Analyzers.Codebase;

internal sealed record CodebaseFileSelectionResult(
    IReadOnlyList<string> Files,
    int EligiblePartitionCount,
    int SelectedPartitionCount);

internal static class CodebaseFileSelection
{
    private static readonly HashSet<string> PartitionedRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        "apps",
        "clients",
        "cmd",
        "components",
        "crates",
        "extensions",
        "libs",
        "modules",
        "packages",
        "plugins",
        "projects",
        "services",
        "src",
        "tools"
    };

    internal static CodebaseFileSelectionResult Select(
        string repositoryPath,
        IEnumerable<string> candidates,
        int maximumFiles,
        Func<string, int>? priority = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumFiles);
        priority ??= static _ => 0;

        var partitions = candidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .GroupBy(file => GetPartitionKey(repositoryPath, file), StringComparer.OrdinalIgnoreCase)
            .Select(group => new Partition(
                group.Key,
                group
                    .OrderBy(priority)
                    .ThenBy(file => ToRelativePath(repositoryPath, file), StringComparer.OrdinalIgnoreCase)
                    .ToArray()))
            .ToArray();

        if (partitions.Length == 0)
        {
            return new CodebaseFileSelectionResult([], 0, 0);
        }

        var queue = new PriorityQueue<SelectionCandidate, SelectionPriority>();
        foreach (var partition in partitions)
        {
            Enqueue(queue, partition, index: 0, priority);
        }

        var selected = new List<string>(Math.Min(maximumFiles, partitions.Sum(partition => partition.Files.Length)));
        var selectedPartitions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (selected.Count < maximumFiles && queue.TryDequeue(out var candidate, out _))
        {
            selected.Add(candidate.Partition.Files[candidate.Index]);
            selectedPartitions.Add(candidate.Partition.Key);

            var nextIndex = candidate.Index + 1;
            if (nextIndex < candidate.Partition.Files.Length)
            {
                Enqueue(queue, candidate.Partition, nextIndex, priority);
            }
        }

        return new CodebaseFileSelectionResult(selected, partitions.Length, selectedPartitions.Count);
    }

    private static void Enqueue(
        PriorityQueue<SelectionCandidate, SelectionPriority> queue,
        Partition partition,
        int index,
        Func<string, int> priority)
    {
        var file = partition.Files[index];
        queue.Enqueue(
            new SelectionCandidate(partition, index),
            new SelectionPriority(index, priority(file), StableHash(partition.Key), partition.Key));
    }

    private static string GetPartitionKey(string repositoryPath, string filePath)
    {
        var relativePath = ToRelativePath(repositoryPath, filePath);
        var segments = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length <= 1)
        {
            return ".";
        }

        return PartitionedRoots.Contains(segments[0]) && segments.Length > 2
            ? $"{segments[0]}/{segments[1]}"
            : segments[0];
    }

    private static string ToRelativePath(string repositoryPath, string filePath) =>
        Path.GetRelativePath(repositoryPath, filePath).Replace('\\', '/');

    private static ulong StableHash(string value)
    {
        const ulong offset = 14695981039346656037;
        const ulong prime = 1099511628211;
        var hash = offset;

        foreach (var character in value)
        {
            hash ^= char.ToUpperInvariant(character);
            hash *= prime;
        }

        return hash;
    }

    private sealed record Partition(string Key, string[] Files);

    private sealed record SelectionCandidate(Partition Partition, int Index);

    private readonly record struct SelectionPriority(
        int Round,
        int FilePriority,
        ulong PartitionHash,
        string PartitionKey) : IComparable<SelectionPriority>
    {
        public int CompareTo(SelectionPriority other)
        {
            var round = Round.CompareTo(other.Round);
            if (round != 0) return round;

            var priority = FilePriority.CompareTo(other.FilePriority);
            if (priority != 0) return priority;

            var hash = PartitionHash.CompareTo(other.PartitionHash);
            if (hash != 0) return hash;

            return StringComparer.OrdinalIgnoreCase.Compare(PartitionKey, other.PartitionKey);
        }
    }
}
