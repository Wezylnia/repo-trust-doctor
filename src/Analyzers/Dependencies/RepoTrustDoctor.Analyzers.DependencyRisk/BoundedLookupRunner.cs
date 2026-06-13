using System.Collections.Concurrent;

namespace RepoTrustDoctor.Analyzers.DependencyRisk;

internal sealed record BoundedLookupResult<T>(
    IReadOnlyList<T> Results,
    int TotalCount,
    int CompletedCount,
    bool SoftBudgetExceeded);

internal static class BoundedLookupRunner
{
    public static async Task<BoundedLookupResult<TOutput>> RunAsync<TInput, TOutput>(
        IReadOnlyList<TInput> items,
        int maxConcurrency,
        TimeSpan softBudget,
        Func<TInput, CancellationToken, Task<TOutput>> operation,
        CancellationToken cancellationToken)
    {
        if (items.Count == 0)
        {
            return new BoundedLookupResult<TOutput>([], 0, 0, false);
        }

        using var budgetCts = new CancellationTokenSource(softBudget);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, budgetCts.Token);
        var results = new ConcurrentBag<IndexedResult<TOutput>>();
        var nextIndex = -1;
        var completedCount = 0;
        var workerCount = Math.Min(Math.Max(1, maxConcurrency), items.Count);

        var workers = Enumerable.Range(0, workerCount)
            .Select(_ => RunWorkerAsync())
            .ToArray();

        await Task.WhenAll(workers);

        return new BoundedLookupResult<TOutput>(
            results
                .OrderBy(result => result.Index)
                .Select(result => result.Value)
                .ToArray(),
            items.Count,
            completedCount,
            budgetCts.IsCancellationRequested && completedCount < items.Count);

        async Task RunWorkerAsync()
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var index = Interlocked.Increment(ref nextIndex);
                if (index >= items.Count)
                {
                    return;
                }

                try
                {
                    var result = await operation(items[index], linkedCts.Token);
                    results.Add(new IndexedResult<TOutput>(index, result));
                    Interlocked.Increment(ref completedCount);
                }
                catch (OperationCanceledException) when (
                    budgetCts.IsCancellationRequested &&
                    !cancellationToken.IsCancellationRequested)
                {
                    return;
                }
            }
        }
    }

    private sealed record IndexedResult<T>(int Index, T Value);
}
