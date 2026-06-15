using RepoTrustDoctor.Analysis.Abstractions;

namespace RepoTrustDoctor.Infrastructure.PackageRegistries;

public enum PackageMetadataLookupStatus
{
    Found,
    NotFound,
    TransientFailure,
    InvalidResponse,
    Blocked
}

public sealed record PackageMetadataLookupResult(
    PackageMetadataLookupStatus Status,
    PackageRegistryMetadata? Metadata,
    SafeLookupErrorKind? ErrorKind = null,
    string? ErrorMessage = null,
    string? Source = null,
    DateTimeOffset? FetchedAt = null,
    bool IsStale = false)
{
    public static PackageMetadataLookupResult Found(PackageRegistryMetadata metadata) =>
        new(PackageMetadataLookupStatus.Found, metadata);

    public static PackageMetadataLookupResult NotFound(string? message = null) =>
        new(
            PackageMetadataLookupStatus.NotFound,
            null,
            SafeLookupErrorKind.NotFound,
            message);

    public static PackageMetadataLookupResult Failure(
        PackageMetadataLookupStatus status,
        SafeLookupErrorKind? errorKind,
        string message)
    {
        if (status is PackageMetadataLookupStatus.Found or PackageMetadataLookupStatus.NotFound)
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        return new PackageMetadataLookupResult(status, null, errorKind, message);
    }

    public static PackageMetadataLookupResult FromSafeLookupFailure(SafeLookupResult result)
    {
        if (result.Success || result.ErrorKind is null)
        {
            throw new ArgumentException("A failed safe lookup result is required.", nameof(result));
        }

        var status = result.ErrorKind switch
        {
            SafeLookupErrorKind.NotFound => PackageMetadataLookupStatus.NotFound,
            SafeLookupErrorKind.BlockedUrl => PackageMetadataLookupStatus.Blocked,
            SafeLookupErrorKind.TooLarge or SafeLookupErrorKind.MalformedResponse =>
                PackageMetadataLookupStatus.InvalidResponse,
            SafeLookupErrorKind.Timeout or SafeLookupErrorKind.TransportError =>
                PackageMetadataLookupStatus.TransientFailure,
            _ => PackageMetadataLookupStatus.TransientFailure
        };

        return new PackageMetadataLookupResult(
            status,
            null,
            result.ErrorKind,
            result.ErrorMessage);
    }
}
