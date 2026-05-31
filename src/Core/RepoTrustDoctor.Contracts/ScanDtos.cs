namespace RepoTrustDoctor.Contracts;

public sealed record StartScanRequest(string Target, string Depth = "fast", string Format = "console");

public sealed record StartScanResponse(Guid ScanId, string Status);
