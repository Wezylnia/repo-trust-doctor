namespace RepoTrustDoctor.Shared;

public sealed record Result<T>(T? Value, string? Error)
{
    public bool IsSuccess => Error is null;

    public static Result<T> Success(T value) => new(value, null);

    public static Result<T> Failure(string error) => new(default, error);
}
