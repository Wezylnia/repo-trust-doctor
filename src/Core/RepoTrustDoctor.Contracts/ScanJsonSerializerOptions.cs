namespace RepoTrustDoctor.Contracts;

using System.Text.Json;
using System.Text.Json.Serialization;

public static class ScanJsonSerializerOptions
{
    public static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        Configure(options);
        return options;
    }

    public static void Configure(JsonSerializerOptions options) =>
        options.Converters.Add(new JsonStringEnumConverter());
}
