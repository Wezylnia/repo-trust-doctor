using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace RepoTrustDoctor.UnitTests;

internal static class OsvTestArchive
{
    public static MemoryStream Create(string advisoryJson)
    {
        var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var documents = ReadDocuments(advisoryJson);
            for (var index = 0; index < documents.Count; index++)
            {
                var entry = archive.CreateEntry($"advisory-{index}.json");
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(documents[index]);
            }
        }

        output.Position = 0;
        return output;
    }

    private static IReadOnlyList<string> ReadDocuments(string value)
    {
        if (!value.TrimStart().StartsWith('['))
        {
            return [value];
        }

        using var document = JsonDocument.Parse(value);
        return document.RootElement
            .EnumerateArray()
            .Select(item => item.GetRawText())
            .ToArray();
    }
}
