using System.IO.Compression;
using System.Text;

namespace RepoTrustDoctor.UnitTests;

internal static class OsvTestArchive
{
    public static MemoryStream Create(string advisoryJson)
    {
        var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("advisory.json");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write(advisoryJson);
        }

        output.Position = 0;
        return output;
    }
}
