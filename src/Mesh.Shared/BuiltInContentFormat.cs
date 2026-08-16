using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mesh.Shared;

public sealed class BuiltInCatalog
{
    public int SchemaVersion { get; set; }
    public string ContentVersion { get; set; } = "";
    public string CatalogHash { get; set; } = "";
    public List<BuiltInCatalogEntry> Items { get; set; } = new();
}

public sealed class BuiltInCatalogEntry
{
    public string Id { get; set; } = "";
    public string Type { get; set; } = "";
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public int SizeBytes { get; set; }
    public List<string> Roles { get; set; } = new();
    public string? Title { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public List<string> Keywords { get; set; } = new();
    public List<string> Triggers { get; set; } = new();
    public int? Priority { get; set; }
}

public sealed record BuiltInMarkdownDocument(
    IReadOnlyDictionary<string, string> FrontMatter,
    string Body);

public static class BuiltInContentFormat
{
    public const int SchemaVersion = 1;
    public const int MaximumItemBytes = 64 * 1024;
    public const int MaximumPackagedItemBytes = MaximumItemBytes * 2 + 3;
    public const int MaximumCatalogBytes = 512 * 1024;
    public const int MaximumIndexBytes = 1024 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static JsonSerializerOptions JsonOptions(bool writeIndented = false) => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        WriteIndented = writeIndented
    };

    public static string DecodeUtf8(ReadOnlySpan<byte> bytes)
        => StrictUtf8.GetString(bytes);

    public static byte[] CanonicalUtf8(string text)
        => StrictUtf8.GetBytes(NormalizeText(text));

    public static BuiltInMarkdownDocument ParseMarkdown(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var normalized = NormalizeText(text);
        var lines = normalized.Split('\n');
        if (lines.Length < 3 || !string.Equals(lines[0].Trim(), "---", StringComparison.Ordinal))
            throw new FormatException("Markdown must start with frontmatter delimited by ---.");

        var end = -1;
        for (var index = 1; index < lines.Length; index++)
        {
            if (!string.Equals(lines[index].Trim(), "---", StringComparison.Ordinal)) continue;
            end = index;
            break;
        }
        if (end < 0) throw new FormatException("Frontmatter is missing its closing --- delimiter.");

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 1; index < end; index++)
        {
            var line = lines[index].Trim();
            if (line.Length == 0) continue;
            var separator = line.IndexOf(':');
            if (separator <= 0)
                throw new FormatException($"Invalid frontmatter line {index + 1}: expected key: value.");
            var key = line[..separator].Trim();
            var value = Unquote(line[(separator + 1)..].Trim());
            if (key.Length == 0 || value.Length == 0)
                throw new FormatException($"Invalid frontmatter line {index + 1}: key and value are required.");
            if (!metadata.TryAdd(key, value))
                throw new FormatException($"Duplicate frontmatter key '{key}'.");
        }

        var body = string.Join('\n', lines.Skip(end + 1)).Trim();
        return new BuiltInMarkdownDocument(metadata, body);
    }

    public static string Required(IReadOnlyDictionary<string, string> metadata, string key)
        => metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : throw new FormatException($"Frontmatter field '{key}' is required.");

    public static string? Optional(IReadOnlyDictionary<string, string> metadata, string key)
        => metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : null;

    public static int RequiredInt(IReadOnlyDictionary<string, string> metadata, string key)
        => int.TryParse(Required(metadata, key), out var value)
            ? value
            : throw new FormatException($"Frontmatter field '{key}' must be an integer.");

    public static List<string> List(IReadOnlyDictionary<string, string> metadata, string key)
        => Optional(metadata, key)?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
               .Where(value => value.Length > 0)
               .Distinct(StringComparer.OrdinalIgnoreCase)
               .ToList()
           ?? new List<string>();

    public static string ExtractSkillInstructions(string body)
    {
        var lines = body.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index].Trim();
            var markerLength = 0;
            while (markerLength < line.Length && line[markerLength] == '#') markerLength++;
            if (markerLength == 0 || markerLength >= line.Length) continue;
            if (!string.Equals(line[markerLength..].Trim(), "Instructions", StringComparison.OrdinalIgnoreCase))
                continue;
            var instructions = string.Join('\n', lines.Skip(index + 1)).Trim();
            if (instructions.Length == 0)
                throw new FormatException("Skill instructions must not be empty.");
            return instructions;
        }
        throw new FormatException("Skills require an Instructions heading.");
    }

    public static string FileHash(ReadOnlySpan<byte> bytes)
        => Convert.ToHexStringLower(SHA256.HashData(bytes));

    public static string CatalogHash(IEnumerable<BuiltInCatalogEntry> entries)
    {
        var canonical = new StringBuilder();
        foreach (var entry in entries.OrderBy(item => item.Id, StringComparer.Ordinal))
        {
            AppendField(canonical, entry.Id);
            AppendField(canonical, entry.Type);
            AppendField(canonical, NormalizePath(entry.Path));
            AppendField(canonical, entry.Sha256.ToLowerInvariant());
            AppendField(canonical, entry.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AppendField(canonical, string.Join(',', entry.Roles.OrderBy(role => role, StringComparer.Ordinal)));
            AppendField(canonical, entry.Title ?? "");
            AppendField(canonical, entry.Name ?? "");
            AppendField(canonical, entry.Description ?? "");
            AppendField(canonical, string.Join(',', entry.Keywords));
            AppendField(canonical, string.Join(',', entry.Triggers));
            AppendField(canonical, entry.Priority?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "");
        }
        return FileHash(Encoding.UTF8.GetBytes(canonical.ToString()));
    }

    public static string ContentVersion(string catalogHash)
    {
        if (catalogHash.Length < 16) throw new ArgumentException("A SHA-256 catalog hash is required.", nameof(catalogHash));
        return "sha256:" + catalogHash[..16];
    }

    public static string NormalizePath(string path) => path.Replace('\\', '/');

    private static string NormalizeText(string text)
        => text.TrimStart('\uFEFF')
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

    private static string Unquote(string value)
    {
        if (value.Length >= 2
            && ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            return value[1..^1].Trim();
        return value;
    }

    private static void AppendField(StringBuilder target, string value)
        => target.Append(value.Length).Append(':').Append(value).Append(';');
}
