using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mesh.Shared;

public sealed record DeviceSyncSnapshotTransfer(
    DeviceSyncSnapshotManifest Manifest,
    IReadOnlyList<DeviceSyncSnapshotChunk> Chunks);

public static class DeviceSyncSnapshotProtocol
{
    public const int FormatVersion = 2;
    public const int MaxChunkBytes = 512 * 1024;
    public const int MaxChunks = 512;
    public const int MaxCompressedBytes = MaxChunkBytes * MaxChunks;
    public const int MaxUncompressedBytes = 256 * 1024 * 1024;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static DeviceSyncSnapshotTransfer Create(
        string sourceDeviceId,
        IReadOnlyList<DeviceSyncOperation> operations)
    {
        if (string.IsNullOrWhiteSpace(sourceDeviceId))
            throw new ArgumentException("A source device ID is required.", nameof(sourceDeviceId));
        ArgumentNullException.ThrowIfNull(operations);

        if (operations.Any(operation => operation is null))
            throw new ArgumentException("Device snapshot operations were invalid.", nameof(operations));
        var canonicalOperations = operations
            .OrderBy(operation => operation.OperationId, StringComparer.Ordinal)
            .ToArray();
        if (canonicalOperations.Any(operation => string.IsNullOrWhiteSpace(operation.OperationId)
                || !string.Equals(operation.SourceDeviceId, sourceDeviceId, StringComparison.Ordinal))
            || canonicalOperations.Select(operation => operation.OperationId)
                .Distinct(StringComparer.Ordinal).Count() != canonicalOperations.Length)
            throw new ArgumentException("Device snapshot operations were invalid.", nameof(operations));

        var serialized = JsonSerializer.SerializeToUtf8Bytes(canonicalOperations, Json);
        if (serialized.Length > MaxUncompressedBytes)
            throw new InvalidOperationException("The device snapshot is too large to transfer.");
        var compressed = Compress(serialized);
        if (compressed.Length > MaxCompressedBytes)
            throw new InvalidOperationException("The compressed device snapshot is too large to transfer.");

        var snapshotHash = Hash(compressed);
        var chunkCount = Math.Max(1, (compressed.Length + MaxChunkBytes - 1) / MaxChunkBytes);
        var chunks = new List<DeviceSyncSnapshotChunk>(chunkCount);
        for (var index = 0; index < chunkCount; index++)
        {
            var offset = index * MaxChunkBytes;
            var length = Math.Min(MaxChunkBytes, compressed.Length - offset);
            var data = compressed.AsSpan(offset, length).ToArray();
            chunks.Add(new DeviceSyncSnapshotChunk(
                snapshotHash,
                sourceDeviceId,
                index,
                Hash(data),
                data));
        }

        return new DeviceSyncSnapshotTransfer(
            new DeviceSyncSnapshotManifest(
                snapshotHash,
                sourceDeviceId,
                canonicalOperations.Length,
                chunkCount,
                compressed.Length,
                snapshotHash),
            chunks);
    }

    public static IReadOnlyList<DeviceSyncOperation> Assemble(
        DeviceSyncSnapshotManifest manifest,
        IReadOnlyList<DeviceSyncSnapshotChunk> chunks)
    {
        ValidateManifest(manifest);
        ArgumentNullException.ThrowIfNull(chunks);
        if (chunks.Count != manifest.ChunkCount)
            throw new InvalidDataException("The device snapshot is missing chunks.");

        using var compressed = new MemoryStream(manifest.CompressedBytes);
        var expectedIndex = 0;
        foreach (var chunk in chunks.OrderBy(item => item.Index))
        {
            if (!string.Equals(chunk.SnapshotId, manifest.SnapshotId, StringComparison.Ordinal)
                || !string.Equals(chunk.SourceDeviceId, manifest.SourceDeviceId, StringComparison.Ordinal)
                || chunk.Index != expectedIndex
                || !string.Equals(Hash(chunk.Data), chunk.Sha256, StringComparison.Ordinal))
                throw new InvalidDataException("A device snapshot chunk failed validation.");
            compressed.Write(chunk.Data);
            expectedIndex++;
        }
        if (compressed.Length != manifest.CompressedBytes)
            throw new InvalidDataException("The device snapshot length did not match its manifest.");
        var compressedBytes = compressed.ToArray();
        if (!string.Equals(Hash(compressedBytes), manifest.Sha256, StringComparison.Ordinal))
            throw new InvalidDataException("The device snapshot hash did not match its manifest.");

        var serialized = Decompress(compressedBytes);
        var operations = JsonSerializer.Deserialize<DeviceSyncOperation[]>(serialized, Json)
                         ?? throw new InvalidDataException("The device snapshot payload was empty.");
        if (operations.Length != manifest.OperationCount)
            throw new InvalidDataException("The device snapshot operation count did not match its manifest.");
        if (operations.Any(operation => operation is null
                || string.IsNullOrWhiteSpace(operation.OperationId)
                || !string.Equals(operation.SourceDeviceId, manifest.SourceDeviceId, StringComparison.Ordinal))
            || operations.Select(operation => operation.OperationId)
                .Distinct(StringComparer.Ordinal).Count() != operations.Length)
            throw new InvalidDataException("The device snapshot operations were invalid.");
        return operations;
    }

    public static void ValidateManifest(DeviceSyncSnapshotManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (!IsHash(manifest.SnapshotId)
            || !IsHash(manifest.Sha256)
            || !string.Equals(manifest.SnapshotId, manifest.Sha256, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(manifest.SourceDeviceId)
            || manifest.OperationCount < 0
            || manifest.ChunkCount is < 1 or > MaxChunks
            || manifest.CompressedBytes is < 1 or > MaxCompressedBytes)
            throw new InvalidDataException("The device snapshot manifest was invalid.");
    }

    public static void ValidateChunk(DeviceSyncSnapshotChunk chunk)
    {
        ArgumentNullException.ThrowIfNull(chunk);
        if (!IsHash(chunk.SnapshotId)
            || !IsHash(chunk.Sha256)
            || string.IsNullOrWhiteSpace(chunk.SourceDeviceId)
            || chunk.Index < 0
            || chunk.Data is null
            || chunk.Data.Length is < 1 or > MaxChunkBytes
            || !string.Equals(Hash(chunk.Data), chunk.Sha256, StringComparison.Ordinal))
            throw new InvalidDataException("The device snapshot chunk was invalid.");
    }

    public static void ValidateComplete(DeviceSyncSnapshotComplete completion)
    {
        ArgumentNullException.ThrowIfNull(completion);
        if (!IsHash(completion.SnapshotId)
            || !IsHash(completion.Sha256)
            || !string.Equals(completion.SnapshotId, completion.Sha256, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(completion.SourceDeviceId)
            || string.IsNullOrWhiteSpace(completion.TargetDeviceId)
            || completion.OperationCount < 0)
            throw new InvalidDataException("The device snapshot completion was invalid.");
    }

    private static byte[] Compress(byte[] serialized)
    {
        using var output = new MemoryStream();
        using (var brotli = new BrotliStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            brotli.Write(serialized);
        return output.ToArray();
    }

    private static byte[] Decompress(byte[] compressed)
    {
        using var input = new MemoryStream(compressed, writable: false);
        using var brotli = new BrotliStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = brotli.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            output.Write(buffer, 0, read);
            if (output.Length > MaxUncompressedBytes)
                throw new InvalidDataException("The device snapshot expanded beyond its limit.");
        }
        return output.ToArray();
    }

    private static string Hash(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static bool IsHash(string? value)
        => value is { Length: 64 } && value.All(Uri.IsHexDigit);
}

public static class DeviceSyncEnvelopeIdProtocol
{
    public static string SnapshotRequestId(
        string requestingDeviceId,
        string sourceDeviceId,
        string? knownSnapshotId,
        IReadOnlyList<int>? missingChunkIndexes)
    {
        var missing = missingChunkIndexes is null
            ? "all"
            : string.Join(",", missingChunkIndexes.OrderBy(index => index));
        return Hash(
            "snapshot-request",
            requestingDeviceId,
            sourceDeviceId,
            knownSnapshotId ?? "none",
            missing);
    }

    public static string LiveBatchId(
        string sourceDeviceId,
        IReadOnlyList<DeviceSyncOperation> operations)
        => Hash(
            "live-batch",
            sourceDeviceId,
            string.Join("\n", operations
                .OrderBy(operation => operation.OperationId, StringComparer.Ordinal)
                .Select(operation => operation.OperationId)));

    public static string EnvelopeId(
        string kind,
        string sourceDeviceId,
        string targetDeviceId,
        string plaintext)
        => Hash("device-envelope", kind, sourceDeviceId, targetDeviceId, plaintext);

    private static string Hash(params string[] values)
    {
        var canonical = string.Join("\0", values);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
            .ToLowerInvariant();
    }
}
