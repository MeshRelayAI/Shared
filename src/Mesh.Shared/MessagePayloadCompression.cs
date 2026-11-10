using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace Mesh.Shared;

public enum MessagePayloadPurpose { Uncompressed, DurableEvent, TopicProgress }
public enum PayloadCompressionDecision { Ineligible, Disabled, Small, InsufficientSavings, Compressed }

public sealed class PreparedMessagePayload : IDisposable
{
    private byte[]? bytes;
    internal PreparedMessagePayload(byte[] bytes, MessagePayloadPurpose purpose, PayloadCompressionDecision decision)
    {
        this.bytes = bytes;
        Purpose = purpose;
        Decision = decision;
    }

    public MessagePayloadPurpose Purpose { get; }
    public PayloadCompressionDecision Decision { get; }
    public bool IsCompressed => Decision == PayloadCompressionDecision.Compressed;
    internal ReadOnlySpan<byte> Bytes => bytes ?? throw new ObjectDisposedException(nameof(PreparedMessagePayload));

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref bytes, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

public sealed class PayloadCompressionException : Exception
{
    public PayloadCompressionException(MessageDecryptOutcome outcome, string message) : base(message) => Outcome = outcome;
    public MessageDecryptOutcome Outcome { get; }
}

public static class MessagePayloadCompression
{
    public const int MinimumInputBytes = 1024;
    public const int MaximumWindowBytes = 4 * 1024 * 1024;
    public const int MaximumProgressDecodedBytes = 1_800_000;
    private const int WindowLog = 22;
    private static readonly SemaphoreSlim Slots = new(2, 2);
    private static readonly Meter Meter = new("Mesh.PayloadCompression", "2");
    private static readonly Counter<long> Operations = Meter.CreateCounter<long>("mesh.payload.operations");
    private static readonly Counter<long> Bytes = Meter.CreateCounter<long>("mesh.payload.bytes");
    private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("mesh.payload.codec.duration", "ms");
    private static readonly UpDownCounter<long> Active = Meter.CreateUpDownCounter<long>("mesh.payload.codec.active");

    public static bool MeetsSavingsThreshold(int inputBytes, int compressedBytes)
    {
        if (inputBytes < MinimumInputBytes || compressedBytes < 0 || compressedBytes > inputBytes) return false;
        var saved = (long)inputBytes - compressedBytes;
        return saved >= 128 && 100L * saved >= 5L * inputBytes;
    }

    public static PreparedMessagePayload Prepare(
        string plaintext, MessagePayloadPurpose purpose, bool compressionEnabled, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (!Enum.IsDefined(purpose)) throw new ArgumentOutOfRangeException(nameof(purpose));
        ct.ThrowIfCancellationRequested();
        byte[]? input = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            if (purpose == MessagePayloadPurpose.TopicProgress && input.Length > MaximumProgressDecodedBytes)
                throw new PayloadCompressionException(MessageDecryptOutcome.DecodedLimitExceeded, "Live progress exceeds its decoded-input limit.");
            var decision = purpose == MessagePayloadPurpose.Uncompressed ? PayloadCompressionDecision.Ineligible
                : !compressionEnabled ? PayloadCompressionDecision.Disabled
                : input.Length < MinimumInputBytes ? PayloadCompressionDecision.Small
                : PayloadCompressionDecision.InsufficientSavings;
            if (decision == PayloadCompressionDecision.InsufficientSavings)
            {
                Slots.Wait(ct);
                var started = Stopwatch.GetTimestamp();
                Active.Add(1);
                try
                {
                    using var compressor = new Compressor(1);
                    compressor.SetParameter(ZSTD_cParameter.ZSTD_c_nbWorkers, 0);
                    compressor.SetParameter(ZSTD_cParameter.ZSTD_c_windowLog, WindowLog);
                    compressor.SetParameter(ZSTD_cParameter.ZSTD_c_contentSizeFlag, 1);
                    var compressed = compressor.Wrap(input);
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        if (MeetsSavingsThreshold(input.Length, compressed.Length))
                        {
                            RecordPreparation(purpose, PayloadCompressionDecision.Compressed, input.Length, compressed.Length);
                            return new(compressed.ToArray(), purpose, PayloadCompressionDecision.Compressed);
                        }
                    }
                    finally { CryptographicOperations.ZeroMemory(compressed); }
                }
                catch (ZstdException)
                {
                    throw new PayloadCompressionException(MessageDecryptOutcome.CompressionFailed, "Zstd payload preparation failed.");
                }
                finally
                {
                    Duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds, new KeyValuePair<string, object?>("operation", "compress"));
                    Active.Add(-1);
                    Slots.Release();
                }
            }
            RecordPreparation(purpose, decision, input.Length, input.Length);
            var prepared = new PreparedMessagePayload(input, purpose, decision);
            input = null;
            return prepared;
        }
        finally
        {
            if (input is not null) CryptographicOperations.ZeroMemory(input);
        }
    }

    internal static byte[] Decompress(byte[] frame, MessagePayloadPurpose purpose, CancellationToken ct)
    {
        var declared = ValidateFrame(frame, purpose);
        Slots.Wait(ct);
        var started = Stopwatch.GetTimestamp();
        Active.Add(1);
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        using var output = new MemoryStream();
        try
        {
            using var decompressor = new Decompressor();
            decompressor.SetParameter(ZSTD_dParameter.ZSTD_d_windowLogMax, WindowLog);
            var offset = 0;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var status = decompressor.UnwrapStream(frame.AsSpan(offset), buffer, out var consumed, out var written);
                offset += consumed;
                var total = checked((ulong)output.Length + (uint)written);
                if (total > declared) throw InvalidFrame();
                if (purpose == MessagePayloadPurpose.TopicProgress && total > MaximumProgressDecodedBytes)
                    throw new PayloadCompressionException(MessageDecryptOutcome.DecodedLimitExceeded, "Live progress exceeds its decoded-output limit.");
                output.Write(buffer, 0, written);
                if (status == OperationStatus.Done)
                {
                    if (offset != frame.Length || total != declared) throw InvalidFrame();
                    Operations.Add(1, new("operation", "decompress"), new("purpose", purpose.ToString()));
                    Bytes.Add(output.Length, new("representation", "decoded"), new("purpose", purpose.ToString()));
                    return output.ToArray();
                }
                if (status == OperationStatus.InvalidData || consumed == 0 && written == 0) throw InvalidFrame();
            }
        }
        catch (ZstdException)
        {
            throw InvalidFrame();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output.GetBuffer().AsSpan(0, checked((int)output.Length)));
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            Duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds, new KeyValuePair<string, object?>("operation", "decompress"));
            Active.Add(-1);
            Slots.Release();
        }
    }

    // Walk the sole frame before streaming: the decoder must never accept another frame or trailing data.
    private static ulong ValidateFrame(ReadOnlySpan<byte> frame, MessagePayloadPurpose purpose)
    {
        if (frame.Length < 6 || BinaryPrimitives.ReadUInt32LittleEndian(frame) != 0xFD2FB528) throw InvalidFrame();
        var descriptor = frame[4];
        if ((descriptor & 0x18) != 0) throw InvalidFrame();
        var singleSegment = (descriptor & 0x20) != 0;
        var offset = 5;
        ulong window = 0;
        if (!singleSegment)
        {
            var windowDescriptor = ReadUnsigned(frame, ref offset, 1);
            var basis = 1UL << (10 + (int)(windowDescriptor >> 3));
            window = basis + (basis >> 3) * (windowDescriptor & 7);
        }
        var dictionarySize = (descriptor & 3) switch { 0 => 0, 1 => 1, 2 => 2, _ => 4 };
        if (ReadUnsigned(frame, ref offset, dictionarySize) != 0) throw InvalidFrame();
        var sizeBytes = (descriptor >> 6) switch { 0 => singleSegment ? 1 : 0, 1 => 2, 2 => 4, _ => 8 };
        if (sizeBytes == 0) throw InvalidFrame();
        var size = ReadUnsigned(frame, ref offset, sizeBytes);
        if (sizeBytes == 2) size += 256;
        if (singleSegment) window = size;
        if (window > MaximumWindowBytes)
            throw new PayloadCompressionException(MessageDecryptOutcome.DecoderWindowExceeded, "Zstd window exceeds the supported bound.");
        if (purpose == MessagePayloadPurpose.TopicProgress && size > MaximumProgressDecodedBytes)
            throw new PayloadCompressionException(MessageDecryptOutcome.DecodedLimitExceeded, "Live progress declares an excessive decoded size.");
        bool last;
        do
        {
            var header = ReadUnsigned(frame, ref offset, 3);
            last = (header & 1) != 0;
            var type = (header >> 1) & 3;
            var sizeInBlock = (int)(header >> 3);
            if (type == 3 || sizeInBlock > 128 * 1024) throw InvalidFrame();
            var storedBytes = type == 1 ? 1 : sizeInBlock;
            if (storedBytes > frame.Length - offset) throw InvalidFrame();
            offset += storedBytes;
        } while (!last);
        if ((descriptor & 4) != 0) _ = ReadUnsigned(frame, ref offset, 4);
        if (offset != frame.Length) throw InvalidFrame();
        return size;
    }

    private static ulong ReadUnsigned(ReadOnlySpan<byte> source, ref int offset, int count)
    {
        if (count > source.Length - offset) throw InvalidFrame();
        ulong value = 0;
        for (var index = 0; index < count; index++) value |= (ulong)source[offset++] << (8 * index);
        return value;
    }

    private static PayloadCompressionException InvalidFrame()
        => new(MessageDecryptOutcome.MalformedCompressedData, "Invalid or unsupported Zstd frame.");

    private static void RecordPreparation(MessagePayloadPurpose purpose, PayloadCompressionDecision decision, int input, int output)
    {
        Operations.Add(1, new("operation", "prepare"), new("purpose", purpose.ToString()), new("decision", decision.ToString()));
        Bytes.Add(input, new("representation", "serialized"), new("purpose", purpose.ToString()));
        Bytes.Add(output, new("representation", "prepared"), new("purpose", purpose.ToString()));
    }
}
