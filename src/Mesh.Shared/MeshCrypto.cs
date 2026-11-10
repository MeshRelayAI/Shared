using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Mesh.Shared;

/// <summary>
/// Shared ECDSA (P-256) verification used by the relay to authenticate handles
/// and validate message signatures. Public keys are base64 SubjectPublicKeyInfo.
/// </summary>
public static class MeshCrypto
{
    public static bool Verify(string publicKeyB64, string message, string signatureB64)
    {
        if (string.IsNullOrWhiteSpace(publicKeyB64) || string.IsNullOrWhiteSpace(signatureB64))
            return false;
        try
        {
            using var ec = ECDsa.Create();
            ec.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyB64), out _);
            return ec.VerifyData(Encoding.UTF8.GetBytes(message),
                Convert.FromBase64String(signatureB64), HashAlgorithmName.SHA256);
        }
        catch { return false; }
    }

    /// <summary>True if the signature is valid for any of the supplied public keys.</summary>
    public static bool VerifyAny(IEnumerable<string> publicKeys, string message, string signatureB64)
    {
        foreach (var pk in publicKeys)
            if (Verify(pk, message, signatureB64)) return true;
        return false;
    }

    public static string NewNonce()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
}

public enum MessageDecryptOutcome
{
    Success = 0,
    MissingRecipientSlot = 1,
    AuthenticationFailed = 2,
    Malformed = 3,
    UnsupportedFormat = 4,
    MalformedCompressedData = 5,
    DecodedLimitExceeded = 6,
    DecoderWindowExceeded = 7,
    InvalidUtf8 = 8,
    WireLimitExceeded = 9,
    CompressionFailed = 10,
}

public sealed record MessageDecryptResult
{
    public MessageDecryptResult(
        MessageDecryptOutcome outcome,
        string? plaintext = null)
    {
        Outcome = outcome;
        Plaintext = plaintext;
    }

    public MessageDecryptOutcome Outcome { get; }
    public string? Plaintext { get; }
    public bool IsSuccess => Outcome == MessageDecryptOutcome.Success;

    // Preserve source compatibility for callers that only need success/failure.
    public void Deconstruct(out bool ok, out string? plaintext)
    {
        ok = IsSuccess;
        plaintext = Plaintext;
    }
}

/// <summary>
/// End-to-end message encryption for Mesh. The relay only ever sees ciphertext: the
/// encrypted payload is carried inside the opaque envelope body.
/// Each message uses fresh ephemeral P-256 keys and a random AES-256-GCM content key,
/// wrapped separately for every authorized recipient device.
/// </summary>
public static class MessageCrypto
{
    private const string Alg = "ECIES-P256-AESGCM";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Encrypts using the legacy v1 representation; null means no usable recipient key.</summary>
    public static string? Encrypt(string plaintext, IEnumerable<string> recipientDeviceKeysB64)
    {
        using var prepared = MessagePayloadCompression.Prepare(plaintext, MessagePayloadPurpose.Uncompressed, false);
        return Encrypt(prepared, recipientDeviceKeysB64);
    }

    /// <summary>Encrypts prepared content with fresh randomness. Never falls back to plaintext.</summary>
    public static string? Encrypt(PreparedMessagePayload prepared, IEnumerable<string> recipientDeviceKeysB64)
    {
        ArgumentNullException.ThrowIfNull(prepared);
        var recipients = recipientDeviceKeysB64.Where(k => !string.IsNullOrWhiteSpace(k)).Distinct().ToList();
        if (recipients.Count == 0) return null;
        var version = prepared.IsCompressed ? 2 : 1;
        var compression = prepared.IsCompressed ? "zstd" : null;
        var contentKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var (iv, ct, tag) = AesGcmEncrypt(contentKey, prepared.Bytes, ContentAad(version, compression));
            using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var epk = Convert.ToBase64String(ephemeral.PublicKey.ExportSubjectPublicKeyInfo());
            var wrapped = new Dictionary<string, WrappedKey>();
            foreach (var pub in recipients)
            {
                byte[]? kek = null;
                try
                {
                    using var peer = ECDiffieHellman.Create();
                    peer.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pub), out _);
                    kek = ephemeral.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
                    var (wiv, wct, wtag) = AesGcmEncrypt(kek, contentKey);
                    wrapped[DeviceId(pub)] = new WrappedKey(B64(wiv), B64(wct), B64(wtag));
                }
                catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
                {
                    // Preserve legacy recipient filtering; no usable slots still fails closed at the caller.
                }
                finally
                {
                    if (kek is not null) CryptographicOperations.ZeroMemory(kek);
                }
            }
            if (wrapped.Count == 0) return null;
            var payload = new EncPayload(version, Alg, epk, B64(iv), B64(ct), B64(tag), wrapped, compression);
            return JsonSerializer.Serialize(payload, PayloadJson);
        }
        finally { CryptographicOperations.ZeroMemory(contentKey); }
    }

    /// <summary>True if a body string is a Mesh encrypted payload (vs plaintext).</summary>
    public static bool IsEncrypted(string? body)
    {
        if (string.IsNullOrEmpty(body) || body[0] != '{') return false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("alg", out var a) && a.GetString() == Alg;
        }
        catch { return false; }
    }

    /// <summary>Reads recipient key-slot metadata without decrypting the content.</summary>
    public static IReadOnlyList<string> EncryptedDeviceIds(string? body)
    {
        if (string.IsNullOrEmpty(body) || body[0] != '{') return Array.Empty<string>();
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("alg", out var algorithm)
                || algorithm.GetString() != Alg
                || !root.TryGetProperty("keys", out var keys)
                || keys.ValueKind != JsonValueKind.Object)
                return Array.Empty<string>();
            return keys.EnumerateObject().Select(property => property.Name)
                .Where(deviceId => !string.IsNullOrWhiteSpace(deviceId))
                .Distinct(StringComparer.Ordinal).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    public static MessageDecryptResult TryDecrypt(
        string? body, string myPrivateKeyB64, string myPublicKeyB64,
        MessagePayloadPurpose purpose = MessagePayloadPurpose.Uncompressed, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(body) || body[0] != '{') return new(MessageDecryptOutcome.Malformed);
        if (!Enum.IsDefined(purpose)) return new(MessageDecryptOutcome.UnsupportedFormat);
        int? wireLimit = purpose switch
        {
            MessagePayloadPurpose.DurableEvent => OnlineReplicationLimits.MaxBatchBytes - 256,
            MessagePayloadPurpose.TopicProgress => MessageLimits.MaxEnvelopeBodyBytes,
            _ => null
        };
        if (wireLimit is { } limit && Encoding.UTF8.GetByteCount(body) > limit) return new(MessageDecryptOutcome.WireLimitExceeded);
        ct.ThrowIfCancellationRequested();
        EncPayload? p;
        try
        {
            using var doc = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            if (!HasUnambiguousProperties(doc.RootElement)) return new(MessageDecryptOutcome.Malformed);
            p = doc.RootElement.Deserialize<EncPayload>(PayloadJson);
            if (p is null) return new(MessageDecryptOutcome.Malformed);
            if (string.IsNullOrWhiteSpace(p.Alg) || string.IsNullOrWhiteSpace(p.Epk) || string.IsNullOrWhiteSpace(p.Iv)
                || p.Ct is null || string.IsNullOrWhiteSpace(p.Tag) || p.Keys is null)
                return new(MessageDecryptOutcome.Malformed);
            if (p.V is not (1 or 2) || p.Alg != Alg) return new(MessageDecryptOutcome.UnsupportedFormat);
            if (p.V == 1 && p.ContentCompression is not null
                || p.V == 2 && (purpose == MessagePayloadPurpose.Uncompressed || p.ContentCompression is not ("zstd" or "none")))
                return new(MessageDecryptOutcome.UnsupportedFormat);
        }
        catch (JsonException) { return new(MessageDecryptOutcome.Malformed); }

        if (!p.Keys.TryGetValue(DeviceId(myPublicKeyB64), out var wk)) return new(MessageDecryptOutcome.MissingRecipientSlot);
        if (wk is null || string.IsNullOrWhiteSpace(wk.Iv) || string.IsNullOrWhiteSpace(wk.Wrap) || string.IsNullOrWhiteSpace(wk.Tag))
            return new(MessageDecryptOutcome.Malformed);
        byte[]? contentKey = null, kek = null, plain = null, decoded = null;
        try
        {
            using var mine = ECDiffieHellman.Create();
            mine.ImportPkcs8PrivateKey(Convert.FromBase64String(myPrivateKeyB64), out _);
            using var eph = ECDiffieHellman.Create();
            eph.ImportSubjectPublicKeyInfo(Convert.FromBase64String(p.Epk), out _);
            kek = mine.DeriveKeyFromHash(eph.PublicKey, HashAlgorithmName.SHA256);
            contentKey = AesGcmDecrypt(kek, FromB64(wk.Iv), FromB64(wk.Wrap), FromB64(wk.Tag));
            plain = AesGcmDecrypt(contentKey, FromB64(p.Iv), FromB64(p.Ct), FromB64(p.Tag), ContentAad(p.V, p.ContentCompression));
            if (p.V == 1) return new(MessageDecryptOutcome.Success, Encoding.UTF8.GetString(plain));
            ct.ThrowIfCancellationRequested();
            if (p.ContentCompression == "zstd") decoded = MessagePayloadCompression.Decompress(plain, purpose, ct);
            else if (purpose == MessagePayloadPurpose.TopicProgress && plain.Length > MessagePayloadCompression.MaximumProgressDecodedBytes)
                return new(MessageDecryptOutcome.DecodedLimitExceeded);
            return new(MessageDecryptOutcome.Success, StrictUtf8.GetString(decoded ?? plain));
        }
        catch (PayloadCompressionException ex) { return new(ex.Outcome); }
        catch (DecoderFallbackException) { return new(MessageDecryptOutcome.InvalidUtf8); }
        catch (AuthenticationTagMismatchException) { return new(MessageDecryptOutcome.AuthenticationFailed); }
        catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
        {
            return new(MessageDecryptOutcome.Malformed);
        }
        finally
        {
            if (contentKey is not null) CryptographicOperations.ZeroMemory(contentKey);
            if (kek is not null) CryptographicOperations.ZeroMemory(kek);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (decoded is not null) CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static bool HasUnambiguousProperties(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) return false;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name)) return false;
            if (property.Value.ValueKind == JsonValueKind.Object && !HasUnambiguousProperties(property.Value)) return false;
        }
        return true;
    }

    private static byte[]? ContentAad(int version, string? compression)
        => version == 1 ? null : Encoding.UTF8.GetBytes($"mesh-message-crypto|2|{Alg}|{compression}");

    /// <summary>Stable short id for a device public key (matches the relay's device-id scheme).</summary>
    public static string DeviceId(string publicKeyB64)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(publicKeyB64)))[..12].ToLowerInvariant();

    private static (byte[] iv, byte[] ct, byte[] tag) AesGcmEncrypt(byte[] key, ReadOnlySpan<byte> plaintext, byte[]? aad = null)
    {
        var iv = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var ct = new byte[plaintext.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using var gcm = new AesGcm(key, tag.Length);
        gcm.Encrypt(iv, plaintext, ct, tag, aad);
        return (iv, ct, tag);
    }

    private static byte[] AesGcmDecrypt(byte[] key, byte[] iv, byte[] ct, byte[] tag, byte[]? aad = null)
    {
        var plain = new byte[ct.Length];
        using var gcm = new AesGcm(key, tag.Length);
        try { gcm.Decrypt(iv, ct, tag, plain, aad); }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plain);
            throw;
        }
        return plain;
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b);
    private static byte[] FromB64(string s) => Convert.FromBase64String(s);
    private static readonly JsonSerializerOptions PayloadJson = new(JsonSerializerDefaults.Web) { MaxDepth = 16 };
    private sealed record WrappedKey(string Iv, string Wrap, string Tag);
    private sealed record EncPayload(int V, string Alg, string Epk, string Iv, string Ct, string Tag,
        Dictionary<string, WrappedKey> Keys,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ContentCompression = null);
}

/// <summary>Frames exchanged during the WebSocket auth handshake.</summary>
public record AuthChallenge(string Nonce)
{
    public string Type { get; init; } = "auth.challenge";
}

public record AuthResponse(string PublicKey, string Signature)
{
    public string Type { get; init; } = "auth.response";
}

public record AuthResult(bool Ok, string? Error = null)
{
    public string Type { get; init; } = "auth.result";
}
