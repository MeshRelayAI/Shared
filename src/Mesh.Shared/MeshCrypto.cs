using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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
/// encrypted payload is carried inside the opaque envelope body, so no relay change is
/// needed and the relay operator cannot read messages.
///
/// Scheme (ECIES over the existing P-256 device keys):
///  - A fresh ephemeral P-256 key pair is generated per message.
///  - A random 256-bit content key encrypts the plaintext once with AES-256-GCM.
///  - For each of the recipient handle's device public keys, ECDH(ephemeral, deviceKey)
///    plus SHA-256 derivation yields a key-encryption key that wraps the content key with
///    AES-256-GCM. Any of the recipient's devices can therefore unwrap and decrypt.
///  - Device keys are the same P-256 SubjectPublicKeyInfo keys already published to the
///    relay directory, so no new key distribution is required.
/// </summary>
public static class MessageCrypto
{
    private const string Alg = "ECIES-P256-AESGCM";

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> to every device public key of the recipient.
    /// Returns a self-describing JSON string to place in the envelope body. Returns null if
    /// no usable recipient keys were supplied (caller should then send plaintext as a fallback).
    /// </summary>
    public static string? Encrypt(string plaintext, IEnumerable<string> recipientDeviceKeysB64)
    {
        var recipients = recipientDeviceKeysB64
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct()
            .ToList();
        if (recipients.Count == 0) return null;

        var contentKey = RandomNumberGenerator.GetBytes(32);
        var (iv, ct, tag) = AesGcmEncrypt(contentKey, Encoding.UTF8.GetBytes(plaintext));

        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var epk = Convert.ToBase64String(ephemeral.PublicKey.ExportSubjectPublicKeyInfo());

        var wrapped = new Dictionary<string, WrappedKey>();
        foreach (var pub in recipients)
        {
            try
            {
                using var peer = ECDiffieHellman.Create();
                peer.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pub), out _);
                var kek = ephemeral.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
                var (wiv, wct, wtag) = AesGcmEncrypt(kek, contentKey);
                wrapped[DeviceId(pub)] = new WrappedKey(B64(wiv), B64(wct), B64(wtag));
            }
            catch { /* skip a malformed recipient key */ }
        }
        CryptographicOperations.ZeroMemory(contentKey);
        if (wrapped.Count == 0) return null;

        var payload = new EncPayload(1, Alg, epk, B64(iv), B64(ct), B64(tag), wrapped);
        return JsonSerializer.Serialize(payload, PayloadJson);
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

    /// <summary>
    /// Returns the device ids with wrapped content keys in an encrypted body. This reads only
    /// recipient key-slot metadata; it never decrypts or exposes the message plaintext.
    /// </summary>
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
            return keys.EnumerateObject()
                .Select(property => property.Name)
                .Where(deviceId => !string.IsNullOrWhiteSpace(deviceId))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    /// <summary>
    /// Attempts to decrypt a body with this device's key pair while preserving the distinction
    /// between an immutable event that was not addressed to this device and a payload that failed
    /// authentication or is structurally malformed.
    /// </summary>
    public static MessageDecryptResult TryDecrypt(
        string? body,
        string myPrivateKeyB64,
        string myPublicKeyB64)
    {
        if (string.IsNullOrWhiteSpace(body) || body[0] != '{')
            return new(MessageDecryptOutcome.Malformed);

        EncPayload? p;
        try
        {
            p = JsonSerializer.Deserialize<EncPayload>(body, PayloadJson);
            if (p is null
                || p.V != 1
                || p.Alg != Alg
                || string.IsNullOrWhiteSpace(p.Epk)
                || string.IsNullOrWhiteSpace(p.Iv)
                || string.IsNullOrWhiteSpace(p.Ct)
                || string.IsNullOrWhiteSpace(p.Tag)
                || p.Keys is null)
                return new(MessageDecryptOutcome.Malformed);
        }
        catch (JsonException)
        {
            return new(MessageDecryptOutcome.Malformed);
        }

        if (!p.Keys.TryGetValue(DeviceId(myPublicKeyB64), out var wk))
            return new(MessageDecryptOutcome.MissingRecipientSlot);
        if (wk is null
            || string.IsNullOrWhiteSpace(wk.Iv)
            || string.IsNullOrWhiteSpace(wk.Wrap)
            || string.IsNullOrWhiteSpace(wk.Tag))
            return new(MessageDecryptOutcome.Malformed);

        byte[]? contentKey = null;
        try
        {
            using var mine = ECDiffieHellman.Create();
            mine.ImportPkcs8PrivateKey(Convert.FromBase64String(myPrivateKeyB64), out _);
            using var eph = ECDiffieHellman.Create();
            eph.ImportSubjectPublicKeyInfo(Convert.FromBase64String(p.Epk), out _);

            var kek = mine.DeriveKeyFromHash(eph.PublicKey, HashAlgorithmName.SHA256);
            contentKey = AesGcmDecrypt(kek, FromB64(wk.Iv), FromB64(wk.Wrap), FromB64(wk.Tag));
            var plain = AesGcmDecrypt(contentKey, FromB64(p.Iv), FromB64(p.Ct), FromB64(p.Tag));
            return new(MessageDecryptOutcome.Success, Encoding.UTF8.GetString(plain));
        }
        catch (AuthenticationTagMismatchException)
        {
            return new(MessageDecryptOutcome.AuthenticationFailed);
        }
        catch (FormatException)
        {
            return new(MessageDecryptOutcome.Malformed);
        }
        catch (ArgumentException)
        {
            return new(MessageDecryptOutcome.Malformed);
        }
        catch (CryptographicException)
        {
            return new(MessageDecryptOutcome.Malformed);
        }
        finally
        {
            if (contentKey is not null)
                CryptographicOperations.ZeroMemory(contentKey);
        }
    }

    /// <summary>Stable short id for a device public key (matches the relay's device-id scheme).</summary>
    public static string DeviceId(string publicKeyB64)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(publicKeyB64)))[..12].ToLowerInvariant();

    private static (byte[] iv, byte[] ct, byte[] tag) AesGcmEncrypt(byte[] key, byte[] plaintext)
    {
        var iv = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var ct = new byte[plaintext.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using var gcm = new AesGcm(key, tag.Length);
        gcm.Encrypt(iv, plaintext, ct, tag);
        return (iv, ct, tag);
    }

    private static byte[] AesGcmDecrypt(byte[] key, byte[] iv, byte[] ct, byte[] tag)
    {
        var plain = new byte[ct.Length];
        using var gcm = new AesGcm(key, tag.Length);
        gcm.Decrypt(iv, ct, tag, plain);
        return plain;
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b);
    private static byte[] FromB64(string s) => Convert.FromBase64String(s);

    private static readonly System.Text.Json.JsonSerializerOptions PayloadJson =
        new(System.Text.Json.JsonSerializerDefaults.Web);

    private sealed record WrappedKey(string Iv, string Wrap, string Tag);
    private sealed record EncPayload(
        int V, string Alg, string Epk, string Iv, string Ct, string Tag,
        Dictionary<string, WrappedKey> Keys);
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
