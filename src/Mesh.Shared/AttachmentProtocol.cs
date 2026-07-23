using System;
using System.Linq;
using System.Security.Cryptography;

namespace Mesh.Shared;

/// <summary>
/// Canonical strings and constants for the blob-backed attachment transport. Attachments never travel
/// inline in an envelope (the relay persists each envelope as a single Cosmos item, hard-capped at 2 MB).
/// Instead the client encrypts each attachment locally, uploads the ciphertext to blob storage through a
/// short-lived relay-issued SAS URL, and the envelope carries only an <see cref="AttachmentPointer"/>
/// inside its end-to-end-encrypted body, so the relay and storage never see plaintext.
/// </summary>
public static class AttachmentProtocol
{
    /// <summary>Default blob container name that holds attachment ciphertext.</summary>
    public const string Container = "attachments";

    /// <summary>
    /// Blobs auto-expire this many days after creation, matching the 14-day inbox TTL so an attachment
    /// never outlives its message. Enforced by a storage lifecycle rule on the container, not per-blob TTL.
    /// </summary>
    public const int RetentionDays = 14;

    /// <summary>Max size of a single attachment (plaintext). Mirrors <see cref="MessageLimits.MaxAttachmentBytes"/>.</summary>
    public const long MaxAttachmentBytes = MessageLimits.MaxAttachmentBytes;

    /// <summary>Canonical string a device signs to request an upload SAS URL (proof of key possession).</summary>
    public static string UploadMessage(string handle, string deviceId, long size)
        => $"attach-upload|{LinkProtocol.Normalize(handle)}|{deviceId}|{size}";

    /// <summary>Canonical string a device signs to request a download SAS URL for one blob.</summary>
    public static string DownloadMessage(string handle, string deviceId, string blobId)
        => $"attach-download|{LinkProtocol.Normalize(handle)}|{deviceId}|{blobId}";

    /// <summary>A blob id is a 32-char lowercase hex GUID ("N" format). Validates untrusted route input.</summary>
    public static bool IsValidBlobId(string? blobId)
        => !string.IsNullOrEmpty(blobId)
           && blobId.Length == 32
           && blobId.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

/// <summary>
/// Pointer to one encrypted attachment blob, carried inside the end-to-end-encrypted envelope body. The
/// relay and blob storage only ever see ciphertext; <see cref="Key"/> (which decrypts the blob) is
/// protected by the envelope's E2EE and never leaves the client in the clear.
/// </summary>
public sealed record AttachmentPointer(
    string BlobId,
    string Name,
    string MimeType,
    long Size,
    string Key,
    string Sha256);

/// <summary>Requests a short-lived upload SAS URL for one attachment blob. Signed with the device key.</summary>
public sealed record AttachmentUploadRequest(
    string DevicePublicKey,
    long Size,
    string Signature);

/// <summary>The short-lived URL the client PUTs ciphertext to, plus the assigned blob id.</summary>
public sealed record AttachmentUploadResponse(
    string BlobId,
    string UploadUrl,
    DateTimeOffset ExpiresAt,
    long MaxBytes);

/// <summary>Requests a short-lived download SAS URL for one attachment blob. Signed with the device key.</summary>
public sealed record AttachmentDownloadRequest(
    string DevicePublicKey,
    string Signature);

/// <summary>The short-lived URL the client GETs ciphertext from.</summary>
public sealed record AttachmentDownloadResponse(
    string DownloadUrl,
    DateTimeOffset ExpiresAt);

/// <summary>
/// Symmetric AEAD used to seal an attachment before upload. A fresh random 256-bit key encrypts the bytes
/// with AES-256-GCM; the wire layout is nonce(12) || tag(16) || ciphertext. The key travels only inside the
/// E2EE <see cref="AttachmentPointer"/>, so the relay and storage never see plaintext or the key.
/// </summary>
public static class AttachmentCrypto
{
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private const int KeyLen = 32;

    /// <summary>Encrypts <paramref name="plaintext"/> with a fresh key. Returns the sealed bytes and the base64 key.</summary>
    public static (byte[] ciphertext, string keyB64) Seal(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var key = RandomNumberGenerator.GetBytes(KeyLen);
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        var ct = new byte[plaintext.Length];
        var tag = new byte[TagLen];
        using (var gcm = new AesGcm(key, TagLen))
            gcm.Encrypt(nonce, plaintext, ct, tag);

        var sealedBytes = new byte[NonceLen + TagLen + ct.Length];
        Buffer.BlockCopy(nonce, 0, sealedBytes, 0, NonceLen);
        Buffer.BlockCopy(tag, 0, sealedBytes, NonceLen, TagLen);
        Buffer.BlockCopy(ct, 0, sealedBytes, NonceLen + TagLen, ct.Length);
        return (sealedBytes, Convert.ToBase64String(key));
    }

    /// <summary>Decrypts bytes produced by <see cref="Seal"/> using the base64 key carried in the pointer.</summary>
    public static byte[] Open(byte[] sealedBytes, string keyB64)
    {
        ArgumentNullException.ThrowIfNull(sealedBytes);
        if (sealedBytes.Length < NonceLen + TagLen)
            throw new ArgumentException("attachment ciphertext too short", nameof(sealedBytes));

        var key = Convert.FromBase64String(keyB64);
        var nonce = new byte[NonceLen];
        var tag = new byte[TagLen];
        var ct = new byte[sealedBytes.Length - NonceLen - TagLen];
        Buffer.BlockCopy(sealedBytes, 0, nonce, 0, NonceLen);
        Buffer.BlockCopy(sealedBytes, NonceLen, tag, 0, TagLen);
        Buffer.BlockCopy(sealedBytes, NonceLen + TagLen, ct, 0, ct.Length);

        var plain = new byte[ct.Length];
        using (var gcm = new AesGcm(key, TagLen))
            gcm.Decrypt(nonce, ct, tag, plain);
        return plain;
    }

    /// <summary>Base64 SHA-256 of the plaintext, used as an integrity check after download.</summary>
    public static string Sha256B64(byte[] data) => Convert.ToBase64String(SHA256.HashData(data));
}
