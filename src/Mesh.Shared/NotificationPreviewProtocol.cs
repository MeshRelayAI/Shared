using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mesh.Shared;

public sealed record NotificationPreviewRequest(
    string Handle,
    string PublicKey,
    string WakeId,
    string Nonce,
    long SentAtUnixMs,
    string Signature);

public sealed record NotificationPreviewResponse(
    string SenderHandle,
    string SenderPublicKey,
    string Ciphertext,
    string Signature);

public sealed record NotificationPreviewContent(
    string WakeId,
    string StableId,
    string SourceEventId,
    string OriginDeviceId,
    string LogEpoch,
    int Kind,
    string EntityId,
    string? ConversationId,
    string Route,
    string Title,
    string Body,
    long CreatedAtUnixMs);

/// <summary>Read-only, online preview retrieval. A preview is never a replication receipt.</summary>
public static class NotificationPreviewProtocol
{
    public const string Route = "/notifications/preview";
    public const string ClientMethod = "ReadNotificationPreview";
    public const int MaxResponseBytes = 32 * 1024;
    public const int MaxTitleChars = 160;
    public const int MaxBodyChars = 160;
    public static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan RouteLifetime = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan RetrievalBudget = TimeSpan.FromSeconds(18);
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string WakeId(string originDevice, string epoch, string notificationId, string recipientDevice)
        => Hash(string.Join('\0', "notification", originDevice, epoch, notificationId, recipientDevice));

    public static string Scope(string relayUrl, string handle, string publicKey)
        => Hash(string.Join('\0', relayUrl.TrimEnd('/'), NormalizeHandle(handle), DeviceProtocol.DeviceId(publicKey)));

    public static string NormalizeHandle(string handle) => handle.Trim().TrimStart('@').ToLowerInvariant();

    public static string Hash(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    public static bool IsWakeId(string? value)
        => value is { Length: 64 } && value.All(static c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static bool IsValidRequest(NotificationPreviewRequest? request, DateTimeOffset now)
    {
        if (request is null || request.Handle is not { Length: >= 2 and <= 64 }
            || !request.Handle.All(static c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-')
            || request.PublicKey is not { Length: > 0 and <= 256 }
            || !IsWakeId(request.WakeId)
            || request.Nonce is not { Length: 32 }
            || !request.Nonce.All(static c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/')
            || request.Signature is not { Length: > 0 and <= 256 })
            return false;
        var nowMs = now.ToUnixTimeMilliseconds();
        var window = (long)RequestLifetime.TotalMilliseconds;
        return request.SentAtUnixMs >= nowMs - window && request.SentAtUnixMs <= nowMs + window
               && MeshCrypto.Verify(request.PublicKey, RequestCanonical(request), request.Signature);
    }

    public static NotificationPreviewRequest CreateRequest(
        string handle, string publicKey, string privateKey, string wakeId, DateTimeOffset now)
    {
        if (!IsWakeId(wakeId)) throw new ArgumentException("Invalid notification wake id.", nameof(wakeId));
        var request = new NotificationPreviewRequest(
            NormalizeHandle(handle), publicKey, wakeId, MeshCrypto.NewNonce(), now.ToUnixTimeMilliseconds(), "");
        return request with { Signature = OnlineReplicationProtocol.Sign(privateKey, RequestCanonical(request)) };
    }

    public static string RequestCanonical(NotificationPreviewRequest request)
        => JsonSerializer.Serialize(new object[]
        {
            "mesh-notification-preview-v1", request.Handle, request.PublicKey,
            request.WakeId, request.Nonce, request.SentAtUnixMs
        }, Json);

    public static string ResponseCanonical(NotificationPreviewRequest request, NotificationPreviewResponse response)
        => JsonSerializer.Serialize(new object[]
        {
            "mesh-notification-preview-response-v1", RequestCanonical(request),
            response.SenderHandle, response.SenderPublicKey, response.Ciphertext
        }, Json);

    public static NotificationPreviewResponse Seal(
        NotificationPreviewRequest request, NotificationPreviewContent content,
        string senderHandle, string senderPublicKey, string senderPrivateKey)
    {
        var ciphertext = MessageCrypto.Encrypt(JsonSerializer.Serialize(content, Json), [request.PublicKey])
            ?? throw new CryptographicException("Notification preview encryption failed.");
        var response = new NotificationPreviewResponse(
            NormalizeHandle(senderHandle), senderPublicKey, ciphertext, "");
        return response with
        {
            Signature = OnlineReplicationProtocol.Sign(senderPrivateKey, ResponseCanonical(request, response))
        };
    }

    public static NotificationPreviewContent Open(
        NotificationPreviewRequest request, NotificationPreviewResponse response,
        string privateKey, IReadOnlyCollection<string> authorizedSenderKeys)
    {
        if (response.SenderHandle is not { Length: >= 2 and <= 64 }
            || response.SenderPublicKey is not { Length: > 0 and <= 256 }
            || response.Ciphertext is not { Length: > 0 and <= MaxResponseBytes }
            || !authorizedSenderKeys.Contains(response.SenderPublicKey, StringComparer.Ordinal)
            || !MeshCrypto.Verify(response.SenderPublicKey, ResponseCanonical(request, response), response.Signature))
            throw new CryptographicException("Notification preview authentication failed.");
        var decrypted = MessageCrypto.TryDecrypt(response.Ciphertext, privateKey, request.PublicKey);
        if (!decrypted.IsSuccess || decrypted.Plaintext is null)
            throw new CryptographicException("Notification preview decryption failed.");
        var content = JsonSerializer.Deserialize<NotificationPreviewContent>(decrypted.Plaintext, Json)
            ?? throw new InvalidDataException("Empty notification preview.");
        if (content.WakeId != request.WakeId
            || content.OriginDeviceId != DeviceProtocol.DeviceId(response.SenderPublicKey)
            || content.StableId is not { Length: > 0 and <= 256 }
            || content.LogEpoch is not { Length: > 0 and <= 128 }
            || content.EntityId is not { Length: > 0 and <= 256 }
            || content.SourceEventId is not { Length: 64 }
            || content.Title is not { Length: > 0 and <= MaxTitleChars }
            || content.Body is null || content.Body.Length > MaxBodyChars + 3
            || content.Route is not { Length: > 0 and <= 1024 }
            || !IsNotificationRoute(content) || content.Kind is < 0 or > 8
            || content.CreatedAtUnixMs < 0 || content.CreatedAtUnixMs > DateTimeOffset.MaxValue.ToUnixTimeMilliseconds()
            || WakeId(content.OriginDeviceId, content.LogEpoch, content.StableId,
                DeviceProtocol.DeviceId(request.PublicKey)) != request.WakeId)
            throw new InvalidDataException("Notification preview does not match the requested activity.");
        return content;
    }

    private static bool IsNotificationRoute(NotificationPreviewContent content)
    {
        if (!Uri.TryCreate(content.Route, UriKind.Absolute, out var route) || route.Scheme != "mesh"
            || route.Query.Length > 0 || route.Fragment.Length > 0 || route.UserInfo.Length > 0
            || !route.IsDefaultPort)
            return false;
        var parts = route.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(Uri.UnescapeDataString).ToArray();
        var conversation = content.ConversationId ?? content.EntityId;
        return route.Host switch
        {
            "messages" => content.Kind is 0 or 7 or 8 && parts.Length == 1 && parts[0] == conversation,
            "me" when content.Kind is 1 or 2 or 3
                => parts.Length == 1 && parts[0] == conversation,
            "me" when content.Kind == 4
                => parts.Length == 3 && parts[0] == conversation && parts[1] == "ask" && parts[2] == content.EntityId,
            "requests" => content.Kind is 6 or 7 && parts.Length == 0,
            "approvals" => content.Kind == 5 && parts.Length == 0,
            _ => false
        };
    }
}
