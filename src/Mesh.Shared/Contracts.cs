using System.Text.Json;

namespace Mesh.Shared;

/// <summary>
/// Register (or re-assert) a handle together with a device public key.
/// <para>
/// Collision avoidance: <see cref="Signature"/> is a proof of possession over
/// <c>ClaimProtocol.Message(handle, devicePublicKey)</c>, produced with the device PRIVATE key.
/// The relay rejects any registration whose signature does not verify against the presented
/// device public key, so a handle can only ever be claimed or re-asserted by someone who
/// actually controls the key. Taking over an already-claimed handle with a different key still
/// requires device linking or recovery (proof of the handle's recovery key).
/// </para>
/// </summary>
public record RegisterHandleRequest(
    string Handle,
    string DevicePublicKey,
    string? DisplayName,
    string? RecoveryPublicKey = null,
    string? Signature = null,
    string? DeviceName = null,
    string? DevicePlatform = null,
    bool RemoteAgentEnabled = false);

/// <summary>Canonical string a registrant signs with its device key to prove key possession.</summary>
public static class ClaimProtocol
{
    public static string Message(string handle, string devicePublicKey)
        => $"handle-claim|{LinkProtocol.Normalize(handle)}|{devicePublicKey}";
}

public record RegisterHandleResponse(
    string Handle,
    string DeviceId,
    DateTimeOffset RegisteredAt);

/// <summary>
/// Recover a handle onto a brand-new device when no existing device is available to issue a
/// link invite. The new device presents its own fresh public key, signed by the handle's
/// recovery private key (which travels only inside the user's passphrase-encrypted export).
/// The relay verifies the signature against the recovery public key stored at registration and,
/// on success, authorizes the new device key under the handle.
/// Signature is over <c>handle-recover|handle|newPublicKey</c> by the recovery key.
/// </summary>
public record RecoverHandleRequest(
    string Handle,
    string NewPublicKey,
    string RecoverySignature);

/// <summary>Canonical strings for handle recovery.</summary>
public static class RecoveryProtocol
{
    public static string Message(string handle, string newPublicKey)
        => $"handle-recover|{LinkProtocol.Normalize(handle)}|{newPublicKey}";
}

/// <summary>
/// Delete (release) a handle so its name becomes free to claim again. Authenticated: the caller
/// signs with a device key currently registered under the handle, proving ownership. The relay
/// verifies the key is registered and the signature is valid, then removes the handle registration
/// (and its pending invites and offline inbox). This is what makes handle names truly reusable and
/// prevents stale registrations from blocking a legitimate re-creation.
/// Signature is over <c>handle-delete|handle</c> by a registered device key.
/// </summary>
public record DeleteHandleRequest(
    string Handle,
    string DevicePublicKey,
    string Signature);

/// <summary>Canonical string a device signs to delete (release) its handle.</summary>
public static class DeleteProtocol
{
    public static string Message(string handle)
        => $"handle-delete|{LinkProtocol.Normalize(handle)}";
}

/// <summary>
/// Device-linking: an already-authorized device creates a short-lived, single-use
/// invite so another device can join the same handle. The relay only stores the
/// hash of the code; the raw code travels out-of-band (QR) to the new device.
/// Signature is over <c>link-invite|handle|codeHash|expiresAtUnix</c> by the creator key.
/// </summary>
public record LinkInviteRequest(
    string Handle,
    string CreatorPublicKey,
    string CodeHash,
    long ExpiresAtUnix,
    string Signature);

public record LinkInviteResponse(string Handle, long ExpiresAtUnix);

/// <summary>
/// Device-linking redemption by the new device. Presents the raw invite code plus
/// its own new public key, signed to prove key possession.
/// Signature is over <c>link-redeem|handle|code</c> by <see cref="NewPublicKey"/>.
/// </summary>
public record LinkRedeemRequest(
    string Handle,
    string NewPublicKey,
    string Code,
    string Signature);

public record LinkRedeemResponse(string Handle, string DeviceId, string? DisplayName);

/// <summary>Canonical strings + hashing used by both client and relay for device-linking.</summary>
public static class LinkProtocol
{
    public static string InviteMessage(string handle, string codeHash, long expiresAtUnix)
        => $"link-invite|{Normalize(handle)}|{codeHash}|{expiresAtUnix}";

    public static string RedeemMessage(string handle, string code)
        => $"link-redeem|{Normalize(handle)}|{code}";

    public static string HashCode(string code)
        => Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(code)));

    public static string Normalize(string handle)
        => handle.Trim().TrimStart('@').ToLowerInvariant();
}

/// <summary>
/// Custom-scheme deep links (mesh://) that route the app to a service or a handle. Services are public,
/// so unlike the pairing link these carry no crypto, just a navigation target. Builders and a tolerant
/// parser live here so the client (share buttons + router) and any tooling agree on the format.
/// </summary>
public static class DeepLink
{
    public const string Scheme = "mesh";

    /// <summary>mesh://service?handle=&id=&name= (name optional, for display before the thread loads).</summary>
    public static string Service(string handle, string serviceId, string? name = null)
    {
        var q = $"handle={Uri.EscapeDataString(LinkProtocol.Normalize(handle))}&id={Uri.EscapeDataString(serviceId)}";
        if (!string.IsNullOrWhiteSpace(name)) q += $"&name={Uri.EscapeDataString(name)}";
        return $"mesh://service?{q}";
    }

    /// <summary>mesh://user?handle= (open/add a contact and start a conversation).</summary>
    public static string User(string handle)
        => $"mesh://user?handle={Uri.EscapeDataString(LinkProtocol.Normalize(handle))}";

    /// <summary>mesh://link?handle=&amp;code=&amp;relay= for short-lived single-use device linking.</summary>
    public static string Pairing(string handle, string code, string? relayUrl = null)
    {
        var q = $"handle={Uri.EscapeDataString(LinkProtocol.Normalize(handle))}&code={Uri.EscapeDataString(code.Trim())}";
        if (!string.IsNullOrWhiteSpace(relayUrl))
            q += $"&relay={Uri.EscapeDataString(relayUrl.TrimEnd('/'))}";
        return $"mesh://link?{q}";
    }

    public enum Kind { None, Service, User, Pairing }

    /// <summary>Parsed deep link. Fields are populated per <see cref="Kind"/>; Raw always echoes the input.</summary>
    public readonly record struct Parsed(Kind Kind, string? Handle, string? ServiceId, string? ServiceName, string? Raw)
    {
        public string? PairingCode { get; init; }
        public string? RelayUrl { get; init; }
    }

    /// <summary>
    /// Tolerantly parses a mesh:// URI into a routing target. Returns Kind.None for anything that is not
    /// a recognized mesh link. Recognizes service, user, and the existing link (pairing) hosts.
    /// </summary>
    public static Parsed TryParse(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri)) return new Parsed(Kind.None, null, null, null, uri);
        if (!Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var u)
            || !string.Equals(u.Scheme, Scheme, StringComparison.OrdinalIgnoreCase))
            return new Parsed(Kind.None, null, null, null, uri);

        var host = u.Host.ToLowerInvariant();
        var q = ParseQuery(u.Query);
        switch (host)
        {
            case "service":
                return new Parsed(Kind.Service, LinkProtocol.Normalize(Get(q, "handle")), Get(q, "id"), Get(q, "name"), uri);
            case "user":
                return new Parsed(Kind.User, LinkProtocol.Normalize(Get(q, "handle")), null, null, uri);
            case "link":
                return new Parsed(Kind.Pairing, LinkProtocol.Normalize(Get(q, "handle")), null, null, uri)
                {
                    PairingCode = Get(q, "code"),
                    RelayUrl = Get(q, "relay")
                };
            default:
                return new Parsed(Kind.None, null, null, null, uri);
        }
    }

    public static bool TryParsePairing(string? value, out Parsed pairing)
    {
        pairing = default;
        if (string.IsNullOrWhiteSpace(value)) return false;

        var parsed = TryParse(value);
        if (parsed.Kind == Kind.Pairing && !string.IsNullOrWhiteSpace(parsed.PairingCode))
        {
            pairing = parsed;
            return true;
        }

        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || !uri.AbsolutePath.Equals("/link", StringComparison.OrdinalIgnoreCase))
            return false;

        var q = ParseQuery(string.IsNullOrWhiteSpace(uri.Fragment) ? uri.Query : uri.Fragment);
        var code = Get(q, "code");
        if (string.IsNullOrWhiteSpace(code)) return false;

        pairing = new Parsed(Kind.Pairing, LinkProtocol.Normalize(Get(q, "handle")), null, null, value)
        {
            PairingCode = code,
            RelayUrl = Get(q, "relay")
        };
        return true;
    }

    private static string Get(Dictionary<string, string> q, string key)
        => q.TryGetValue(key, out var v) ? v : "";

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;
        foreach (var pair in query.TrimStart('?', '#').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) { result[Uri.UnescapeDataString(pair)] = ""; continue; }
            var key = Uri.UnescapeDataString(pair[..eq]);
            var val = Uri.UnescapeDataString(pair[(eq + 1)..]);
            result[key] = val;
        }
        return result;
    }
}

/// <summary>
/// Public https universal links served by the relay landing pages (meshrelay.net). These are the
/// shareable links (work for people without the app: the page bounces to the mesh:// deep link, else
/// offers install). Client share buttons emit these; the relay serves /s/{handle}/{serviceId} and
/// /u/{handle}. Kept here so the URL format stays in sync on both sides.
/// </summary>
public static class UniversalLink
{
    public const string BaseUrl = "https://meshrelay.net";

    public static string ForService(string handle, string serviceId)
        => $"{BaseUrl}/s/{Uri.EscapeDataString(LinkProtocol.Normalize(handle))}/{Uri.EscapeDataString(serviceId)}";

    public static string ForHandle(string handle)
        => $"{BaseUrl}/u/{Uri.EscapeDataString(LinkProtocol.Normalize(handle))}";

    public static string ForPairing(string handle, string code, string? relayUrl = null)
    {
        var q = $"handle={Uri.EscapeDataString(LinkProtocol.Normalize(handle))}&code={Uri.EscapeDataString(code.Trim())}";
        if (!string.IsNullOrWhiteSpace(relayUrl))
            q += $"&relay={Uri.EscapeDataString(relayUrl.TrimEnd('/'))}";
        return $"{BaseUrl}/link#{q}";
    }
}

/// <summary>
/// Brokered token exchange: for confidential connectors (Google, Notion, Slack, …) the client
/// forwards an OAuth grant to the relay, which holds the client secret and performs the exchange.
/// Supports both the initial <c>authorization_code</c> exchange and hourly <c>refresh_token</c>
/// refresh. The client authenticates with a device key registered under its handle, so only real
/// Mesh users can use the shared OAuth apps.
/// Signature is over <c>connector-token|provider|handle|grantType|secretHash|redirectUri</c> by the
/// device key, where <c>secretHash</c> hashes the code (auth code grant) or the refresh token.
/// </summary>
public record ConnectorTokenRequest(
    string Provider,
    string Handle,
    string DevicePublicKey,
    string GrantType,
    string? Code,
    string? RedirectUri,
    string? CodeVerifier,
    string? RefreshToken,
    string Signature);

/// <summary>The provider's raw token response, passed back verbatim as JSON.</summary>
public record ConnectorTokenResponse(string TokenJson);

/// <summary>
/// Public OAuth metadata for a built-in connector, served by the relay's <c>GET /connectors</c>
/// endpoint and consumed by the client to build authorize requests. This is a data shape only:
/// it carries public identifiers (authorize/token URLs and the OAuth <b>client id</b>, which is
/// public and appears in every authorize URL). Client <b>secrets</b> are never part of this type,
/// for confidential providers the relay injects the secret server-side during the token exchange.
/// The concrete values (which client ids to use) live in the relay's configuration, not in the
/// open shared library, so the shared code carries no app-specific credentials.
/// </summary>
public sealed record ConnectorEndpoint(
    string Key,
    string AuthorizeUrl,
    string TokenUrl,
    string ClientId,
    bool UseBasicAuth,
    bool Confidential);

/// <summary>Canonical strings used by both client and relay for the connector token broker.</summary>
public static class ConnectorProtocol
{
    public const string GrantAuthCode = "authorization_code";
    public const string GrantRefresh = "refresh_token";

    /// <summary>The value bound into the signature: the code (auth code grant) or refresh token.</summary>
    public static string SecretMaterial(string grantType, string? code, string? refreshToken)
        => grantType == GrantRefresh ? (refreshToken ?? "") : (code ?? "");

    public static string TokenMessage(string provider, string handle, string grantType, string secretHash, string? redirectUri)
        => $"connector-token|{provider.ToLowerInvariant()}|{LinkProtocol.Normalize(handle)}|{grantType}|{secretHash}|{redirectUri ?? ""}";
}

/// <summary>Public directory view of a handle (no private data).</summary>
public record HandleInfo(
    string Handle,
    string? DisplayName,
    IReadOnlyList<string> DevicePublicKeys,
    bool Online,
    DateTimeOffset RegisteredAt);

/// <summary>
/// Public view of a single device under a handle: its stable device id, a friendly name (if the
/// device set one), and whether it is currently connected. Served by GET /handles/{handle}/devices
/// so a client can offer a "home device" picker and route remote-agent requests to one device.
/// </summary>
public record DeviceInfo(
    string DeviceId,
    string? Name,
    bool Online,
    string Platform = DevicePlatforms.Unknown,
    bool RemoteAgentEnabled = false)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsDesktop => DevicePlatforms.IsDesktop(Platform);

    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsEligibleHomeAgent => IsDesktop && RemoteAgentEnabled;
}

public static class DevicePlatforms
{
    public const string Unknown = "unknown";
    public const string Windows = "windows";
    public const string MacOS = "macos";
    public const string Android = "android";
    public const string IOS = "ios";

    public static bool IsDesktop(string? platform)
        => platform is not null
           && (platform.Equals(Windows, StringComparison.OrdinalIgnoreCase)
               || platform.Equals(MacOS, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Canonical, stable derivation of a short device id from a device public key. Shared by the relay
/// and the client so both compute the SAME id for a given key. This is what lets an envelope target
/// one specific device of a handle (MeshEnvelope.ToDevice) rather than every device.
/// </summary>
public static class DeviceProtocol
{
    public static string DeviceId(string devicePublicKey)
        => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(devicePublicKey)))[..12].ToLowerInvariant();
}

public sealed record RemoteAgentRequestPayload(string RequestId, string ThreadId, string Prompt);

public sealed record RemoteAgentResponsePayload(string RequestId, string ThreadId, string Text);

public sealed record RemoteAgentDispatchResult(bool Accepted, string Code, string RequestId)
{
    public static RemoteAgentDispatchResult Ok(string requestId) => new(true, "accepted", requestId);
    public static RemoteAgentDispatchResult Reject(string code, string requestId = "") => new(false, code, requestId);
}

public static class RemoteAgentProtocol
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string RequestBody(string requestId, string threadId, string prompt)
        => JsonSerializer.Serialize(new RemoteAgentRequestPayload(requestId, threadId, prompt), Json);

    public static string ResponseBody(string requestId, string threadId, string text)
        => JsonSerializer.Serialize(new RemoteAgentResponsePayload(requestId, threadId, text), Json);

    public static bool TryParseRequest(string? body, out RemoteAgentRequestPayload request)
    {
        request = default!;
        try
        {
            var parsed = JsonSerializer.Deserialize<RemoteAgentRequestPayload>(body ?? "", Json);
            if (parsed is null
                || string.IsNullOrWhiteSpace(parsed.RequestId)
                || string.IsNullOrWhiteSpace(parsed.ThreadId)
                || string.IsNullOrWhiteSpace(parsed.Prompt))
                return false;
            request = parsed;
            return true;
        }

        catch (JsonException) { return false; }
    }

    public static bool TryParseResponse(string? body, out RemoteAgentResponsePayload response)
    {
        response = default!;
        try
        {
            var parsed = JsonSerializer.Deserialize<RemoteAgentResponsePayload>(body ?? "", Json);
            if (parsed is null
                || string.IsNullOrWhiteSpace(parsed.RequestId)
                || string.IsNullOrWhiteSpace(parsed.ThreadId)
                || string.IsNullOrWhiteSpace(parsed.Text))
                return false;
            response = parsed;
            return true;
        }
        catch (JsonException) { return false; }
    }
}

public static class DeviceSyncKinds
{
    public const string EnvelopeOperation = "device.sync.operation";
    public const string EnvelopeSnapshotRequest = "device.sync.snapshot.request";

    public const string TopicUpsert = "topic.upsert";
    public const string TopicDelete = "topic.delete";
    public const string TopicClear = "topic.clear";
    public const string TopicLineUpsert = "topic.line.upsert";
    public const string ConversationUpsert = "conversation.upsert";
    public const string ConversationDelete = "conversation.delete";
    public const string ConversationClear = "conversation.clear";
    public const string ConversationLineUpsert = "conversation.line.upsert";
    public const string ContactUpsert = "contact.upsert";
    public const string ContactDelete = "contact.delete";
    public const string CircleUpsert = "circle.upsert";
    public const string CircleDelete = "circle.delete";

     public static bool IsEnvelopeKind(string? kind)
        => kind is EnvelopeOperation or EnvelopeSnapshotRequest;
}

public sealed record DeviceSyncOperation(
    string OperationId,
    string SourceDeviceId,
    string Kind,
    string EntityId,
    string Version,
    string Payload);

public sealed record DeviceSyncBatch(
    string BatchId,
    string SourceDeviceId,
    bool IsSnapshot,
    IReadOnlyList<DeviceSyncOperation> Operations);

public sealed record DeviceSyncSnapshotRequest(string RequestId, string RequestingDeviceId);

public sealed record DeviceSyncTopic(
    string Id,
    string Title,
    DateTimeOffset CreatedAt,
    int SortOrder);

public sealed record DeviceSyncConversation(
    string Handle,
    int SortOrder,
    string? ServiceId,
    string? ServiceName,
    string? ProviderHandle,
    string? GroupId,
    string? GroupName,
    string? GroupOwnerHandle,
    IReadOnlyList<string> GroupMembers,
    int GroupVersion);

public sealed record DeviceSyncContact(
    string Handle,
    string? DisplayName,
    IReadOnlyList<string> Circles,
    bool Allowed,
    IReadOnlyList<string> SigningKeys,
    bool KeyChanged,
    bool Muted,
    bool Blocked);

public sealed record DeviceSyncCircle(
    string Name,
    bool RequireApproval,
    IReadOnlyList<DeviceSyncCircleRename>? Renames = null);

public sealed record DeviceSyncCircleRename(
    string PreviousName,
    string DeleteVersion);

public sealed record DeviceSyncLine(
    string Id,
    string Role,
    string Text,
    string Via,
    string Status,
    DateTimeOffset At,
    string? SenderHandle,
    bool Internal,
    string? Reasoning);

public static class DeviceSyncVersion
{
    public static string Create(DateTimeOffset at, string sourceDeviceId, string operationId)
        => $"{at.UtcDateTime.Ticks:D19}|{sourceDeviceId}|{operationId}";

    public static int Compare(string? left, string? right)
        => string.Compare(left ?? "", right ?? "", StringComparison.Ordinal);

    public static bool IsNewer(string candidate, string? current)
        => Compare(candidate, current) > 0;
}

/// <summary>
/// A request to the relay-hosted free model. The relay holds the upstream model key
/// server-side and proxies the completion, rate limited per handle, so first-launch users
/// get a working model with no key of their own. The caller proves it owns a device key
/// registered under its handle (same device-key auth as the connector broker).
/// Signature is over <c>hosted-model|handle|promptHash</c> by the device key.
/// </summary>
public record HostedModelRequest(
    string Handle,
    string DevicePublicKey,
    string Signature,
    string SystemPrompt,
    IReadOnlyList<HostedModelMessage> Messages,
    string? ToolsJson = null,
    int MaxTokens = 0);

/// <summary>
/// A single message in a hosted-model conversation. <see cref="ToolCallsJson"/> carries an
/// assistant turn's raw OpenAI tool_calls array; a message with <see cref="ToolCallId"/> and
/// Role "tool" carries a tool result. Both are null for ordinary user/assistant text.
/// </summary>
public record HostedModelMessage(string Role, string Content, string? ToolCallsJson = null, string? ToolCallId = null);

/// <summary>
/// The hosted model reply. <see cref="Content"/> is the assistant text; when the model wants to
/// call tools, <see cref="ToolCallsJson"/> holds the raw OpenAI tool_calls array so the CLIENT
/// can execute the tools locally (the relay never runs them) and continue the conversation.
/// Token usage (as reported by the upstream model) is echoed back so the client can show a live
/// token counter and so free-tier metering is done in tokens, the primary cost currency.
/// <see cref="FinishReason"/> echoes the upstream stop reason (e.g. "length" when the output-token
/// limit truncated the reply) so the client can reject a truncated answer instead of rendering it.
/// </summary>
public record HostedModelResponse(
    string Content,
    string? ToolCallsJson = null,
    int PromptTokens = 0,
    int CompletionTokens = 0,
    int TotalTokens = 0,
    string? FinishReason = null);

/// <summary>Canonical strings for the hosted-model proxy signature.</summary>
public static class HostedModelProtocol
{
    public static string Message(string handle, string promptHash)
        => $"hosted-model|{LinkProtocol.Normalize(handle)}|{promptHash}";

    public static string PromptHash(string systemPrompt, IEnumerable<HostedModelMessage> messages)
    {
        var joined = systemPrompt + "\n" + string.Join("\n", messages.Select(m => m.Role + ":" + m.Content));
        return Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(joined)));
    }
}

/// <summary>
/// An end-to-end message routed by the relay between two handles.
/// The relay treats <see cref="Body"/> as opaque and never inspects it.
/// </summary>
public record MeshEnvelope(
    string Id,
    string From,
    string To,
    string Kind,
    string Body,
    string? Signature,
    DateTimeOffset SentAt,
    string? FromDevice = null,
    string? ToDevice = null)
{
    public static MeshEnvelope Create(string from, string to, string kind, string body, string? signature = null,
        string? fromDevice = null, string? toDevice = null)
        => new(Guid.NewGuid().ToString("n"), from, to, kind, body, signature, DateTimeOffset.UtcNow, fromDevice, toDevice);
}

/// <summary>
/// One opaque ciphertext routed to several handles. The relay receives no group identifier or
/// membership metadata beyond the transient recipient list required for delivery.
/// </summary>
public sealed record MeshFanoutRequest(
    string Id,
    IReadOnlyList<string> Recipients,
    string Body,
    string? Signature,
    DateTimeOffset SentAt);

/// <summary>
/// Dispatch metadata carried inside an encrypted fan-out body. The relay sees only ciphertext.
/// </summary>
public sealed record MeshFanoutContent(string Kind, string Payload);

/// <summary>Explicit hub acknowledgement for a logical direct or fan-out send.</summary>
public sealed record MeshSendResult(
    bool Accepted,
    string Code,
    int RetryAfterMs = 0,
    int RecipientCount = 0)
{
    public static MeshSendResult Ok(int recipientCount = 1) => new(true, "accepted", 0, recipientCount);
    public static MeshSendResult Reject(string code, int retryAfterMs = 0)
        => new(false, code, Math.Max(0, retryAfterMs), 0);
}

/// <summary>Batch request for public device encryption keys.</summary>
public sealed record HandleKeysBatchRequest(IReadOnlyList<string> Handles);

/// <summary>Public device keys registered under one normalized handle.</summary>
public sealed record HandleKeysBatchEntry(string Handle, IReadOnlyList<string> DevicePublicKeys);

/// <summary>Batch directory response. Missing handles are omitted.</summary>
public sealed record HandleKeysBatchResponse(IReadOnlyList<HandleKeysBatchEntry> Handles);

/// <summary>Hard transport bounds for stateless relay fan-out.</summary>
public static class FanoutProtocol
{
    public const int MaxRecipients = 128;
}

/// <summary>
/// Complete client-side group metadata carried only inside an end-to-end encrypted envelope body.
/// </summary>
public sealed record GroupSnapshotPayload(
    string GroupId,
    string Name,
    string OwnerHandle,
    IReadOnlyList<string> MemberHandles,
    int Version);

/// <summary>A group chat message carried only inside an end-to-end encrypted envelope body.</summary>
public sealed record GroupMessagePayload(
    string GroupId,
    string MessageId,
    string SenderHandle,
    string Text,
    int MembershipVersion,
    DateTimeOffset SentAt);

/// <summary>Well-known envelope kinds for the prototype.</summary>
public static class MeshKinds
{
    public const string Chat = "chat";
    public const string AgentRequest = "agent.request";
    public const string AgentResponse = "agent.response";
    public const string System = "system";
    public const string Fanout = "fanout";
    public const string GroupControl = "group.control";
    public const string GroupMessage = "group.message";

    /// <summary>
    /// A person-to-person message addressed to the human, not their agent. The
    /// receiving client records it but does NOT auto-engage the guest agent.
    /// </summary>
    public const string DirectMessage = "direct";

    /// <summary>
    /// A delivery receipt: the recipient's client acknowledges it received a specific message.
    /// The body carries the acknowledged message id (see <see cref="ReceiptProtocol"/>).
    /// </summary>
    public const string Receipt = "receipt";

    /// <summary>
    /// A request from one of the owner's OWN devices to another (e.g. phone to home desktop) asking
    /// the remote device's agent to answer with its full local toolset. Only honored between devices
    /// sharing the same handle when the target has opted in (ActAsRemoteAgent).
    /// </summary>
    public const string RemoteAgentRequest = "remote.request";

    /// <summary>The remote device's answer to a <see cref="RemoteAgentRequest"/>.</summary>
    public const string RemoteAgentResponse = "remote.response";

    /// <summary>
    /// A request to invoke a provider's PUBLIC service (a published capability bundle) by service id.
    /// Unlike <see cref="AgentRequest"/> it does not require an allow-listed contact relationship: any
    /// handle may invoke a public-listed service. The provider's client answers with a sandboxed
    /// service-scoped agent (published KB/Skills/Widgets only, never private connectors or local tools).
    /// The body is <see cref="ServiceProtocol"/>-framed (serviceId + prompt). The relay records the
    /// invocation as an attested usage event for reputation (it sees that it routed it, not the content).
    /// </summary>
    public const string ServiceRequest = "service.request";

    /// <summary>The provider's answer to a <see cref="ServiceRequest"/>.</summary>
    public const string ServiceResponse = "service.response";

    /// <summary>
    /// A user-submitted report of inappropriate AI-generated content, sent as an ordinary end-to-end
    /// encrypted message to the reserved <see cref="ReservedHandles.Report"/> handle for operator
    /// review (Microsoft Store Policy 11.16). The body is <see cref="ReportProtocol"/>-framed.
    /// </summary>
    public const string Report = "report";
}

/// <summary>
/// System handles the relay reserves so no ordinary user can register (hijack) them. The report sink
/// <see cref="Report"/> receives user reports of AI content and its queued messages never expire.
/// </summary>
public static class ReservedHandles
{
    /// <summary>The report sink: users send AI-content reports here for operator review.</summary>
    public const string Report = "meshreport";

    /// <summary>All reserved system handles (normalized, lowercase).</summary>
    public static readonly IReadOnlyList<string> All = new[] { Report };

    /// <summary>True when the handle is a reserved system handle (case-insensitive, @ and case tolerant).</summary>
    public static bool IsReserved(string? handle)
    {
        if (string.IsNullOrWhiteSpace(handle)) return false;
        var h = LinkProtocol.Normalize(handle);
        foreach (var r in All) if (h == r) return true;
        return false;
    }
}

/// <summary>
/// Frames the body of a <see cref="MeshKinds.Report"/> message: a JSON <see cref="ReportPayload"/>.
/// The whole body is end-to-end encrypted to the reserved report handle exactly like any message.
/// </summary>
public static class ReportProtocol
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static string Body(ReportPayload payload) => JsonSerializer.Serialize(payload, Json);

    public static ReportPayload? Parse(string body)
    {
        try { return JsonSerializer.Deserialize<ReportPayload>(body, Json); }
        catch { return null; }
    }
}

/// <summary>
/// A report of inappropriate AI-generated content. Carries the metadata and the exact transcript the
/// reporting user reviewed and explicitly agreed to share, so the operator can review the AI output.
/// </summary>
public sealed record ReportPayload(
    string Target,
    string Category,
    string? Note,
    string? Model,
    string? ServiceId,
    string AppVersion,
    DateTimeOffset At,
    IReadOnlyList<ReportLine> Transcript);

/// <summary>One transcript line included in a report: who authored it and the exact text.</summary>
public readonly record struct ReportLine(string Author, string Text);

/// <summary>
/// One turn of a service conversation carried inside a <see cref="MeshKinds.ServiceRequest"/> so the
/// provider's sandboxed agent has multi-turn context for follow-ups. Role is "user" (the consumer) or
/// "assistant" (a prior service answer), from the provider agent's point of view. The provider stays
/// stateless per caller: the consumer supplies the (windowed) transcript on every request.
/// </summary>
public readonly record struct ServiceTurn(string Role, string Text);

/// <summary>
/// Frames the body of a <see cref="MeshKinds.ServiceRequest"/> / ServiceResponse so the recipient
/// can route it to the right published service. A response (and a legacy request) is
/// <c>serviceId\ntext</c>; a modern request is <c>serviceId\n{json transcript}</c>. The whole body is
/// still end-to-end encrypted on the wire exactly like any other envelope body.
/// </summary>
public static class ServiceProtocol
{
    public static string Body(string serviceId, string text) => serviceId + "\n" + text;

    public static (string serviceId, string text) Parse(string body)
    {
        var nl = body.IndexOf('\n');
        return nl < 0 ? (body, "") : (body[..nl], body[(nl + 1)..]);
    }

    /// <summary>
    /// Frames a ServiceRequest that carries the recent transcript: <c>serviceId\n{json array of
    /// ServiceTurn}</c>. The provider feeds this to its sandboxed agent so follow-up turns have
    /// context, while the provider itself keeps no per-caller state.
    /// </summary>
    public static string RequestBody(string serviceId, IEnumerable<ServiceTurn> history)
        => serviceId + "\n" + JsonSerializer.Serialize(history);

    /// <summary>
    /// Parses a ServiceRequest body into its serviceId and transcript. Backward compatible: a legacy
    /// plain-text body (<c>serviceId\nprompt</c>) is read as a single user turn.
    /// </summary>
    public static (string serviceId, IReadOnlyList<ServiceTurn> history) ParseRequest(string body)
    {
        var (id, rest) = Parse(body);
        if (!string.IsNullOrWhiteSpace(rest) && rest.TrimStart().StartsWith("["))
        {
            try
            {
                var turns = JsonSerializer.Deserialize<List<ServiceTurn>>(rest);
                if (turns is not null) return (id, turns);
            }
            catch { /* not JSON: fall through to plain-text */ }
        }
        return (id, new List<ServiceTurn> { new("user", rest) });
    }
}

/// <summary>
/// The fixed set of service categories shown in the Community directory. Kept as a small, stable,
/// single-select taxonomy so browse/filter never fragments across free-text variants. Defined once
/// here so the relay (coercion on publish) and the client (publish dropdown + filter) always agree.
/// </summary>
public static class ServiceCategories
{
    /// <summary>Canonical categories in display order. "Other" is the catch-all.</summary>
    public static readonly IReadOnlyList<string> All = new[]
    {
        "Productivity", "Writing", "Development", "Analytics", "Business", "Marketing",
        "Research", "Education", "Design", "Lifestyle", "News", "Entertainment",
        "Professional Services", "Other"
    };

    /// <summary>The catch-all category assigned to empty or unrecognized values.</summary>
    public const string Fallback = "Other";

    /// <summary>True when <paramref name="category"/> is one of the canonical categories (case-insensitive).</summary>
    public static bool IsValid(string? category)
    {
        if (string.IsNullOrWhiteSpace(category)) return false;
        foreach (var c in All)
            if (string.Equals(c, category, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// Normalizes any input to a canonical category: matches case-insensitively and returns the
    /// canonical casing, or <see cref="Fallback"/> ("Other") for empty/unknown values. Keeps the
    /// directory clean even when older clients or hand-crafted requests send arbitrary category text.
    /// </summary>
    public static string Coerce(string? category)
    {
        if (!string.IsNullOrWhiteSpace(category))
            foreach (var c in All)
                if (string.Equals(c, category, StringComparison.OrdinalIgnoreCase)) return c;
        return Fallback;
    }
}

/// <summary>
/// A public directory listing for a published service, served by the relay's capability directory
/// (<c>GET /capabilities</c>). Carries only public data: no private KB content, just the metadata a
/// consumer needs to discover and judge a service. Reputation fields are relay-computed.
/// </summary>
public sealed record ServiceListing(
    string ServiceId,
    string Handle,
    string Name,
    string Description,
    string Category,
    int Upvotes,
    int Downvotes,
    int UniqueUsers,
    double Score,
    bool Verified,
    DateTimeOffset PublishedAt);

/// <summary>
/// Publish (or update) a service in the relay directory. Authenticated with a device key registered
/// under the handle (same device-key auth as the connector broker / hosted model). The relay stores
/// only this public metadata; the actual capabilities run on the provider's client on invocation.
/// Signature is over <see cref="ServiceDirectoryProtocol.PublishMessage"/> by the device key.
/// </summary>
public record PublishServiceRequest(
    string Handle,
    string DevicePublicKey,
    string ServiceId,
    string Name,
    string Description,
    string Category,
    string Signature);

/// <summary>Unpublish a service. Signature is over <c>service-unpublish|handle|serviceId</c>.</summary>
public record UnpublishServiceRequest(
    string Handle,
    string DevicePublicKey,
    string ServiceId,
    string Signature);

/// <summary>
/// Cast (or change/clear) a usage-gated up/down vote on a service. The relay only accepts the vote
/// when it has observed the voter's handle actually invoke the service (attested usage), and stores
/// one updatable vote per voter per service. Vote is +1 (up), -1 (down), or 0 (clear).
/// Signature is over <c>service-vote|voterHandle|serviceId|vote</c> by the voter's device key.
/// </summary>
public record ServiceVoteRequest(
    string VoterHandle,
    string DevicePublicKey,
    string ServiceId,
    int Vote,
    string Signature);

/// <summary>Canonical strings for the capability directory endpoints.</summary>
public static class ServiceDirectoryProtocol
{
    public static string PublishMessage(string handle, string serviceId, string name)
        => $"service-publish|{LinkProtocol.Normalize(handle)}|{serviceId}|{name}";

    public static string UnpublishMessage(string handle, string serviceId)
        => $"service-unpublish|{LinkProtocol.Normalize(handle)}|{serviceId}";

    public static string VoteMessage(string voterHandle, string serviceId, int vote)
        => $"service-vote|{LinkProtocol.Normalize(voterHandle)}|{serviceId}|{vote}";

    /// <summary>
    /// Wilson score lower bound of the positive proportion at 95% confidence: the ranking signal for
    /// the directory. Balances up/down proportion against sample size so a 1/1 does not outrank 90/100,
    /// and low-vote items are ranked conservatively (cold-start safe). Returns 0 when there are no votes.
    /// </summary>
    public static double WilsonScore(int up, int down)
    {
        var n = up + down;
        if (n == 0) return 0.0;
        const double z = 1.96;
        var phat = (double)up / n;
        var denom = 1 + z * z / n;
        var centre = phat + z * z / (2 * n);
        var margin = z * Math.Sqrt((phat * (1 - phat) + z * z / (4 * n)) / n);
        return (centre - margin) / denom;
    }
}

/// <summary>Canonical body format for a delivery receipt: just the acknowledged message id.</summary>
public static class ReceiptProtocol
{
    public static string Body(string messageId) => "receipt:" + messageId;
    public static string? MessageId(string body)
        => body is not null && body.StartsWith("receipt:", StringComparison.Ordinal) ? body["receipt:".Length..] : null;
}

/// <summary>
/// Names shared by the SignalR hub and the client so both agree on the transport contract.
/// The hub is used purely for the connection/transport; cross-node routing is done by the
/// relay's directed backplane (presence lookup plus per-node forward), not a fan-out backplane.
///
/// Auth is a nonce challenge/response over the connection (replay resistant): the server
/// issues a fresh nonce, the client signs it with its device private key, and the server
/// verifies against the device public keys registered under the handle.
/// </summary>
public static class MeshHubProtocol
{
    /// <summary>Relative path the hub is mapped at on the relay.</summary>
    public const string Route = "/hub/mesh";

    // Client -> server invocations.
    public const string Authenticate = "Authenticate";
    public const string SendEnvelope = "SendEnvelope";
    public const string SendFanout = "SendFanout";

    // Server -> client events.
    public const string Challenge = "Challenge"; // payload: nonce (string)
    public const string Ready = "Ready";         // payload: none (auth accepted)
    public const string Receive = "Receive";     // payload: envelope JSON (string)
}
