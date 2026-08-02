namespace Mesh.Shared;

// Mesh online-only replication contracts (protocol version 9).
//
// The relay is an online-only, opaque authenticated forwarder: it never persists
// message payloads. Devices own an immutable event log in their local encrypted
// database and replicate it directly to peer devices through the relay using the
// contracts below. Every durable payload the relay ever sees is an opaque encrypted
// frame; the relay only reads route metadata.
//
// This file contains data-transfer objects, enums and constants only. It has no
// dependency on the App layer and no algorithms (those live in
// OnlineReplicationProtocol).

/// <summary>Hard, protocol-wide limits shared by every online replication participant.</summary>
public static class OnlineReplicationLimits
{
    /// <summary>Absolute ceiling for any single transport frame handed to the relay.</summary>
    public const int MaxTransportBytes = 12 * 1024 * 1024;

    /// <summary>Maximum number of events carried in one replication batch.</summary>
    public const int MaxBatchOps = 64;

    /// <summary>Maximum encoded size of one replication batch.</summary>
    public const int MaxBatchBytes = 4 * 1024 * 1024;

    /// <summary>Maximum number of sequence ranges a single request may carry.</summary>
    public const int MaxRangeRequests = 128;

    /// <summary>Out-of-order reorder window: how far ahead of the contiguous head a cursor tracks.</summary>
    public const int ReorderWindow = 1024;

    /// <summary>Fixed size, in bytes, of a cursor ahead-bitset (<see cref="ReorderWindow"/> bits).</summary>
    public const int AheadBitsBytes = ReorderWindow / 8;

    /// <summary>Maximum number of distinct origin logs a single replica tracks concurrently.</summary>
    public const int MaxTrackedOrigins = 64;

    /// <summary>Length, in hex characters, of a SHA-256 identifier or hash.</summary>
    public const int HashHexLength = 64;
}

// ---------------------------------------------------------------------------
// 1. Relay transport frames (client -> relay, relay -> client).
// ---------------------------------------------------------------------------

/// <summary>
/// A frame submitted by a client to the relay for opaque forwarding. The relay
/// authenticates the caller, stamps sender identity on delivery, and never inspects
/// or stores <see cref="Ciphertext"/>.
/// </summary>
public sealed record OnlineRelayFrame(
    string ToHandle,
    string? ToDevice,
    string FrameId,
    string PushClass,
    string Ciphertext);

/// <summary>
/// A frame delivered by the relay to a recipient client. The sender identity fields
/// are stamped by the relay from the authenticated connection and cannot be forged
/// by the submitter.
/// </summary>
public sealed record OnlineRelayDelivery(
    string FromHandle,
    string FromDevice,
    string ToHandle,
    string? ToDevice,
    string FrameId,
    string PushClass,
    string Ciphertext);

/// <summary>Result the relay returns for a submitted <see cref="OnlineRelayFrame"/>.</summary>
public sealed record OnlineRelaySendResult(
    bool Accepted,
    string Code,
    int? RetryAfterMs = null);

/// <summary>Result codes carried by <see cref="OnlineRelaySendResult.Code"/>.</summary>
public static class OnlineRelaySendCodes
{
    public const string Delivered = "delivered";
    public const string NotOnline = "not_online";
    public const string TargetDeviceUnknown = "target_device_unknown";
    public const string RateLimited = "rate_limited";
    public const string TooLarge = "too_large";
    public const string DeviceRevoked = "device_revoked";

    public static bool IsKnown(string? code)
        => code is Delivered or NotOnline or TargetDeviceUnknown
            or RateLimited or TooLarge or DeviceRevoked;
}

/// <summary>Relay hub method names used for online-only forwarding and presence.</summary>
public static class OnlineRelayMethods
{
    public const string Relay = "Relay";
    public const string ResolvePresence = "ResolvePresence";
    public const string Deliver = "Deliver";
    public const string PresenceChanged = "PresenceChanged";
    public const string Wake = "Wake";
}

/// <summary>Push urgency classes carried on a frame so the relay can pick a wake strategy.</summary>
public static class OnlinePushClasses
{
    public const string Silent = "silent";
    public const string Normal = "normal";
    public const string High = "high";

    public static bool IsKnown(string? pushClass)
        => pushClass is Silent or Normal or High;
}

// ---------------------------------------------------------------------------
// 2. End-to-end outer frame and session handshake.
// ---------------------------------------------------------------------------

/// <summary>Kinds of end-to-end frame carried opaquely inside a relay frame.</summary>
public enum E2EFrameKind
{
    SessionInit = 0,
    SessionAck = 1,
    Offer = 2,
    Request = 3,
    Batch = 4,
    Receipt = 5,
    ResyncRequest = 6,
    ResyncSnapshot = 7,
    ReadWatermark = 8,
    Custody = 9,
}

/// <summary>
/// The outer end-to-end frame. <see cref="Payload"/> is the encrypted, self-describing
/// body for the given <see cref="Kind"/> and replication <see cref="SessionId"/>.
/// </summary>
public sealed record E2EFrame(
    E2EFrameKind Kind,
    string SessionId,
    string Payload);

/// <summary>
/// Opens a replication session. Carries a fresh nonce, the sender's custody head hash
/// and authoritative auth generation, all bound by a signature over the canonical init.
/// </summary>
public sealed record ReplicationSessionInit(
    string SessionId,
    string FromDevice,
    string ToDevice,
    string Nonce,
    string CustodyHead,
    long AuthGeneration,
    string Signature);

/// <summary>
/// Acknowledges a <see cref="ReplicationSessionInit"/>, echoing the peer nonce and
/// carrying the acker's own nonce, custody head and auth generation, all signed.
/// </summary>
public sealed record ReplicationSessionAck(
    string SessionId,
    string FromDevice,
    string ToDevice,
    string Nonce,
    string PeerNonce,
    string CustodyHead,
    long AuthGeneration,
    string Signature);

// ---------------------------------------------------------------------------
// 3. Replication event: the unit of the immutable log.
// ---------------------------------------------------------------------------

/// <summary>
/// A single immutable replication event. Identity is the tuple
/// (<see cref="OriginDeviceId"/>, <see cref="LogEpoch"/>, <see cref="Seq"/>).
/// <see cref="EventId"/> is deterministically derived from the canonical header and
/// content hash. <see cref="Ciphertext"/> is opaque and never read by the relay.
/// </summary>
public sealed record ReplicationEvent(
    string EventId,
    string? ConversationId,
    string OriginAccount,
    string OriginDeviceId,
    string LogEpoch,
    ulong Seq,
    long AuthGeneration,
    string Kind,
    string EntityId,
    string CausalVersion,
    long CreatedAtUnixMs,
    string Ciphertext,
    string ContentHash,
    string Signature);

/// <summary>Unified operation kinds carried on the single replication event stream.</summary>
public static class ReplicationOpKinds
{
    public const string Message = "message";
    public const string Topic = "topic";
    public const string Conversation = "conversation";
    public const string Contact = "contact";
    public const string Circle = "circle";
    public const string Memory = "memory";
    public const string Asset = "asset";
    public const string AskUser = "ask_user";
    public const string ReadWatermark = "read_watermark";
    public const string Custody = "custody";

    public static bool IsKnown(string? kind)
        => kind is Message or Topic or Conversation or Contact or Circle
            or Memory or Asset or AskUser or ReadWatermark or Custody;
}

// ---------------------------------------------------------------------------
// 4. Cursors, offers, requests, batches, receipts, flow, resync, watermarks.
// ---------------------------------------------------------------------------

/// <summary>A compact statement of what an origin log currently offers.</summary>
public sealed record ReplicaSummary(
    string OriginDeviceId,
    string LogEpoch,
    ulong Contiguous);

/// <summary>
/// A replication cursor for one origin log: the highest contiguous sequence applied
/// plus a fixed-size bitset of out-of-order sequences received ahead of the head.
/// </summary>
public sealed record ReplicationCursorEntry(
    string LogEpoch,
    ulong Contiguous,
    byte[] AheadBits);

/// <summary>An offer of the available sequence span in an origin log.</summary>
public sealed record ReplicationOffer(
    string OriginDeviceId,
    string LogEpoch,
    ulong AvailableFrom,
    ulong AvailableThrough);

/// <summary>An inclusive sequence range.</summary>
public sealed record ReplicationRange(
    ulong FromSeq,
    ulong ToSeq);

/// <summary>A request for missing sequence ranges of one origin log.</summary>
public sealed record ReplicationRequest(
    string OriginDeviceId,
    string LogEpoch,
    IReadOnlyList<ReplicationRange> Ranges);

/// <summary>A bounded batch of events from one origin log.</summary>
public sealed record ReplicationBatch(
    string OriginDeviceId,
    string LogEpoch,
    IReadOnlyList<ReplicationEvent> Events);

/// <summary>
/// A signed persistence receipt proving a receiver durably stored an origin log up to
/// and including <see cref="ThroughSeq"/>. Distinct from a read watermark.
/// </summary>
public sealed record PersistenceReceipt(
    string ReceiverDeviceId,
    string OriginDeviceId,
    string LogEpoch,
    ulong ThroughSeq,
    string CursorHash,
    string BatchHash,
    string Signature);

/// <summary>Flow-control credits and per-batch bounds a peer advertises.</summary>
public sealed record ReplicationFlow(
    int Credits,
    int MaxBatchOps,
    int MaxBatchBytes);

/// <summary>A request to fully resynchronise an origin log from a given sequence.</summary>
public sealed record ReplicationResyncRequest(
    string OriginDeviceId,
    string LogEpoch,
    ulong FromSeq);

/// <summary>
/// A conversation read watermark. Last-writer-wins by (<see cref="Version"/> then
/// <see cref="ThroughEventId"/>); there is no per-device read matrix.
/// </summary>
public sealed record ReadWatermarkPayload(
    string ConversationId,
    string AccountHandle,
    string ThroughEventId,
    string SourceDeviceId,
    long Version,
    long UpdatedAtUnixMs);

/// <summary>Result of applying one event to a cursor. Pure, side-effect free.</summary>
public enum CursorApplyResult
{
    Duplicate = 0,
    AppliedContiguous = 1,
    AppliedAhead = 2,
    RejectedTooFarAhead = 3,
    RejectedEpochMismatch = 4,
    RejectedInvalid = 5,
}

/// <summary>A missing-range plan plus whether the gap forces a full resync.</summary>
public sealed record ReplicationRangePlan(
    IReadOnlyList<ReplicationRange> Ranges,
    bool RequiresResync);

// ---------------------------------------------------------------------------
// 7. Custody log.
// ---------------------------------------------------------------------------

/// <summary>Custody log actions. Genesis must be the first (generation 0) entry.</summary>
public enum CustodyAction
{
    Genesis = 0,
    AddDevice = 1,
    RemoveDevice = 2,
    RekeyRecovery = 3,
}

/// <summary>
/// One entry in a handle's custody hash chain. Generation 0 is the genesis (zero prev
/// hash); every later entry links to its predecessor by <see cref="PrevHash"/>. The
/// authoritative auth generation is the highest generation in a valid chain.
/// </summary>
public sealed record CustodyEntry(
    string Handle,
    long Generation,
    string EntryHash,
    string PrevHash,
    CustodyAction Action,
    string SubjectDeviceKey,
    string? RecoveryPublicKey,
    long EffectiveAtUnixMs,
    string SignerKey,
    string Signature);

/// <summary>Result of validating a custody entry or an append to a chain.</summary>
public enum CustodyValidationResult
{
    Valid = 0,
    InvalidGenesis = 1,
    BrokenChain = 2,
    Fork = 3,
    DuplicateGeneration = 4,
    InvalidSignatureShape = 5,
    HashMismatch = 6,
}

/// <summary>
/// Names of the durable data categories the relay is permitted to retain in an
/// online-only deployment. This central-storage invariant contract exists so tests can
/// assert that payload categories never appear in the allowed set. No relay code
/// depends on it yet.
/// </summary>
public static class RelayDurableCategories
{
    /// <summary>Route and presence metadata the relay may retain.</summary>
    public static readonly IReadOnlyList<string> Allowed = new[]
    {
        "handle_directory",
        "device_directory",
        "presence",
        "push_token",
        "rate_limit_counter",
    };

    /// <summary>Payload categories the relay must never durably store.</summary>
    public static readonly IReadOnlyList<string> Forbidden = new[]
    {
        "message_payload",
        "replication_event",
        "replication_batch",
        "snapshot_payload",
        "ciphertext",
    };

    public static bool IsAllowed(string category)
        => Allowed.Contains(category);

    public static bool IsForbidden(string category)
        => Forbidden.Contains(category);
}
