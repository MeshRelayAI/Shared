using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mesh.Shared;

/// <summary>
/// Pure protocol-9 online replication algorithms: canonicalisation, deterministic
/// identifiers and hashes, signature helpers, validators, the cursor / range planning
/// state machine and custody chain canonicalisation and fork detection.
///
/// Everything here is deterministic and free of I/O and storage concerns so it can be
/// unit tested directly and reused by both the relay-facing and device-side code.
/// </summary>
public static class OnlineReplicationProtocol
{
    public const int CanonicalVersion = 9;

    /// <summary>The all-zero SHA-256 hash used as the genesis predecessor.</summary>
    public static readonly string ZeroHash = new('0', OnlineReplicationLimits.HashHexLength);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // -----------------------------------------------------------------------
    // Hashing and identifiers.
    // -----------------------------------------------------------------------

    /// <summary>Lower-case hex SHA-256 of a UTF-8 string.</summary>
    public static string HashText(string text)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    /// <summary>Lower-case hex SHA-256 of raw bytes.</summary>
    public static string HashBytes(ReadOnlySpan<byte> bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>Content hash of an opaque ciphertext string.</summary>
    public static string ComputeContentHash(string ciphertext)
        => HashText(ciphertext ?? "");

    /// <summary>
    /// Length-prefixes every field by its UTF-8 byte count. This encoding is unambiguous even when
    /// user-controlled values contain separators, colons, Unicode, or embedded canonical strings.
    /// </summary>
    private static string Canonical(params string?[] fields)
    {
        var sb = new StringBuilder(fields.Sum(field => field?.Length ?? 0) + fields.Length * 8);
        foreach (var field in fields)
        {
            var value = field ?? "";
            sb.Append(Encoding.UTF8.GetByteCount(value).ToString(CultureInfo.InvariantCulture))
                .Append(':')
                .Append(value);
        }
        return sb.ToString();
    }

    // -----------------------------------------------------------------------
    // Replication event canonicalisation, identity and signing.
    // -----------------------------------------------------------------------

    /// <summary>
    /// Canonical header covering every field of an event that binds its identity, excluding
    /// the content hash and signature. Field order is fixed and version prefixed.
    /// </summary>
    public static string EventCanonicalHeader(
        string originDeviceId,
        string logEpoch,
        ulong seq,
        string originAccount,
        long authGeneration,
        string kind,
        string entityId,
        string? conversationId,
        string causalVersion,
        long createdAtUnixMs)
    {
        return Canonical(
            "mesh.rev",
            CanonicalVersion.ToString(CultureInfo.InvariantCulture),
            originDeviceId,
            logEpoch,
            seq.ToString(CultureInfo.InvariantCulture),
            originAccount,
            authGeneration.ToString(CultureInfo.InvariantCulture),
            kind,
            entityId,
            conversationId,
            causalVersion,
            createdAtUnixMs.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>The exact message an origin device signs (header bound to content hash).</summary>
    public static string EventSigningMessage(string canonicalHeader, string contentHash)
        => Canonical("mesh.event-sign", canonicalHeader, contentHash);

    /// <summary>Deterministic event id from the canonical header and content hash.</summary>
    public static string ComputeEventId(string canonicalHeader, string contentHash)
        => HashText(EventSigningMessage(canonicalHeader, contentHash));

    /// <summary>Builds a fully-formed, signed event from its fields and the signer's private key.</summary>
    public static ReplicationEvent CreateEvent(
        string originDeviceId,
        string logEpoch,
        ulong seq,
        string originAccount,
        long authGeneration,
        string kind,
        string entityId,
        string? conversationId,
        string causalVersion,
        long createdAtUnixMs,
        string ciphertext,
        string signerPrivateKeyB64)
    {
        var header = EventCanonicalHeader(
            originDeviceId, logEpoch, seq, originAccount, authGeneration,
            kind, entityId, conversationId, causalVersion, createdAtUnixMs);
        var contentHash = ComputeContentHash(ciphertext);
        var eventId = ComputeEventId(header, contentHash);
        var signature = Sign(signerPrivateKeyB64, EventSigningMessage(header, contentHash));
        return new ReplicationEvent(
            eventId, conversationId, originAccount, originDeviceId, logEpoch, seq,
            authGeneration, kind, entityId, causalVersion, createdAtUnixMs,
            ciphertext, contentHash, signature);
    }

    /// <summary>Recomputes an event's canonical header from the event itself.</summary>
    public static string EventCanonicalHeader(ReplicationEvent e)
        => EventCanonicalHeader(
            e.OriginDeviceId, e.LogEpoch, e.Seq, e.OriginAccount, e.AuthGeneration,
            e.Kind, e.EntityId, e.ConversationId, e.CausalVersion, e.CreatedAtUnixMs);

    /// <summary>True when the event's id and content hash match its fields.</summary>
    public static bool EventIdentityMatches(ReplicationEvent e)
    {
        if (e is null) return false;
        var header = EventCanonicalHeader(e);
        var contentHash = ComputeContentHash(e.Ciphertext);
        return string.Equals(contentHash, e.ContentHash, StringComparison.Ordinal)
            && string.Equals(ComputeEventId(header, contentHash), e.EventId, StringComparison.Ordinal);
    }

    /// <summary>Cryptographically verifies an event's signature against a public key.</summary>
    public static bool VerifyEvent(ReplicationEvent e, string signerPublicKeyB64)
    {
        if (e is null) return false;
        if (!EventIdentityMatches(e)) return false;
        var header = EventCanonicalHeader(e);
        return MeshCrypto.Verify(signerPublicKeyB64, EventSigningMessage(header, e.ContentHash), e.Signature);
    }

    // -----------------------------------------------------------------------
    // Validators.
    // -----------------------------------------------------------------------

    private static bool IsHex(string? value, int length)
    {
        if (value is null || value.Length != length) return false;
        foreach (var c in value)
            if (c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) return false;
        return true;
    }

    private static bool IsSignatureShape(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try
        {
            var bytes = Convert.FromBase64String(value);
            // ECDSA P-256 IEEE-P1363 signatures are 64 bytes; DER encodings are larger.
            return bytes.Length is >= 64 and <= 144;
        }
        catch (FormatException) { return false; }
    }

    /// <summary>
    /// Structural validation of an event: identifiers present, sequence in the safe range,
    /// content hash matches, deterministic id matches and the signature is well shaped.
    /// Does not perform cryptographic verification; use <see cref="VerifyEvent"/> for that.
    /// </summary>
    public static bool ValidateEventShape(ReplicationEvent e, out string error)
    {
        error = "";
        if (e is null) { error = "Event is null."; return false; }
        if (string.IsNullOrWhiteSpace(e.OriginDeviceId)) { error = "OriginDeviceId is required."; return false; }
        if (string.IsNullOrWhiteSpace(e.LogEpoch)) { error = "LogEpoch is required."; return false; }
        if (string.IsNullOrWhiteSpace(e.OriginAccount)) { error = "OriginAccount is required."; return false; }
        if (string.IsNullOrWhiteSpace(e.EntityId)) { error = "EntityId is required."; return false; }
        if (!ReplicationOpKinds.IsKnown(e.Kind)) { error = "Kind is not a known op kind."; return false; }
        if (e.Seq == 0) { error = "Seq must start at 1."; return false; }
        if (e.Seq > long.MaxValue) { error = "Seq exceeds the storable range."; return false; }
        if (e.CreatedAtUnixMs < 0) { error = "CreatedAtUnixMs must be non-negative."; return false; }
        if (e.Ciphertext is null) { error = "Ciphertext is required."; return false; }
        if (Encoding.UTF8.GetByteCount(e.Ciphertext) > OnlineReplicationLimits.MaxBatchBytes)
        { error = "Ciphertext exceeds the per-event size bound."; return false; }
        if (!IsHex(e.ContentHash, OnlineReplicationLimits.HashHexLength)) { error = "ContentHash is malformed."; return false; }
        if (!IsHex(e.EventId, OnlineReplicationLimits.HashHexLength)) { error = "EventId is malformed."; return false; }
        if (!IsSignatureShape(e.Signature)) { error = "Signature is malformed."; return false; }
        if (!EventIdentityMatches(e)) { error = "EventId or ContentHash does not match the event fields."; return false; }
        return true;
    }

    /// <summary>Validates a batch against op-count, size and single-origin invariants.</summary>
    public static bool ValidateBatch(ReplicationBatch batch, out string error)
    {
        error = "";
        if (batch is null) { error = "Batch is null."; return false; }
        if (batch.Events is null || batch.Events.Count == 0) { error = "Batch has no events."; return false; }
        if (batch.Events.Count > OnlineReplicationLimits.MaxBatchOps) { error = "Batch exceeds the op-count limit."; return false; }
        long size = 0;
        foreach (var e in batch.Events)
        {
            if (!ValidateEventShape(e, out error)) return false;
            if (!string.Equals(e.OriginDeviceId, batch.OriginDeviceId, StringComparison.Ordinal))
            { error = "Batch mixes origin devices."; return false; }
            if (!string.Equals(e.LogEpoch, batch.LogEpoch, StringComparison.Ordinal))
            { error = "Batch mixes log epochs."; return false; }
            size += Encoding.UTF8.GetByteCount(e.Ciphertext) + 256;
        }
        if (size > OnlineReplicationLimits.MaxBatchBytes) { error = "Batch exceeds the byte-size limit."; return false; }
        return true;
    }

    /// <summary>Validates a range request against count and ordering bounds.</summary>
    public static bool ValidateRequest(ReplicationRequest request, out string error)
    {
        error = "";
        if (request is null) { error = "Request is null."; return false; }
        if (string.IsNullOrWhiteSpace(request.OriginDeviceId)) { error = "OriginDeviceId is required."; return false; }
        if (string.IsNullOrWhiteSpace(request.LogEpoch)) { error = "LogEpoch is required."; return false; }
        if (request.Ranges is null || request.Ranges.Count == 0) { error = "Request has no ranges."; return false; }
        if (request.Ranges.Count > OnlineReplicationLimits.MaxRangeRequests) { error = "Request exceeds the range-count limit."; return false; }
        ulong prevTo = 0;
        foreach (var r in request.Ranges)
        {
            if (r.FromSeq == 0 || r.ToSeq < r.FromSeq) { error = "Range is malformed."; return false; }
            if (r.ToSeq > long.MaxValue) { error = "Range exceeds the storable range."; return false; }
            if (r.FromSeq <= prevTo) { error = "Ranges must be strictly ascending and disjoint."; return false; }
            prevTo = r.ToSeq;
        }
        return true;
    }

    /// <summary>Validates an offer's ordering and bounds.</summary>
    public static bool ValidateOffer(ReplicationOffer offer, out string error)
    {
        error = "";
        if (offer is null) { error = "Offer is null."; return false; }
        if (string.IsNullOrWhiteSpace(offer.OriginDeviceId)) { error = "OriginDeviceId is required."; return false; }
        if (string.IsNullOrWhiteSpace(offer.LogEpoch)) { error = "LogEpoch is required."; return false; }
        if (offer.AvailableThrough != 0 && offer.AvailableFrom == 0) { error = "AvailableFrom must start at 1."; return false; }
        if (offer.AvailableThrough < offer.AvailableFrom) { error = "AvailableThrough precedes AvailableFrom."; return false; }
        if (offer.AvailableThrough > long.MaxValue) { error = "Offer exceeds the storable range."; return false; }
        return true;
    }

    /// <summary>Validates advertised flow credits and per-batch bounds.</summary>
    public static bool ValidateFlow(ReplicationFlow flow, out string error)
    {
        error = "";
        if (flow is null) { error = "Flow is null."; return false; }
        if (flow.Credits < 0) { error = "Credits must be non-negative."; return false; }
        if (flow.MaxBatchOps is <= 0 or > OnlineReplicationLimits.MaxBatchOps) { error = "MaxBatchOps is out of bounds."; return false; }
        if (flow.MaxBatchBytes is <= 0 or > OnlineReplicationLimits.MaxBatchBytes) { error = "MaxBatchBytes is out of bounds."; return false; }
        return true;
    }

    // -----------------------------------------------------------------------
    // Cursor state machine.
    // -----------------------------------------------------------------------

    /// <summary>A fresh, empty cursor with no epoch bound and no sequences applied.</summary>
    public static ReplicationCursorEntry EmptyCursor()
        => new("", 0, new byte[OnlineReplicationLimits.AheadBitsBytes]);

    private static bool GetBit(byte[] bits, int index)
        => (bits[index >> 3] & (1 << (index & 7))) != 0;

    private static void SetBit(byte[] bits, int index)
        => bits[index >> 3] |= (byte)(1 << (index & 7));

    private static void ShiftDownByOne(byte[] bits)
    {
        // bit[i] <- bit[i+1]; the top bit is cleared. Bit 0 is the byte's low bit.
        for (var i = 0; i < bits.Length; i++)
        {
            var current = (byte)(bits[i] >> 1);
            if (i + 1 < bits.Length && (bits[i + 1] & 1) != 0)
                current |= 0x80;
            bits[i] = current;
        }
    }

    /// <summary>
    /// Applies one sequence to a cursor, returning the outcome and (on acceptance) the
    /// updated cursor. Pure: the input cursor is never mutated. Behaviour:
    /// duplicate (already contiguous or already flagged ahead), contiguous advance with
    /// ahead-bit collapse, in-order within the reorder window as an ahead bit, rejection
    /// beyond the window, and epoch-mismatch rejection.
    /// </summary>
    public static CursorApplyResult ApplyToCursor(
        ReplicationCursorEntry cursor,
        string logEpoch,
        ulong seq,
        out ReplicationCursorEntry updated)
    {
        updated = cursor;
        if (cursor is null || cursor.AheadBits is null
            || cursor.AheadBits.Length != OnlineReplicationLimits.AheadBitsBytes)
            return CursorApplyResult.RejectedInvalid;
        if (seq == 0 || seq > long.MaxValue) return CursorApplyResult.RejectedInvalid;
        if (string.IsNullOrEmpty(logEpoch)) return CursorApplyResult.RejectedInvalid;

        var epochBound = !string.IsNullOrEmpty(cursor.LogEpoch);
        if (epochBound && !string.Equals(cursor.LogEpoch, logEpoch, StringComparison.Ordinal))
            return CursorApplyResult.RejectedEpochMismatch;

        var contiguous = cursor.Contiguous;
        if (seq <= contiguous) return CursorApplyResult.Duplicate;

        var bits = (byte[])cursor.AheadBits.Clone();

        if (seq == contiguous + 1)
        {
            contiguous++;
            ShiftDownByOne(bits);
            while (GetBit(bits, 0))
            {
                contiguous++;
                ShiftDownByOne(bits);
            }
            updated = new ReplicationCursorEntry(logEpoch, contiguous, bits);
            return CursorApplyResult.AppliedContiguous;
        }

        var offset = seq - contiguous - 1;
        if (offset >= (ulong)OnlineReplicationLimits.ReorderWindow)
            return CursorApplyResult.RejectedTooFarAhead;

        var index = (int)offset;
        if (GetBit(bits, index)) return CursorApplyResult.Duplicate;
        SetBit(bits, index);
        updated = new ReplicationCursorEntry(logEpoch, contiguous, bits);
        return CursorApplyResult.AppliedAhead;
    }

    /// <summary>Deterministic hash binding a cursor's epoch, contiguous head and ahead bits.</summary>
    public static string ComputeCursorHash(ReplicationCursorEntry cursor)
        => HashText(Canonical(
            "mesh.cursor",
            cursor.LogEpoch,
            cursor.Contiguous.ToString(CultureInfo.InvariantCulture),
            Convert.ToHexString(cursor.AheadBits).ToLowerInvariant()));

    // -----------------------------------------------------------------------
    // Range planning.
    // -----------------------------------------------------------------------

    /// <summary>
    /// Computes the normalised, bounded set of sequence ranges missing between a cursor's
    /// contiguous head and an offered upper bound. Ranges are ascending, disjoint and
    /// capped at <see cref="OnlineReplicationLimits.MaxRangeRequests"/>.
    /// </summary>
    public static IReadOnlyList<ReplicationRange> ComputeMissingRanges(
        ReplicationCursorEntry cursor,
        ulong offeredThrough)
    {
        var result = new List<ReplicationRange>();
        if (cursor is null) return result;
        var contiguous = cursor.Contiguous;
        if (offeredThrough <= contiguous) return result;

        var window = (ulong)OnlineReplicationLimits.ReorderWindow;
        var windowEnd = contiguous + window;
        var scanEnd = Math.Min(offeredThrough, windowEnd);

        ulong? runStart = null;
        for (var seq = contiguous + 1; seq <= scanEnd; seq++)
        {
            var index = (int)(seq - contiguous - 1);
            var present = GetBit(cursor.AheadBits, index);
            if (!present)
            {
                runStart ??= seq;
            }
            else if (runStart is { } start)
            {
                result.Add(new ReplicationRange(start, seq - 1));
                runStart = null;
                if (result.Count >= OnlineReplicationLimits.MaxRangeRequests) return result;
            }
        }
        if (runStart is { } tailStart)
            result.Add(new ReplicationRange(tailStart, scanEnd));

        if (offeredThrough > windowEnd)
        {
            var beyondStart = windowEnd + 1;
            if (result.Count > 0 && result[^1].ToSeq == windowEnd)
            {
                var last = result[^1];
                result[^1] = new ReplicationRange(last.FromSeq, offeredThrough);
            }
            else
            {
                result.Add(new ReplicationRange(beyondStart, offeredThrough));
            }
        }

        if (result.Count > OnlineReplicationLimits.MaxRangeRequests)
            return result.Take(OnlineReplicationLimits.MaxRangeRequests).ToList();
        return result;
    }

    /// <summary>
    /// Plans replication against an offer. If the offer's earliest available sequence is
    /// past the sequence we still need, the gap cannot be filled incrementally and a full
    /// resync is required.
    /// </summary>
    public static ReplicationRangePlan PlanReplication(ReplicationCursorEntry cursor, ReplicationOffer offer)
    {
        var needFrom = (cursor?.Contiguous ?? 0) + 1;
        if (offer.AvailableThrough < needFrom)
            return new ReplicationRangePlan(Array.Empty<ReplicationRange>(), false);
        if (offer.AvailableFrom > needFrom)
            return new ReplicationRangePlan(Array.Empty<ReplicationRange>(), RequiresResync: true);
        var ranges = ComputeMissingRanges(cursor!, offer.AvailableThrough);
        return new ReplicationRangePlan(ranges, false);
    }

    // -----------------------------------------------------------------------
    // Persistence receipts.
    // -----------------------------------------------------------------------

    /// <summary>Canonical string a receiver signs to acknowledge durable persistence.</summary>
    public static string ReceiptCanonical(
        string receiverDeviceId,
        string originDeviceId,
        string logEpoch,
        ulong throughSeq,
        string cursorHash,
        string batchHash)
    {
        return Canonical(
            "mesh.rcpt",
            CanonicalVersion.ToString(CultureInfo.InvariantCulture),
            receiverDeviceId,
            originDeviceId,
            logEpoch,
            throughSeq.ToString(CultureInfo.InvariantCulture),
            cursorHash,
            batchHash);
    }

    /// <summary>Deterministic hash of a batch's ordered event ids.</summary>
    public static string ComputeBatchHash(ReplicationBatch batch)
    {
        var fields = new List<string?>
        {
            "mesh.batch",
            batch.OriginDeviceId,
            batch.LogEpoch
        };
        foreach (var e in batch.Events)
        {
            fields.Add(e.Seq.ToString(CultureInfo.InvariantCulture));
            fields.Add(e.EventId);
        }
        return HashText(Canonical(fields.ToArray()));
    }

    /// <summary>Builds a signed persistence receipt.</summary>
    public static PersistenceReceipt CreateReceipt(
        string receiverDeviceId,
        string originDeviceId,
        string logEpoch,
        ulong throughSeq,
        string cursorHash,
        string batchHash,
        string receiverPrivateKeyB64)
    {
        var canonical = ReceiptCanonical(receiverDeviceId, originDeviceId, logEpoch, throughSeq, cursorHash, batchHash);
        var signature = Sign(receiverPrivateKeyB64, canonical);
        return new PersistenceReceipt(receiverDeviceId, originDeviceId, logEpoch, throughSeq, cursorHash, batchHash, signature);
    }

    /// <summary>Verifies a persistence receipt signature against the receiver's public key.</summary>
    public static bool VerifyReceipt(PersistenceReceipt receipt, string receiverPublicKeyB64)
    {
        if (receipt is null) return false;
        if (receipt.ThroughSeq == 0 || receipt.ThroughSeq > long.MaxValue) return false;
        if (!IsHex(receipt.CursorHash, OnlineReplicationLimits.HashHexLength)) return false;
        if (!IsHex(receipt.BatchHash, OnlineReplicationLimits.HashHexLength)) return false;
        if (!IsSignatureShape(receipt.Signature)) return false;
        var canonical = ReceiptCanonical(
            receipt.ReceiverDeviceId, receipt.OriginDeviceId, receipt.LogEpoch,
            receipt.ThroughSeq, receipt.CursorHash, receipt.BatchHash);
        return MeshCrypto.Verify(receiverPublicKeyB64, canonical, receipt.Signature);
    }

    // -----------------------------------------------------------------------
    // Session handshake.
    // -----------------------------------------------------------------------

    public static string SessionInitCanonical(ReplicationSessionInit init)
        => Canonical(
            "mesh.sinit",
            CanonicalVersion.ToString(CultureInfo.InvariantCulture),
            init.SessionId,
            init.FromDevice,
            init.ToDevice,
            init.Nonce,
            init.CustodyHead,
            init.AuthGeneration.ToString(CultureInfo.InvariantCulture));

    public static string SessionAckCanonical(ReplicationSessionAck ack)
        => Canonical(
            "mesh.sack",
            CanonicalVersion.ToString(CultureInfo.InvariantCulture),
            ack.SessionId,
            ack.FromDevice,
            ack.ToDevice,
            ack.Nonce,
            ack.PeerNonce,
            ack.CustodyHead,
            ack.AuthGeneration.ToString(CultureInfo.InvariantCulture));

    public static ReplicationSessionInit CreateSessionInit(
        string sessionId, string fromDevice, string toDevice, string nonce,
        string custodyHead, long authGeneration, string signerPrivateKeyB64)
    {
        var draft = new ReplicationSessionInit(sessionId, fromDevice, toDevice, nonce, custodyHead, authGeneration, "");
        return draft with { Signature = Sign(signerPrivateKeyB64, SessionInitCanonical(draft)) };
    }

    public static bool VerifySessionInit(ReplicationSessionInit init, string fromDevicePublicKeyB64)
    {
        if (init is null || string.IsNullOrWhiteSpace(init.SessionId) || string.IsNullOrWhiteSpace(init.Nonce))
            return false;
        if (!IsSignatureShape(init.Signature)) return false;
        return MeshCrypto.Verify(fromDevicePublicKeyB64, SessionInitCanonical(init), init.Signature);
    }

    public static ReplicationSessionAck CreateSessionAck(
        string sessionId, string fromDevice, string toDevice, string nonce, string peerNonce,
        string custodyHead, long authGeneration, string signerPrivateKeyB64)
    {
        var draft = new ReplicationSessionAck(sessionId, fromDevice, toDevice, nonce, peerNonce, custodyHead, authGeneration, "");
        return draft with { Signature = Sign(signerPrivateKeyB64, SessionAckCanonical(draft)) };
    }

    public static bool VerifySessionAck(ReplicationSessionAck ack, string fromDevicePublicKeyB64, string expectedPeerNonce)
    {
        if (ack is null || string.IsNullOrWhiteSpace(ack.SessionId) || string.IsNullOrWhiteSpace(ack.Nonce))
            return false;
        if (!string.Equals(ack.PeerNonce, expectedPeerNonce, StringComparison.Ordinal)) return false;
        if (!IsSignatureShape(ack.Signature)) return false;
        return MeshCrypto.Verify(fromDevicePublicKeyB64, SessionAckCanonical(ack), ack.Signature);
    }

    // -----------------------------------------------------------------------
    // Custody log.
    // -----------------------------------------------------------------------

    /// <summary>Canonical string covering a custody entry's identity, excluding hash and signature.</summary>
    public static string CustodyCanonical(
        string handle,
        long generation,
        string prevHash,
        CustodyAction action,
        string subjectDeviceKey,
        string? recoveryPublicKey,
        long effectiveAtUnixMs,
        string signerKey)
    {
        return Canonical(
            "mesh.cust",
            CanonicalVersion.ToString(CultureInfo.InvariantCulture),
            handle,
            generation.ToString(CultureInfo.InvariantCulture),
            prevHash,
            ((int)action).ToString(CultureInfo.InvariantCulture),
            subjectDeviceKey,
            recoveryPublicKey,
            effectiveAtUnixMs.ToString(CultureInfo.InvariantCulture),
            signerKey);
    }

    public static string CustodyCanonical(CustodyEntry entry)
        => CustodyCanonical(entry.Handle, entry.Generation, entry.PrevHash, entry.Action,
            entry.SubjectDeviceKey, entry.RecoveryPublicKey, entry.EffectiveAtUnixMs, entry.SignerKey);

    public static string ComputeCustodyHash(CustodyEntry entry)
        => HashText(CustodyCanonical(entry));

    /// <summary>Builds a signed custody entry, computing its chained entry hash.</summary>
    public static CustodyEntry CreateCustodyEntry(
        string handle,
        long generation,
        string prevHash,
        CustodyAction action,
        string subjectDeviceKey,
        string? recoveryPublicKey,
        long effectiveAtUnixMs,
        string signerKey,
        string signerPrivateKeyB64)
    {
        var canonical = CustodyCanonical(handle, generation, prevHash, action, subjectDeviceKey, recoveryPublicKey, effectiveAtUnixMs, signerKey);
        var entryHash = HashText(canonical);
        var signature = Sign(signerPrivateKeyB64, canonical);
        return new CustodyEntry(handle, generation, entryHash, prevHash, action, subjectDeviceKey, recoveryPublicKey, effectiveAtUnixMs, signerKey, signature);
    }

    /// <summary>Verifies a custody entry's hash and signature shape (not signer authorisation).</summary>
    public static bool VerifyCustodyEntry(CustodyEntry entry, string signerPublicKeyB64)
    {
        if (entry is null) return false;
        if (!IsSignatureShape(entry.Signature)) return false;
        var canonical = CustodyCanonical(entry);
        if (!string.Equals(HashText(canonical), entry.EntryHash, StringComparison.Ordinal)) return false;
        return MeshCrypto.Verify(signerPublicKeyB64, canonical, entry.Signature);
    }

    /// <summary>
    /// Validates appending <paramref name="next"/> to a chain whose current head is
    /// <paramref name="head"/> (null when the chain is empty). Enforces genesis at
    /// generation 0 with a zero prev hash, strictly incrementing generations with matching
    /// prev-hash links, hash integrity and duplicate/fork rejection.
    /// </summary>
    public static CustodyValidationResult ValidateCustodyAppend(CustodyEntry? head, CustodyEntry next)
    {
        if (next is null) return CustodyValidationResult.BrokenChain;
        if (!IsSignatureShape(next.Signature)) return CustodyValidationResult.InvalidSignatureShape;
        if (!string.Equals(HashText(CustodyCanonical(next)), next.EntryHash, StringComparison.Ordinal))
            return CustodyValidationResult.HashMismatch;

        if (head is null)
        {
            if (next.Generation != 0) return CustodyValidationResult.InvalidGenesis;
            if (next.Action != CustodyAction.Genesis) return CustodyValidationResult.InvalidGenesis;
            if (!string.Equals(next.PrevHash, ZeroHash, StringComparison.Ordinal)) return CustodyValidationResult.InvalidGenesis;
            return CustodyValidationResult.Valid;
        }

        if (next.Generation <= head.Generation) return CustodyValidationResult.DuplicateGeneration;
        if (next.Generation != head.Generation + 1) return CustodyValidationResult.BrokenChain;
        if (next.Action == CustodyAction.Genesis) return CustodyValidationResult.Fork;
        if (!string.Equals(next.PrevHash, head.EntryHash, StringComparison.Ordinal)) return CustodyValidationResult.Fork;
        return CustodyValidationResult.Valid;
    }

    /// <summary>Validates a full custody chain in order, returning the first failure it finds.</summary>
    public static CustodyValidationResult ValidateCustodyChain(IReadOnlyList<CustodyEntry> chain)
    {
        if (chain is null || chain.Count == 0) return CustodyValidationResult.InvalidGenesis;
        CustodyEntry? head = null;
        foreach (var entry in chain)
        {
            var result = ValidateCustodyAppend(head, entry);
            if (result != CustodyValidationResult.Valid) return result;
            head = entry;
        }
        return CustodyValidationResult.Valid;
    }

    /// <summary>
    /// True when two entries at the same generation with different hashes prove a fork.
    /// </summary>
    public static bool IsCustodyFork(CustodyEntry a, CustodyEntry b)
    {
        if (a is null || b is null) return false;
        return a.Generation == b.Generation
            && !string.Equals(a.EntryHash, b.EntryHash, StringComparison.Ordinal);
    }

    /// <summary>The authoritative auth generation for a valid chain (its highest generation).</summary>
    public static long AuthGenerationOf(IReadOnlyList<CustodyEntry> chain)
        => chain is null || chain.Count == 0 ? -1 : chain[^1].Generation;

    /// <summary>
    /// Policy helper: a device may be removed only if it is a member of the current device
    /// set and it is not the sole remaining device (a handle must never remove its last
    /// device, including removing itself when alone).
    /// </summary>
    public static bool CanRemoveDevice(IReadOnlyCollection<string> currentDeviceKeys, string subjectDeviceKey)
    {
        if (currentDeviceKeys is null || string.IsNullOrWhiteSpace(subjectDeviceKey)) return false;
        if (!currentDeviceKeys.Contains(subjectDeviceKey)) return false;
        return currentDeviceKeys.Count > 1;
    }

    // -----------------------------------------------------------------------
    // Signing primitive.
    // -----------------------------------------------------------------------

    /// <summary>Signs a canonical string with an ECDSA P-256 private key (base64 PKCS#8).</summary>
    public static string Sign(string privateKeyB64, string message)
    {
        using var ec = ECDsa.Create();
        ec.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyB64), out _);
        var signature = ec.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA256);
        return Convert.ToBase64String(signature);
    }

    /// <summary>Encoded size, in bytes, of a value serialised for transport sizing checks.</summary>
    public static int EncodedSize<T>(T value)
        => JsonSerializer.SerializeToUtf8Bytes(value, Json).Length;
}
