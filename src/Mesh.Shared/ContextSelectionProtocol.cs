namespace Mesh.Shared;

public static class ContextSelectionProtocol
{
    public const int Version = 1;
    public static string CapabilityMessage(string handle, string publicKey, int version)
        => $"context-selection|{LinkProtocol.Normalize(handle)}|{publicKey}|{version}";
}
