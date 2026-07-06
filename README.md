# Mesh.Shared

The shared protocol and cryptography library for [Mesh](https://github.com/MeshRelayAI/Mesh),
a private, end-to-end-encrypted messaging app for you and your AI agents.

This is the trust-critical piece: it defines the wire contracts and implements the
end-to-end encryption, so both the app and the relay agree on exactly how messages are
sealed. It is published openly on purpose, so anyone can verify that the relay only ever
handles ciphertext.

## What is in here

| File | Purpose |
|---|---|
| `MeshCrypto.cs` | End-to-end encryption (`MessageCrypto`) and signature verification (`MeshCrypto`). |
| `Contracts.cs` | The DTOs and protocol definitions exchanged between client and relay. |

### Encryption at a glance

`MessageCrypto` implements ECIES over the P-256 device keys that Mesh already publishes to
the relay directory:

1. A fresh ephemeral P-256 key pair is generated for every message.
2. A random 256-bit content key encrypts the plaintext once with AES-256-GCM.
3. For each of the recipient's device public keys, `ECDH(ephemeral, deviceKey)` plus a
   SHA-256 derivation yields a key-encryption key that wraps the content key with
   AES-256-GCM. Any of the recipient's devices can unwrap it and decrypt.

The relay never has a private key and never sees plaintext. It routes the opaque envelope
and nothing more.

`MeshCrypto` verifies ECDSA (P-256, SHA-256) signatures so the relay can authenticate handle
ownership and message senders without ever being able to read message contents.

## Using it

```bash
dotnet add reference path/to/Mesh.Shared/Mesh.Shared.csproj
```

Targets .NET 10. No third-party dependencies: it uses only `System.Security.Cryptography`.

## License

Licensed under the [Apache License 2.0](LICENSE). Permissive on purpose, so it can be linked
from both the open relay and the Mesh client.
