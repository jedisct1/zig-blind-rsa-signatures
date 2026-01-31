# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This is an implementation of the [RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html) RFC.

Also implements [Partially Blind RSA Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-partially-blind-rsa/).

## Protocol overview

A client asks a server to sign a message. The server receives the message, and returns the signature.

Using that `(message, signature)` pair, the client can locally compute a second, valid `(message', signature')` pair.

Anyone can verify that `(message', signature')` is valid for the server's public key, even though the server didn't see that pair before.
But no one besides the client can link `(message', signature')` to `(message, signature)`.

Using that scheme, a server can issue a token and verify that a client has a valid token, without being able to link both actions to the same client.

1. The client creates a random message, optionally prefixes it with noise, and blinds it with a random, secret factor.
2. The server receives the blind message, signs it and returns a blind signature.
3. From the blind signature, and knowing the secret factor, the client can locally compute a `(message, signature)` pair that can be verified using the server's public key.
4. Anyone, including the server, can thus later verify that `(message, signature)` is valid, without knowing when step 2 occurred.

The scheme was designed by David Chaum, and was originally implemented for anonymizing DigiCash transactions.

## Dependencies

This implementation requires OpenSSL or BoringSSL.

## Usage

```zig
const BlindRsa = @import("rsa-blind-signatures").brsa.BlindRsa;

// [SERVER]: Generate a RSA-2048 key pair
const kp = try BlindRsa(2048).KeyPair.generate();
defer kp.deinit();
const pk = kp.pk;
const sk = kp.sk;

// [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
// The client must store the message and the blinding result.
const msg = "msg";
const blinding_result = try pk.blind(msg);

// [SERVER]: compute a signature for a blind message, to be sent to the client.
// The client secret should not be sent to the server.
const blind_sig = try sk.blindSign(blinding_result.blind_message);

// [CLIENT]: later, when the client wants to redeem a signed blind message,
// using the blinding secret, it can locally compute the signature of the
// original message.
// The client then owns a new valid (message, signature) pair, and the
// server cannot link it to a previous (blinded message, blind signature) pair.
// Note that the finalization function also verifies that the new signature
// is correct for the server public key.
const sig = try pk.finalize(blind_sig, &blinding_result, msg);

// [SERVER]: a non-blind signature can be verified using the server's public key.
try pk.verify(sig, blinding_result.msg_randomizer, msg);
```

## RFC9474 Variants

The library supports all four variants defined in RFC9474:

```zig
const brsa = @import("rsa-blind-signatures").brsa;

// RSABSSA-SHA384-PSS-Randomized (default, recommended)
const BRsa1 = brsa.BlindRsa(2048);

// RSABSSA-SHA384-PSSZERO-Randomized
const BRsa2 = brsa.BlindRsaPSSZeroRandomized(2048);

// RSABSSA-SHA384-PSS-Deterministic
const BRsa3 = brsa.BlindRsaPSSDeterministic(2048);

// RSABSSA-SHA384-PSSZERO-Deterministic
const BRsa4 = brsa.BlindRsaDeterministic(2048);
```

For specific use cases, custom hash functions and PSS modes are accessible via the `BlindRsaCustom` type:

```zig
const BRsa = brsa.BlindRsaCustom(2048, .sha256, .pss, .randomized);
const kp = try BRsa.KeyPair.generate();
```

## Partially Blind RSA Signatures

Partially blind signatures allow the signer to include public metadata in the signature, which is visible to both parties. This is useful when the server needs to embed information (like an expiration date) that will be part of the final signature.

```zig
const PartiallyBlindRsa = @import("rsa-blind-signatures").pbrsa.PartiallyBlindRsa;

// [SERVER]: Generate a RSA-2048 master key pair
const kp = try PartiallyBlindRsa(2048).KeyPair.generate();
defer kp.deinit();

// Public metadata that will be bound to the signature
const metadata = "metadata";

// [SERVER]: Derive a key pair for the specific metadata
const derived_kp = try kp.deriveKeyPairForMetadata(metadata);
defer derived_kp.deinit();
const derived_pk = derived_kp.pk;
const derived_sk = derived_kp.sk;

// [CLIENT]: Blind a message using the derived public key
const msg = "msg";
const blinding_result = try derived_pk.blind(msg, metadata);

// [SERVER]: Sign the blinded message
const blind_sig = try derived_sk.blindSign(blinding_result.blind_message);

// [CLIENT]: Finalize the signature
const sig = try derived_pk.finalize(blind_sig, &blinding_result, msg, metadata);

// [SERVER]: Verify the signature (metadata is required for verification)
try derived_pk.verify(sig, blinding_result.msg_randomizer, msg, metadata);
```

The same RFC9474 variants are available for partially blind signatures:

```zig
const pbrsa = @import("rsa-blind-signatures").pbrsa;

// RSAPBSSA-SHA384-PSS-Randomized (default, recommended)
const PBRsa1 = pbrsa.PartiallyBlindRsa(2048);

// RSAPBSSA-SHA384-PSSZERO-Randomized
const PBRsa2 = pbrsa.PartiallyBlindRsaPSSZeroRandomized(2048);

// RSAPBSSA-SHA384-PSS-Deterministic
const PBRsa3 = pbrsa.PartiallyBlindRsaPSSDeterministic(2048);

// RSAPBSSA-SHA384-PSSZERO-Deterministic
const PBRsa4 = pbrsa.PartiallyBlindRsaDeterministic(2048);
```

## Serialization

Keys can be serialized and deserialized in multiple formats:

```zig
const BRsa = brsa.BlindRsa(2048);

// Public keys
const pk = kp.pk;
var buf: [1000]u8 = undefined;

// Raw format
const raw = try pk.serialize(&buf);
const pk2 = try BRsa.PublicKey.import(raw);

// DER format
const der = try pk.serialize_der(&buf);
const pk3 = try BRsa.PublicKey.import_der(der);

// SPKI format (SubjectPublicKeyInfo)
const spki = try pk.serialize_spki(&buf);
const pk4 = try BRsa.PublicKey.import_spki(spki);

// Secret keys (DER format)
const sk = kp.sk;
const sk_der = try sk.serialize(&buf);
const sk2 = try BRsa.SecretKey.import(sk_der);
```

## Accessing RSA Components

Raw RSA key components can be accessed for interoperability:

```zig
var buf: [256]u8 = undefined;

// Public key components
const pk_components = pk.components();
const n = try pk_components.n(&buf); // modulus
const e = try pk_components.e(&buf); // public exponent

// Secret key components
const sk_components = sk.components();
const d = try sk_components.d(&buf);    // private exponent
const p = try sk_components.p(&buf);    // first prime factor
const q = try sk_components.q(&buf);    // second prime factor
const dmp1 = try sk_components.dmp1(&buf); // d mod (p-1)
const dmq1 = try sk_components.dmq1(&buf); // d mod (q-1)
const iqmp = try sk_components.iqmp(&buf); // q^(-1) mod p
```

All values are returned as big-endian byte slices.

## For other languages

* [Rust](https://github.com/jedisct1/rust-blind-rsa-signatures)
* [C](https://github.com/jedisct1/blind-rsa-signatures)
* [Go](https://github.com/cloudflare/circl/tree/master/blindsign)
