# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This is an implementation of the [RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html) RFC.

Also includes a preliminary implementation of the [Partially Blind RSA Signatures](https://datatracker.ietf.org/doc/draft-amjad-cfrg-partially-blind-rsa/) draft.

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
    // [SERVER]: Generate a RSA-2048 key pair
    const kp = try BlindRsa(2048).KeyPair.generate();
    defer kp.deinit();
    const pk = kp.pk;
    const sk = kp.sk;

    // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
    // The second parameter determines whether noise should be added to the message.
    // `true` adds noise, and returns it as `blinding_result.msg_randomizer`
    // `false` doesn't prefix the message with noise.
    // The client must store the message, the optional noise, and the secret.
    const msg = "msg";
    var blinding_result = try pk.blind(msg, true);

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    // The client secret should not be sent to the server.
    const blind_sig = try sk.blindSign(blinding_result.blind_message);

    // [CLIENT]: later, when the client wants to redeem a signed blind message,
    // using the blinding secret, it can locally compute the signature of the
    // original message.
    // The client then owns a new valid (message, signature) pair, and the
    // server cannot link it to a previous(blinded message, blind signature) pair.
    // Note that the finalization function also verifies that the new signature
    // is correct for the server public key.
    // The noise parameter can be set to `null` if the message wasn't prefixed with noise.
    const sig = try pk.finalize(blind_sig, blinding_result.secret,
                                blinding_result.msg_randomizer, msg);

    // [SERVER]: a non-blind signature can be verified using the server's public key.
    try pk.verify(sig, blinding_result.msg_randomizer, msg);
```

Deterministic padding is also supported with the `BlindRsaDeterministic` type:

```zig
const BRsa = BlindRsaDeterministic(2048);
const kp = BRSA.KeyPair.generate();
...
```

For specific use cases, custom hash functions and salt lengths are also accessible via the `BlindRsaCustom` type.

```zig
const BRsa = BlindRsaCustom(2048, .sha256, 48);
const kp = BRSA.KeyPair.generate();
...
```

Some helper functions are also included for key serialization and deserialization.

## For other languages

* [Rust](https://github.com/jedisct1/rust-blind-rsa-signatures)
* [C](https://github.com/jedisct1/blind-rsa-signatures)
* [Go](https://github.com/cloudflare/circl/tree/master/blindsign)
