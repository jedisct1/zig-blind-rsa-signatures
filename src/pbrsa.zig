///! Partially-blind RSA
const std = @import("std");
const assert = std.debug.assert;
const debug = std.debug;
const fmt = std.fmt;
const mem = std.mem;

const ssl = @cImport({
    @cDefine("__FILE__", "\"blind_rsa.zig\"");
    @cDefine("__LINE__", "0");
    @cDefine("OPENSSL_API_COMPAT", "10100");

    @cInclude("openssl/bn.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/rand.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/kdf.h");
});

const IS_BORINGSSL = @hasDecl(ssl, "BORINGSSL_API_VERSION");

const BN_CTX = ssl.BN_CTX;
const BN_MONT_CTX = ssl.BN_MONT_CTX;
const EVP_MD = ssl.EVP_MD;
const EVP_MD_CTX = ssl.EVP_MD_CTX;
const RSA = ssl.RSA;
const BIGNUM = ssl.BIGNUM;
const EVP_PKEY = ssl.EVP_PKEY;
const X509_ALGOR = ssl.X509_ALGOR;
const PKEY_CTX = ssl.EVP_PKEY_CTX;

// Helpers for all the different ways OpenSSL has to return an error.

fn sslTry(ret: c_int) !void {
    if (ret != 1) return error.InternalError;
}

fn sslNegTry(ret: c_int) !void {
    if (ret < 0) return error.InternalError;
}

fn sslNTry(comptime T: type, ret: ?*T) !void {
    if (ret == null) return error.InternalError;
}

fn sslAlloc(comptime T: type, ret: ?*T) !*T {
    return ret orelse error.OutOfMemory;
}

fn sslConstPtr(comptime T: type, ret: ?*const T) !*const T {
    return ret orelse error.InternalError;
}

// Another helper for another way OpenSSL has to return an error
fn bn2binPadded(out: [*c]u8, out_len: usize, in: *const BIGNUM) c_int {
    if (ssl.BN_bn2binpad(in, out, @as(c_int, @intCast(out_len))) == out_len) {
        return 1;
    }
    return 0;
}

fn rsaRef(evp_pkey: *const EVP_PKEY) *RSA {
    return @constCast(ssl.EVP_PKEY_get0_RSA(evp_pkey).?);
}

fn rsaBits(evp_pkey: *const EVP_PKEY) c_int {
    return @intCast(ssl.RSA_bits(rsaRef(evp_pkey)));
}

fn rsaSize(evp_pkey: *const EVP_PKEY) usize {
    return @as(usize, @intCast(ssl.RSA_size(rsaRef(evp_pkey))));
}

fn rsaParam(param: enum { n, e, p, q, d }, evp_pkey: *const EVP_PKEY) *const BIGNUM {
    switch (param) {
        .n => return ssl.RSA_get0_n(rsaRef(evp_pkey)).?,
        .e => return ssl.RSA_get0_e(rsaRef(evp_pkey)).?,
        .p => return ssl.RSA_get0_p(rsaRef(evp_pkey)).?,
        .q => return ssl.RSA_get0_q(rsaRef(evp_pkey)).?,
        .d => return ssl.RSA_get0_d(rsaRef(evp_pkey)).?,
    }
}

fn rsaDup(evp_pkey: *const EVP_PKEY) !*EVP_PKEY {
    var evp_pkey_: ?*EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_dup(@constCast(evp_pkey)));
    return evp_pkey_.?;
}

const HashParams = struct {
    const sha256 = .{ .evp_fn = ssl.EVP_sha256, .salt_length = 32 };
    const sha384 = .{ .evp_fn = ssl.EVP_sha384, .salt_length = 48 };
    const sha512 = .{ .evp_fn = ssl.EVP_sha512, .salt_length = 64 };
};

//

const allow_nonstandard_exponent = true;

fn isSafePrime(p: *const BIGNUM) !bool {
    const q = try sslAlloc(BIGNUM, ssl.BN_dup(p));
    defer ssl.BN_free(q);
    try sslTry(ssl.BN_sub(q, q, ssl.BN_value_one()));
    try sslTry(ssl.BN_rshift1(q, q));
    const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
    ssl.BN_CTX_start(bn_ctx);
    defer {
        ssl.BN_CTX_end(bn_ctx);
        ssl.BN_CTX_free(bn_ctx);
    }
    const ret = ssl.BN_is_prime_ex(q, 20, bn_ctx, null);
    return ret == 1;
}

fn getPhi(bn_ctx: *BN_CTX, p: *const BIGNUM, q: *const BIGNUM) !*BIGNUM {
    const pm1: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
    defer ssl.BN_free(pm1);
    const qm1: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
    defer ssl.BN_free(qm1);
    try sslTry(ssl.BN_sub(pm1, p, ssl.BN_value_one()));
    try sslTry(ssl.BN_sub(qm1, q, ssl.BN_value_one()));

    const phi: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
    errdefer ssl.BN_free(phi);

    try sslTry(ssl.BN_mul(phi, pm1, qm1, bn_ctx));

    return phi;
}

/// Standard blind RSA signatures with a `modulus_bits` modulus size.
/// Recommended for most applications.
pub fn PartiallyBlindRsa(comptime modulus_bits: u16) type {
    return PartiallyBlindRsaCustom(modulus_bits, .sha384, HashParams.sha384.salt_length);
}

/// Blind RSA signatures with a `modulus_bits` modulus size.
/// Non-deterministic padding is recommended for most applications.
pub fn PartiallyBlindRsaDeterministic(comptime modulus_bits: u16) type {
    return PartiallyBlindRsaCustom(modulus_bits, .sha384, 0);
}

/// Blind RSA signatures with custom parameters.
pub fn PartiallyBlindRsaCustom(
    comptime modulus_bits: u16,
    comptime hash_function: enum { sha256, sha384, sha512 },
    comptime salt_length: usize,
) type {
    assert(modulus_bits >= 2048 and modulus_bits <= 4096);
    const Hash = switch (hash_function) {
        .sha256 => HashParams.sha256,
        .sha384 => HashParams.sha384,
        .sha512 => HashParams.sha512,
    };

    return struct {
        const modulus_bytes = (modulus_bits + 7) / 8;

        /// A secret blinding factor
        pub const Secret = [modulus_bytes]u8;

        /// A blind message
        pub const BlindMessage = [modulus_bytes]u8;

        /// A blind signature
        pub const BlindSignature = [modulus_bytes]u8;

        /// A (non-blind) signature
        pub const Signature = [modulus_bytes]u8;

        /// A message randomizer ("noise" added before the message to be signed)
        pub const MessageRandomizer = [32]u8;

        /// The result of a blinding operation
        pub const BlindingResult = struct {
            blind_message: BlindMessage,
            secret: Secret,
            msg_randomizer: ?MessageRandomizer,
        };

        /// An RSA public key
        pub const PublicKey = struct {
            evp_pkey: *EVP_PKEY,
            mont_ctx: *BN_MONT_CTX,

            pub fn deinit(pk: PublicKey) void {
                ssl.EVP_PKEY_free(pk.evp_pkey);
                ssl.BN_MONT_CTX_free(pk.mont_ctx);
            }

            /// Derive a per-metadata public key from a master public key
            pub fn derivePublicKeyForMetadata(pk: PublicKey, metadata: []const u8) !PublicKey {
                const hkdf_input_len = "key".len + metadata.len + 1;
                const hkdf_input_raw: [*c]u8 = @ptrCast(try sslAlloc(anyopaque, ssl.OPENSSL_malloc(hkdf_input_len)));
                defer ssl.OPENSSL_free(hkdf_input_raw);
                var hkdf_input = hkdf_input_raw[0..hkdf_input_len];
                @memcpy(hkdf_input[0.."key".len], "key");
                @memcpy(hkdf_input["key".len..][0..metadata.len], metadata);
                hkdf_input["key".len + metadata.len] = 0;
                var hkdf_salt: [modulus_bytes]u8 = undefined;
                try sslTry(bn2binPadded(&hkdf_salt, hkdf_salt.len, rsaParam(.n, pk.evp_pkey)));

                comptime assert(modulus_bytes % 2 == 0);
                const lambda_len = modulus_bytes / 2;
                const hkdf_len = lambda_len + 16;

                const info = "PBRSA";
                const pkey_ctx: *PKEY_CTX = try sslAlloc(PKEY_CTX, ssl.EVP_PKEY_CTX_new_id(ssl.EVP_PKEY_HKDF, null));
                defer ssl.EVP_PKEY_CTX_free(pkey_ctx);
                try sslNegTry(ssl.EVP_PKEY_derive_init(pkey_ctx));
                try sslNegTry(ssl.EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, Hash.evp_fn().?));
                try sslNegTry(ssl.EVP_PKEY_CTX_set1_hkdf_salt(pkey_ctx, &hkdf_salt, hkdf_salt.len));
                try sslNegTry(ssl.EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx, hkdf_input.ptr, @intCast(hkdf_input.len)));
                try sslNegTry(ssl.EVP_PKEY_CTX_add1_hkdf_info(pkey_ctx, info, info.len));

                var exp_bytes: [hkdf_len]u8 = undefined;

                var exp_bytes_len: usize = @intCast(exp_bytes.len);
                try sslNegTry(ssl.EVP_PKEY_derive(pkey_ctx, &exp_bytes, &exp_bytes_len));

                exp_bytes[0] &= 0x3f;
                exp_bytes[lambda_len - 1] |= 0x01;

                const e2: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(e2);
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&exp_bytes, lambda_len, e2));

                const pk2 = try sslAlloc(RSA, ssl.RSA_new());
                errdefer ssl.RSA_free(pk2);
                const evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                errdefer ssl.EVP_PKEY_free(evp_pkey);
                try sslTry(ssl.EVP_PKEY_assign(evp_pkey, ssl.EVP_PKEY_RSA, pk2));

                const pk2_n = try sslAlloc(BIGNUM, ssl.BN_dup(rsaParam(.n, pk.evp_pkey)));
                errdefer ssl.BN_free(pk2_n);
                try sslTry(ssl.RSA_set0_key(pk2, pk2_n, e2, null));

                const mont_ctx = try sslAlloc(BN_MONT_CTX, ssl.BN_MONT_CTX_new());
                errdefer ssl.BN_MONT_CTX_free(mont_ctx);
                try sslNTry(BN_MONT_CTX, ssl.BN_MONT_CTX_copy(mont_ctx, pk.mont_ctx));

                return PublicKey{ .evp_pkey = evp_pkey, .mont_ctx = mont_ctx };
            }

            /// Import a serialized RSA public key
            pub fn import(raw: []const u8) !PublicKey {
                const max_serialized_pk_length: usize = 1000;

                if (raw.len >= max_serialized_pk_length) {
                    return error.InputTooLarge;
                }
                var evp_pkey_: ?*EVP_PKEY = null;
                var der_ptr: [*c]const u8 = raw.ptr;
                try sslNTry(EVP_PKEY, ssl.d2i_PublicKey(ssl.EVP_PKEY_RSA, &evp_pkey_, &der_ptr, @as(c_long, @intCast(raw.len))));
                const evp_pkey = evp_pkey_.?;
                errdefer ssl.EVP_PKEY_free(evp_pkey);

                if (rsaBits(evp_pkey) != modulus_bits) {
                    return error.UnexpectedModulus;
                }
                const e3: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(e3);
                try sslTry(ssl.BN_set_word(e3, ssl.RSA_3));
                const ef4: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(ef4);
                try sslTry(ssl.BN_set_word(ef4, ssl.RSA_F4));
                if (allow_nonstandard_exponent) {
                    const e_bits = ssl.BN_num_bits(rsaParam(.e, evp_pkey));
                    if (e_bits > modulus_bits / 2) {
                        return error.UnexpectedExponent;
                    }
                } else {
                    if (ssl.BN_cmp(e3, rsaParam(.e, evp_pkey)) != 0 and ssl.BN_cmp(ef4, rsaParam(.e, evp_pkey)) != 0) {
                        return error.UnexpectedExponent;
                    }
                }
                const mont_ctx = try newMontDomain(rsaParam(.n, evp_pkey));
                return PublicKey{ .evp_pkey = evp_pkey, .mont_ctx = mont_ctx };
            }

            pub fn import_der(der: []const u8) !PublicKey {
                const max_serialized_pk_length: usize = 1000;

                if (der.len >= max_serialized_pk_length) {
                    return error.InputTooLarge;
                }
                var x509_pkey: ?*ssl.X509_PUBKEY = null;

                var der_ptr: [*c]const u8 = der.ptr;
                try sslNTry(ssl.X509_PUBKEY, ssl.d2i_X509_PUBKEY(&x509_pkey, &der_ptr, @as(c_long, @intCast(der.len))));
                defer ssl.X509_PUBKEY_free(x509_pkey);

                const evp_pkey: *EVP_PKEY = try sslAlloc(ssl.EVP_PKEY, ssl.X509_PUBKEY_get(x509_pkey));

                if (rsaBits(evp_pkey) != modulus_bits) {
                    return error.UnexpectedModulus;
                }
                const e3: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(e3);
                try sslTry(ssl.BN_set_word(e3, ssl.RSA_3));
                const ef4: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(ef4);
                try sslTry(ssl.BN_set_word(ef4, ssl.RSA_F4));
                if (ssl.BN_cmp(e3, rsaParam(.e, evp_pkey)) != 0 and ssl.BN_cmp(ef4, rsaParam(.e, evp_pkey)) != 0) {
                    return error.UnexpectedExponent;
                }

                const mont_ctx = try newMontDomain(rsaParam(.n, evp_pkey));
                return PublicKey{ .evp_pkey = evp_pkey, .mont_ctx = mont_ctx };
            }

            /// Serialize an RSA public key
            pub fn serialize(pk: PublicKey, serialized: []u8) ![]u8 {
                var serialized_ptr: [*c]u8 = null;
                const len = ssl.i2d_PublicKey(pk.evp_pkey, &serialized_ptr);
                try sslNTry(u8, serialized_ptr);
                defer ssl.OPENSSL_free(serialized_ptr);
                if (len < 0 or len > serialized.len) {
                    return error.Overflow;
                }
                mem.copy(u8, serialized, @as([*]const u8, @ptrCast(serialized_ptr.?))[0..@as(usize, @intCast(len))]);
                return serialized[0..@as(usize, @intCast(len))];
            }

            /// Serialize an RSA public key
            pub fn serialize_der(pk: PublicKey, serialized: []u8) ![]u8 {
                var x509_pkey = ssl.X509_PUBKEY_new();
                try sslTry(ssl.X509_PUBKEY_set(&x509_pkey, pk.evp_pkey));
                defer ssl.X509_PUBKEY_free(x509_pkey);

                var serialized_ptr: [*c]u8 = null;
                const len = ssl.i2d_X509_PUBKEY(x509_pkey, &serialized_ptr);
                try sslNTry(u8, serialized_ptr);
                defer ssl.OPENSSL_free(serialized_ptr);
                if (len < 0 or len > serialized.len) {
                    return error.Overflow;
                }
                mem.copy(u8, serialized, @as([*]const u8, @ptrCast(serialized_ptr.?))[0..@as(usize, @intCast(len))]);
                return serialized[0..@as(usize, @intCast(len))];
            }

            /// Blind a message and return the random blinding secret and the blind message.
            /// randomize_msg can be set to `true` to randomize the message before blinding.
            /// In that case, the message randomizer is returned as BlindingResult.msg_randomizer.
            pub fn blind(pk: PublicKey, msg: []const u8, randomize_msg: bool, metadata: ?[]const u8) !BlindingResult {
                // Compute H(msg)
                const evp_md = Hash.evp_fn().?;
                var msg_hash_buf: [ssl.EVP_MAX_MD_SIZE]u8 = undefined;

                var msg_randomizer: ?MessageRandomizer = null;
                if (randomize_msg) {
                    msg_randomizer = [_]u8{0} ** @sizeOf(MessageRandomizer);
                    try sslTry(ssl.RAND_bytes(&msg_randomizer.?, @as(c_int, @intCast(msg_randomizer.?.len))));
                }
                const msg_hash = try hash(evp_md, &msg_hash_buf, msg_randomizer, msg, metadata);

                // PSS-MGF1 padding
                var padded: [modulus_bytes]u8 = undefined;
                try sslTry(ssl.RSA_padding_add_PKCS1_PSS_mgf1(
                    rsaRef(pk.evp_pkey),
                    &padded,
                    msg_hash.ptr,
                    evp_md,
                    evp_md,
                    salt_length,
                ));
                ssl.OPENSSL_cleanse(msg_hash.ptr, msg_hash.len);

                // Blind the padded message
                const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }
                return _blind(bn_ctx, padded, pk, msg_randomizer);
            }

            /// Compute a signature for the original message
            pub fn finalize(
                pk: PublicKey,
                blind_sig: BlindSignature,
                secret_s: Secret,
                msg_randomizer: ?MessageRandomizer,
                msg: []const u8,
                metadata: ?[]const u8,
            ) !Signature {
                const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }
                const secret: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                const blind_z: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                const z: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));

                try sslNTry(BIGNUM, ssl.BN_bin2bn(&secret_s, secret_s.len, secret));
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&blind_sig, blind_sig.len, blind_z));

                try sslTry(ssl.BN_mod_mul(z, blind_z, secret, rsaParam(.n, pk.evp_pkey), bn_ctx));

                var sig: Signature = undefined;
                try sslTry(bn2binPadded(&sig, sig.len, z));
                try verify(pk, sig, msg_randomizer, msg, metadata);
                return sig;
            }

            /// Verify a (non-blind) signature
            pub fn verify(pk: PublicKey, sig: Signature, msg_randomizer: ?MessageRandomizer, msg: []const u8, metadata: ?[]const u8) !void {
                return rsaSsaPssVerify(pk, sig, msg_randomizer, msg, metadata);
            }

            fn _blind(bn_ctx: *BN_CTX, padded: [modulus_bytes]u8, pk: PublicKey, msg_randomizer: ?MessageRandomizer) !BlindingResult {
                const m: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&padded, padded.len, m));

                // Check that gcd(m, n) == 1
                const gcd: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                try sslTry(ssl.BN_gcd(gcd, m, rsaParam(.n, pk.evp_pkey), bn_ctx));
                if (ssl.BN_is_one(gcd) == 0) {
                    return error.InvalidInput;
                }

                // Compute a blinding factor and its inverse
                const secret_inv: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                const secret: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                while (true) {
                    try sslTry(ssl.BN_rand_range(secret_inv, rsaParam(.n, pk.evp_pkey)));
                    if (!(ssl.BN_is_one(secret_inv) != 0 or ssl.BN_mod_inverse(secret, secret_inv, rsaParam(.n, pk.evp_pkey), bn_ctx) == null)) {
                        break;
                    }
                }

                // Blind the message
                const x: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                const blind_m: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                try sslTry(ssl.BN_mod_exp_mont(x, secret_inv, rsaParam(.e, pk.evp_pkey), rsaParam(.n, pk.evp_pkey), bn_ctx, pk.mont_ctx));
                ssl.BN_clear(secret_inv);
                try sslTry(ssl.BN_mod_mul(blind_m, m, x, rsaParam(.n, pk.evp_pkey), bn_ctx));

                // Serialize the blind message
                var blind_message: BlindMessage = undefined;
                try sslTry(bn2binPadded(&blind_message, blind_message.len, blind_m));

                var secret_s: Secret = undefined;
                try sslTry(bn2binPadded(&secret_s, secret_s.len, secret));

                return BlindingResult{
                    .blind_message = blind_message,
                    .secret = secret_s,
                    .msg_randomizer = msg_randomizer,
                };
            }

            fn rsaSsaPssVerify(pk: PublicKey, sig: Signature, msg_randomizer: ?MessageRandomizer, msg: []const u8, metadata: ?[]const u8) !void {
                const evp_md = Hash.evp_fn().?;
                var msg_hash_buf: [ssl.EVP_MAX_MD_SIZE]u8 = undefined;
                const msg_hash = try hash(evp_md, &msg_hash_buf, msg_randomizer, msg, metadata);
                var em: [modulus_bytes]u8 = undefined;
                try sslNegTry(ssl.RSA_public_decrypt(sig.len, &sig, &em, rsaRef(pk.evp_pkey), ssl.RSA_NO_PADDING));
                try sslTry(ssl.RSA_verify_PKCS1_PSS_mgf1(
                    rsaRef(pk.evp_pkey),
                    msg_hash.ptr,
                    evp_md,
                    evp_md,
                    &em,
                    salt_length,
                ));
            }

            /// Maximum length of a SPKI-encoded public key in bytes
            pub const max_spki_length: usize = 598;

            const spki_tpl = tpl: {
                const SEQ: u8 = 0x30;
                const EXT: u8 = 0x80;
                const CON: u8 = 0xa0;
                const INT: u8 = 0x02;
                const BIT: u8 = 0x03;
                const OBJ: u8 = 0x06;
                break :tpl [72]u8{
                    SEQ, EXT | 2, 0, 0, // container length - offset 2
                    SEQ, 61, // Algorithm sequence
                    OBJ, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, // Signature algorithm (RSASSA-PSS)
                    SEQ,     48, // RSASSA-PSS parameters sequence
                    CON | 0, 2 + 2 + 9,
                    SEQ,     2 + 9,  OBJ, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Hash function - offset 21

                    CON | 1, 2 + 24,
                    SEQ, 24, OBJ, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, // Padding function (MGF1) and parameters
                    SEQ, 2 + 9, OBJ, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, // MGF1 hash function - offset 49
                    CON | 2, 2 + 1, INT, 1, 0, // Salt length - offset 66
                    BIT, EXT | 2, 0, 0, // Public key length - Bit string - offset 69
                    0, // No partial bytes
                };
            };

            /// Return the public key encoded as SPKI.
            /// Output can be up to `max_spki_length` bytes long.
            pub fn serialize_spki(pk: PublicKey, buf: []u8) ![]u8 {
                var raw_ptr: [*c]u8 = null;
                const raw_len = ssl.i2d_PublicKey(pk.evp_pkey, &raw_ptr);
                try sslNTry(u8, raw_ptr);
                var raw = raw_ptr[0..@as(usize, @intCast(raw_len))];
                defer ssl.OPENSSL_free(raw_ptr);
                const container_len = spki_tpl.len - 4 + raw.len;
                const out_len = spki_tpl.len + raw.len;
                if (out_len > buf.len) {
                    return error.Overflow;
                }
                var out = buf[0..out_len];
                mem.copy(u8, out[0..spki_tpl.len], spki_tpl[0..]);
                mem.copy(u8, out[spki_tpl.len..], raw);
                mem.writeInt(u16, out[2..4], @as(u16, @intCast(container_len)), .big);
                out[66] = @as(u8, @intCast(salt_length));
                mem.writeInt(u16, out[69..71], @as(u16, @intCast(1 + raw.len)), .big);

                var algor_mgf1 = try sslAlloc(X509_ALGOR, ssl.X509_ALGOR_new());
                defer ssl.X509_ALGOR_free(algor_mgf1);
                ssl.X509_ALGOR_set_md(algor_mgf1, Hash.evp_fn().?);
                var algor_mgf1_s_ptr: ?*ssl.ASN1_STRING = try sslAlloc(ssl.ASN1_STRING, ssl.ASN1_STRING_new());
                defer ssl.ASN1_STRING_free(algor_mgf1_s_ptr);
                var alg_rptr: *const ssl.ASN1_ITEM = if (IS_BORINGSSL) &ssl.X509_ALGOR_it else ssl.X509_ALGOR_it().?;
                try sslNTry(ssl.ASN1_STRING, ssl.ASN1_item_pack(algor_mgf1, alg_rptr, &algor_mgf1_s_ptr));
                const algor_mgf1_s_len = ssl.ASN1_STRING_length(algor_mgf1_s_ptr);
                const algor_mgf1_s = ssl.ASN1_STRING_get0_data(algor_mgf1_s_ptr)[0..@as(usize, @intCast(algor_mgf1_s_len))];
                var mgf1_s_data: [2 + 2 + 9]u8 = undefined;
                if (algor_mgf1_s_len == mgf1_s_data.len) {
                    mem.copy(u8, &mgf1_s_data, algor_mgf1_s);
                } else {
                    assert(algor_mgf1_s_len == mgf1_s_data.len + 2); // Trailing NUL
                    assert(algor_mgf1_s[1] == mgf1_s_data.len and algor_mgf1_s[3] == 9 and
                        algor_mgf1_s[mgf1_s_data.len] == 5 and algor_mgf1_s[mgf1_s_data.len + 1] == 0);
                    mem.copy(u8, &mgf1_s_data, algor_mgf1_s[0..mgf1_s_data.len]);
                    mgf1_s_data[1] -= 2;
                }
                mem.copy(u8, out[21..][0..mgf1_s_data.len], &mgf1_s_data);
                mem.copy(u8, out[49..][0..mgf1_s_data.len], &mgf1_s_data);
                return out;
            }

            pub fn import_spki(bytes: []const u8) !PublicKey {
                if (bytes.len > max_spki_length + 100) {
                    return error.InputTooLarge;
                }
                if (bytes.len <= spki_tpl.len) {
                    return error.InvalidInput;
                }
                if (!mem.eql(u8, bytes[6..18], spki_tpl[6..18])) {
                    return error.IncompatibleAlgorithm;
                }
                const alg_len: usize = bytes[5];
                if (bytes.len <= alg_len + 11) {
                    return error.InputTooShort;
                }
                return import(bytes[alg_len + 11 ..]);
            }
        };

        /// An RSA secret key
        pub const SecretKey = struct {
            evp_pkey: *EVP_PKEY,

            pub fn deinit(sk: SecretKey) void {
                ssl.EVP_PKEY_free(sk.evp_pkey);
            }

            /// Import an RSA secret key
            pub fn import(der: []const u8) !SecretKey {
                var evp_pkey: ?*EVP_PKEY = null;
                var der_ptr: [*c]const u8 = der.ptr;
                try sslNTry(EVP_PKEY, ssl.d2i_PrivateKey(ssl.EVP_PKEY_RSA, &evp_pkey, &der_ptr, @as(c_long, @intCast(der.len))));
                errdefer ssl.EVP_PKEY_free(evp_pkey);
                if (rsaBits(evp_pkey.?) != modulus_bits) {
                    return error.UnexpectedModulus;
                }
                const p = try sslAlloc(BIGNUM, rsaParam(.p, rsaRef(evp_pkey)));
                const q = try sslAlloc(BIGNUM, rsaParam(.q, rsaRef(evp_pkey)));
                if (!try isSafePrime(p) or !try isSafePrime(q)) {
                    return error.UnsafePrime;
                }
                return SecretKey{ .evp_pkey = evp_pkey.? };
            }

            /// Serialize an RSA secret key
            pub fn serialize(sk: SecretKey, serialized: []u8) ![]u8 {
                var serialized_ptr: [*c]u8 = null;
                const len = ssl.i2d_PrivateKey(sk.evp_pkey, &serialized_ptr);
                try sslNTry(u8, serialized_ptr);
                defer ssl.OPENSSL_free(serialized_ptr);
                if (len < 0 or len > serialized.len) {
                    return error.Overflow;
                }
                mem.copy(u8, serialized, @as([*]const u8, @ptrCast(serialized_ptr.?))[0..@as(usize, @intCast(len))]);
                return serialized[0..@as(usize, @intCast(len))];
            }

            /// Recover the public key
            pub fn publicKey(sk: SecretKey) !PublicKey {
                var serialized: [*c]u8 = null;
                const serialized_len_ = ssl.i2d_PublicKey(sk.evp_pkey, &serialized);
                if (serialized_len_ < 0) {
                    return error.InternalError;
                }
                const serialized_len = @as(usize, @intCast(serialized_len_));
                defer ssl.OPENSSL_clear_free(serialized, serialized_len);
                return PublicKey.import(serialized[0..serialized_len]);
            }

            /// Compute a blind signature
            pub fn blindSign(sk: SecretKey, blind_message: BlindMessage) !BlindSignature {
                const n = rsaParam(.n, sk.evp_pkey);
                var n_s: [blind_message.len]u8 = undefined;
                try sslTry(bn2binPadded(&n_s, n_s.len, n));
                for (blind_message, 0..) |a, i| {
                    const b = n_s[i];
                    if (a < b) break;
                    if (a > b or i + 1 == blind_message.len) return error.NonCanonicalBlindMessage;
                }
                var blind_sig: BlindSignature = undefined;
                try sslNegTry(ssl.RSA_private_encrypt(blind_sig.len, &blind_message, &blind_sig, rsaRef(sk.evp_pkey), ssl.RSA_NO_PADDING));
                return blind_sig;
            }
        };

        /// An RSA key pair
        pub const KeyPair = struct {
            pk: PublicKey,
            sk: SecretKey,

            pub fn deinit(kp: KeyPair) void {
                kp.pk.deinit();
                kp.sk.deinit();
            }

            /// Generate a new key pair
            pub fn generate() !KeyPair {
                const p: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(p);
                const q: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(q);
                const safe = 1;
                while (true) {
                    try sslTry(ssl.BN_generate_prime_ex(
                        p,
                        @as(c_int, @intCast(modulus_bits / 2)),
                        safe,
                        null,
                        null,
                        null,
                    ));
                    try sslTry(ssl.BN_generate_prime_ex(
                        q,
                        @as(c_int, @intCast(modulus_bits / 2)),
                        safe,
                        null,
                        null,
                        null,
                    ));
                    if (ssl.BN_cmp(p, q) != 0) break;
                }

                const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }

                const phi = try getPhi(bn_ctx, p, q);
                defer ssl.BN_free(phi);

                const n: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(n);
                try sslTry(ssl.BN_mul(n, p, q, bn_ctx));

                const e: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(e);
                try sslTry(ssl.BN_set_word(e, ssl.RSA_F4));

                const d: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(d);
                try sslNTry(BIGNUM, ssl.BN_mod_inverse(d, e, phi, null));

                const sk = try sslAlloc(RSA, ssl.RSA_new());
                errdefer ssl.RSA_free(sk);

                try sslTry(ssl.RSA_set0_key(sk, n, e, d));
                try sslTry(ssl.RSA_set0_factors(sk, p, q));
                var evp_pkey: *EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                try sslTry(ssl.EVP_PKEY_assign(evp_pkey, ssl.EVP_PKEY_RSA, sk));
                const sk_ = SecretKey{ .evp_pkey = evp_pkey };
                return KeyPair{ .sk = sk_, .pk = try sk_.publicKey() };
            }

            /// Derive a per-metadata key pair from a master key pair.
            pub fn deriveKeyPairForMetadata(kp: KeyPair, metadata: []const u8) !KeyPair {
                const pk = try kp.pk.derivePublicKeyForMetadata(metadata);

                const e2 = try sslConstPtr(BIGNUM, rsaParam(.e, pk.evp_pkey));
                const p = try sslConstPtr(BIGNUM, rsaParam(.p, kp.sk.evp_pkey));
                const q = try sslConstPtr(BIGNUM, rsaParam(.q, kp.sk.evp_pkey));

                const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }

                const phi = try getPhi(bn_ctx, p, q);
                defer ssl.BN_free(phi);

                const d2 = try sslAlloc(BIGNUM, ssl.BN_new());
                errdefer ssl.BN_free(d2);
                try sslNTry(BIGNUM, ssl.BN_mod_inverse(d2, e2, phi, bn_ctx));

                const e2_ = try sslAlloc(BIGNUM, ssl.BN_dup(e2));
                errdefer ssl.BN_free(e2_);

                const sk_pkey: *EVP_PKEY = try rsaDup(kp.sk.evp_pkey);
                try sslTry(ssl.RSA_set0_key(rsaRef(sk_pkey), null, @constCast(e2), d2));
                const sk = SecretKey{ .evp_pkey = sk_pkey };

                return KeyPair{ .sk = sk, .pk = pk };
            }

            /// Derive a per-metadata secret key from a master key pair.
            pub fn deriveSecretKeyForMetadata(kp: KeyPair, metadata: []const u8) !SecretKey {
                const dkp = try kp.deriveKeyPairForMetadata(metadata);
                dkp.pk.deinit();
                return dkp.sk;
            }
        };

        fn saltLength() usize {
            return salt_length;
        }

        fn hash(evp: *const EVP_MD, h: *[ssl.EVP_MAX_MD_SIZE]u8, prefix: ?MessageRandomizer, msg: []const u8, metadata: ?[]const u8) ![]u8 {
            const len = @as(usize, @intCast(ssl.EVP_MD_size(evp)));
            debug.assert(h.len >= len);
            var hash_ctx = try sslAlloc(EVP_MD_CTX, ssl.EVP_MD_CTX_new());
            try sslTry(ssl.EVP_DigestInit(hash_ctx, evp));
            if (metadata) |ad| {
                try sslTry(ssl.EVP_DigestUpdate(hash_ctx, "msg", 3));
                var metadata_len_bytes: [4]u8 = undefined;
                mem.writeInt(u32, &metadata_len_bytes, @as(u32, @intCast(ad.len)), .big);
                try sslTry(ssl.EVP_DigestUpdate(hash_ctx, &metadata_len_bytes, metadata_len_bytes.len));
                try sslTry(ssl.EVP_DigestUpdate(hash_ctx, ad.ptr, ad.len));
            }
            if (prefix) |p| {
                try sslTry(ssl.EVP_DigestUpdate(hash_ctx, &p, p.len));
            }
            try sslTry(ssl.EVP_DigestUpdate(hash_ctx, msg.ptr, msg.len));
            try sslTry(ssl.EVP_DigestFinal_ex(hash_ctx, h, null));
            return h[0..len];
        }

        fn newMontDomain(n: *const BIGNUM) !*BN_MONT_CTX {
            const mont_ctx = try sslAlloc(BN_MONT_CTX, ssl.BN_MONT_CTX_new());
            errdefer ssl.BN_MONT_CTX_free(mont_ctx);
            const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
            ssl.BN_CTX_start(bn_ctx);
            defer {
                ssl.BN_CTX_end(bn_ctx);
                ssl.BN_CTX_free(bn_ctx);
            }
            try sslTry(ssl.BN_MONT_CTX_set(mont_ctx, n, bn_ctx));
            return mont_ctx;
        }
    };
}

const testing = std.testing;

test "Partially blind RSA signatures" {
    // Generate a new RSA-2048 key
    const kp = try PartiallyBlindRsa(2048).KeyPair.generate();
    defer kp.deinit();

    const metadata = "metadata";

    // Derive a key pair for a specific metadata
    const derived_kp = try kp.deriveKeyPairForMetadata(metadata);
    const derived_pk = derived_kp.pk;
    const derived_sk = derived_kp.sk;

    // Blind a message with the server public key,
    // return the blinding factor and the blind message
    const msg = "msg";
    const blinding_result = try derived_pk.blind(msg, false, metadata);

    // Compute a blind signature
    const blind_sig = try derived_sk.blindSign(blinding_result.blind_message);

    // Compute the signature for the original message
    const sig = try derived_pk.finalize(
        blind_sig,
        blinding_result.secret,
        blinding_result.msg_randomizer,
        msg,
        metadata,
    );

    // Verify the non-blind signature
    try derived_pk.verify(sig, blinding_result.msg_randomizer, msg, metadata);
}

test "Test vector" {
    const tv = .{
        .p = "dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3",
        .q = "f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3",
        .n = "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9",
        .e = "010001",
        .d = "4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d",
    };

    const metadata = "metadata";

    const BRsa = PartiallyBlindRsa(2048);

    var n: ?*BIGNUM = null;
    var e: ?*BIGNUM = null;
    var d: ?*BIGNUM = null;
    var p: ?*BIGNUM = null;
    var q: ?*BIGNUM = null;
    try sslNegTry(ssl.BN_hex2bn(&n, tv.n));
    try sslNegTry(ssl.BN_hex2bn(&e, tv.e));
    try sslNegTry(ssl.BN_hex2bn(&d, tv.d));
    try sslNegTry(ssl.BN_hex2bn(&p, tv.p));
    try sslNegTry(ssl.BN_hex2bn(&q, tv.q));
    const sk_ = try sslAlloc(RSA, ssl.RSA_new());
    try sslTry(ssl.RSA_set0_key(sk_, n, e, d));
    const pk_ = try sslAlloc(RSA, ssl.RSA_new());
    try sslTry(ssl.RSA_set0_key(pk_, n, e, null));
    try sslTry(ssl.RSA_set0_factors(sk_, p, q));

    var sk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    _ = ssl.EVP_PKEY_assign(sk_evp_pkey, ssl.EVP_PKEY_RSA, sk_);
    const sk = BRsa.SecretKey{ .evp_pkey = sk_evp_pkey };
    var pk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    _ = ssl.EVP_PKEY_assign(pk_evp_pkey, ssl.EVP_PKEY_RSA, pk_);
    const pk = BRsa.PublicKey{
        .evp_pkey = pk_evp_pkey,
        .mont_ctx = try BRsa.newMontDomain(ssl.RSA_get0_n(pk_).?),
    };

    const dpk = try pk.derivePublicKeyForMetadata(metadata);

    var buf: [2048 / 8]u8 = undefined;
    var r = try sslConstPtr(BIGNUM, rsaParam(.n, dpk.evp_pkey));
    _ = bn2binPadded(&buf, buf.len, r);

    const kp = PartiallyBlindRsa(2048).KeyPair{
        .pk = pk,
        .sk = sk,
    };
    const dkp = try kp.deriveKeyPairForMetadata(metadata);
    r = try sslConstPtr(BIGNUM, rsaParam(.d, dkp.sk.evp_pkey));
    _ = bn2binPadded(&buf, buf.len, r);

    const expected_d2_hex = "29c25948b214276527434f7d289385098ada0d30866e40eaf56cbe1ffb3ed5881c2df0bd42ea9925d7715fc98767d48e3ee4dae03335e4903fe984c863e1a2f27990fa6999308d7b6515fe0f7da7bb6a979b63f483618b0e2bce2c67daf8dfc099c7f6a0a1292118f35b3133358a200b67f9a0a3c17ceb678095da143d2264327fff5a9fcf280e83421ba398e62965b48628307794e326d57b9f98ce098d88d3e40360e7d5c567fbdce22413e279a7814bc6bab4a5bd35f4bcf3295d68f6d47505fd47aee64f7797f1061342b826db508ba9a62d948c6ee8ec05756267f4a97576d97b773037af601bea110defbd89fb4111c7257b500ad9d1212c849fd355d1";
    var expected_d2: [expected_d2_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_d2, expected_d2_hex);

    try testing.expectEqualSlices(u8, &buf, &expected_d2);
}
