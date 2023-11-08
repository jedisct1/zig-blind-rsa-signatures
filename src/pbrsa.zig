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
});

const BN_CTX = ssl.BN_CTX;
const BN_MONT_CTX = ssl.BN_MONT_CTX;
const EVP_MD = ssl.EVP_MD;
const EVP_MD_CTX = ssl.EVP_MD_CTX;
const RSA = ssl.RSA;
const BIGNUM = ssl.BIGNUM;
const EVP_PKEY = ssl.EVP_PKEY;
const X509_ALGOR = ssl.X509_ALGOR;

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
    return ssl.RSA_bits(rsaRef(evp_pkey));
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

const HashParams = struct {
    const sha256 = .{ .evp_fn = ssl.EVP_sha256, .salt_length = 32 };
    const sha384 = .{ .evp_fn = ssl.EVP_sha384, .salt_length = 48 };
    const sha512 = .{ .evp_fn = ssl.EVP_sha512, .salt_length = 64 };
};

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
                if (ssl.BN_cmp(e3, rsaParam(.e, evp_pkey)) != 0 and ssl.BN_cmp(ef4, rsaParam(.e, evp_pkey)) != 0) {
                    return error.UnexpectedExponent;
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
                var alg_rptr: *const ssl.ASN1_ITEM = &ssl.X509_ALGOR_it;
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
                const p = try sslAlloc(BIGNUM, ssl.RSA_get0_p(rsaRef(evp_pkey)));
                const q = try sslAlloc(BIGNUM, ssl.RSA_get0_q(rsaRef(evp_pkey)));
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
                const pm1: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(pm1);
                const qm1: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(qm1);
                try sslTry(ssl.BN_sub(pm1, p, ssl.BN_value_one()));
                try sslTry(ssl.BN_sub(qm1, q, ssl.BN_value_one()));
                const phi: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(phi);

                const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }

                try sslTry(ssl.BN_mul(phi, pm1, qm1, bn_ctx));
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

test "Partially RSA blind signatures" {
    // Generate a new RSA-2048 key
    const kp = try PartiallyBlindRsa(2048).KeyPair.generate();
    defer kp.deinit();

    const pk = kp.pk;
    const sk = kp.sk;

    const metadata = "metadata";

    // Blind a message with the server public key,
    // return the blinding factor and the blind message
    const msg = "msg";
    const blinding_result = try pk.blind(msg, false, metadata);

    // Compute a blind signature
    const blind_sig = try sk.blindSign(blinding_result.blind_message);

    // Compute the signature for the original message
    const sig = try pk.finalize(
        blind_sig,
        blinding_result.secret,
        blinding_result.msg_randomizer,
        msg,
        metadata,
    );

    // Verify the non-blind signature
    try pk.verify(sig, blinding_result.msg_randomizer, msg, metadata);
}
