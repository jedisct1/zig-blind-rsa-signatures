///! Blind RSA
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

const IS_BORINGSSL = @hasDecl(ssl, "BORINGSSL_API_VERSION");

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
    const evp_pkey_: ?*EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    try sslTry(ssl.EVP_PKEY_copy_parameters(evp_pkey_, evp_pkey));
    return evp_pkey_.?;
}

const HashParams = struct {
    const sha256 = .{ .evp_fn = ssl.EVP_sha256, .salt_length = 32 };
    const sha384 = .{ .evp_fn = ssl.EVP_sha384, .salt_length = 48 };
    const sha512 = .{ .evp_fn = ssl.EVP_sha512, .salt_length = 64 };
};

/// Hash function to use
pub const HashFunction = enum { sha256, sha384, sha512 };

/// PSS mode: PSS uses hash-length salt, PSSZero uses no salt
pub const PSSMode = enum { pss, pss_zero };

/// Prepare mode: whether to randomize the message with a prefix
pub const PrepareMode = enum { randomized, deterministic };

/// RSABSSA-SHA384-PSS-Randomized (RFC9474 default)
/// Recommended for most applications.
pub fn BlindRsa(comptime modulus_bits: u16) type {
    return BlindRsaCustom(modulus_bits, .sha384, .pss, .randomized);
}

/// RSABSSA-SHA384-PSSZERO-Randomized
pub fn BlindRsaPSSZeroRandomized(comptime modulus_bits: u16) type {
    return BlindRsaCustom(modulus_bits, .sha384, .pss_zero, .randomized);
}

/// RSABSSA-SHA384-PSS-Deterministic
pub fn BlindRsaPSSDeterministic(comptime modulus_bits: u16) type {
    return BlindRsaCustom(modulus_bits, .sha384, .pss, .deterministic);
}

/// RSABSSA-SHA384-PSSZERO-Deterministic
pub fn BlindRsaDeterministic(comptime modulus_bits: u16) type {
    return BlindRsaCustom(modulus_bits, .sha384, .pss_zero, .deterministic);
}

/// Blind RSA signatures with custom parameters.
pub fn BlindRsaCustom(
    comptime modulus_bits: u16,
    comptime hash_function: HashFunction,
    comptime pss_mode: PSSMode,
    comptime prepare_mode: PrepareMode,
) type {
    assert(modulus_bits >= 2048 and modulus_bits <= 4096);
    const Hash = switch (hash_function) {
        .sha256 => HashParams.sha256,
        .sha384 => HashParams.sha384,
        .sha512 => HashParams.sha512,
    };
    const salt_length: usize = switch (pss_mode) {
        .pss => Hash.salt_length,
        .pss_zero => 0,
    };
    const randomize_message = prepare_mode == .randomized;

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

            /// Serialize an RSA public key
            pub fn serialize(pk: PublicKey, serialized: []u8) ![]u8 {
                var serialized_ptr: [*c]u8 = null;
                const len = ssl.i2d_PublicKey(pk.evp_pkey, &serialized_ptr);
                try sslNTry(u8, serialized_ptr);
                defer ssl.OPENSSL_free(serialized_ptr);
                if (len < 0 or len > serialized.len) {
                    return error.Overflow;
                }
                @memcpy(serialized[0..@intCast(len)], @as([*]const u8, @ptrCast(serialized_ptr.?))[0..@intCast(len)]);
                return serialized[0..@intCast(len)];
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
                @memcpy(serialized[0..@intCast(len)], @as([*]const u8, @ptrCast(serialized_ptr.?))[0..@intCast(len)]);
                return serialized[0..@intCast(len)];
            }

            /// Blind a message and return the random blinding secret and the blind message.
            /// If prepare_mode is .randomized, the message is randomized with a prefix
            /// returned as BlindingResult.msg_randomizer.
            pub fn blind(pk: PublicKey, msg: []const u8) !BlindingResult {
                // Compute H(msg)
                const evp_md = Hash.evp_fn().?;
                var msg_hash_buf: [ssl.EVP_MAX_MD_SIZE]u8 = undefined;

                var msg_randomizer: ?MessageRandomizer = null;
                if (randomize_message) {
                    msg_randomizer = [_]u8{0} ** @sizeOf(MessageRandomizer);
                    try sslTry(ssl.RAND_bytes(&msg_randomizer.?, @as(c_int, @intCast(msg_randomizer.?.len))));
                }
                const msg_hash = try hash(evp_md, &msg_hash_buf, msg_randomizer, msg);

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
            pub fn finalize(pk: PublicKey, blind_sig: BlindSignature, blinding_result: *const BlindingResult, msg: []const u8) !Signature {
                const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }
                const secret: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                const blind_z: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                const z: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));

                try sslNTry(BIGNUM, ssl.BN_bin2bn(&blinding_result.secret, blinding_result.secret.len, secret));
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&blind_sig, blind_sig.len, blind_z));

                try sslTry(ssl.BN_mod_mul(z, blind_z, secret, rsaParam(.n, pk.evp_pkey), bn_ctx));

                var sig: Signature = undefined;
                try sslTry(bn2binPadded(&sig, sig.len, z));
                try verify(pk, sig, blinding_result.msg_randomizer, msg);
                return sig;
            }

            /// Verify a (non-blind) signature
            pub fn verify(pk: PublicKey, sig: Signature, msg_randomizer: ?MessageRandomizer, msg: []const u8) !void {
                return rsaSsaPssVerify(pk, sig, msg_randomizer, msg);
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
                try sslTry(ssl.BN_mod_exp_mont_consttime(x, secret_inv, rsaParam(.e, pk.evp_pkey), rsaParam(.n, pk.evp_pkey), bn_ctx, pk.mont_ctx));
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

            fn rsaSsaPssVerify(pk: PublicKey, sig: Signature, msg_randomizer: ?MessageRandomizer, msg: []const u8) !void {
                const evp_md = Hash.evp_fn().?;
                var msg_hash_buf: [ssl.EVP_MAX_MD_SIZE]u8 = undefined;
                const msg_hash = try hash(evp_md, &msg_hash_buf, msg_randomizer, msg);
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
                const raw = raw_ptr[0..@as(usize, @intCast(raw_len))];
                defer ssl.OPENSSL_free(raw_ptr);
                const container_len = spki_tpl.len - 4 + raw.len;
                const out_len = spki_tpl.len + raw.len;
                if (out_len > buf.len) {
                    return error.Overflow;
                }
                var out = buf[0..out_len];
                @memcpy(out[0..spki_tpl.len], spki_tpl[0..]);
                @memcpy(out[spki_tpl.len..], raw);
                mem.writeInt(u16, out[2..4], @as(u16, @intCast(container_len)), .big);
                out[66] = @as(u8, @intCast(salt_length));
                mem.writeInt(u16, out[69..71], @as(u16, @intCast(1 + raw.len)), .big);

                const algor_mgf1 = try sslAlloc(X509_ALGOR, ssl.X509_ALGOR_new());
                defer ssl.X509_ALGOR_free(algor_mgf1);
                ssl.X509_ALGOR_set_md(algor_mgf1, Hash.evp_fn().?);
                var algor_mgf1_s_ptr: ?*ssl.ASN1_STRING = try sslAlloc(ssl.ASN1_STRING, ssl.ASN1_STRING_new());
                defer ssl.ASN1_STRING_free(algor_mgf1_s_ptr);
                const alg_rptr: *const ssl.ASN1_ITEM = if (IS_BORINGSSL) &ssl.X509_ALGOR_it else ssl.X509_ALGOR_it().?;
                try sslNTry(ssl.ASN1_STRING, ssl.ASN1_item_pack(algor_mgf1, alg_rptr, &algor_mgf1_s_ptr));
                const algor_mgf1_s_len = ssl.ASN1_STRING_length(algor_mgf1_s_ptr);
                const algor_mgf1_s = ssl.ASN1_STRING_get0_data(algor_mgf1_s_ptr)[0..@as(usize, @intCast(algor_mgf1_s_len))];
                var mgf1_s_data: [2 + 2 + 9]u8 = undefined;
                if (algor_mgf1_s_len == mgf1_s_data.len) {
                    @memcpy(&mgf1_s_data, algor_mgf1_s);
                } else {
                    assert(algor_mgf1_s_len == mgf1_s_data.len + 2); // Trailing NUL
                    assert(algor_mgf1_s[1] == mgf1_s_data.len and algor_mgf1_s[3] == 9 and
                        algor_mgf1_s[mgf1_s_data.len] == 5 and algor_mgf1_s[mgf1_s_data.len + 1] == 0);
                    @memcpy(&mgf1_s_data, algor_mgf1_s[0..mgf1_s_data.len]);
                    mgf1_s_data[1] -= 2;
                }
                @memcpy(out[21..][0..mgf1_s_data.len], &mgf1_s_data);
                @memcpy(out[49..][0..mgf1_s_data.len], &mgf1_s_data);
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

            /// Provides access to the raw RSA key components.
            pub const Components = struct {
                evp_pkey: *const EVP_PKEY,

                /// Returns the modulus (n) as big-endian bytes.
                pub fn n(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.n, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns the public exponent (e) as big-endian bytes.
                pub fn e(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.e, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }
            };

            /// Returns an accessor for the raw RSA key components.
            pub fn components(pk: PublicKey) Components {
                return .{ .evp_pkey = pk.evp_pkey };
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
                @memcpy(serialized[0..@intCast(len)], @as([*]const u8, @ptrCast(serialized_ptr.?))[0..@intCast(len)]);
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
                const bn_n = rsaParam(.n, sk.evp_pkey);
                var n_s: [blind_message.len]u8 = undefined;
                try sslTry(bn2binPadded(&n_s, n_s.len, bn_n));
                for (blind_message, 0..) |a, i| {
                    const b = n_s[i];
                    if (a < b) break;
                    if (a > b or i + 1 == blind_message.len) return error.NonCanonicalBlindMessage;
                }
                var blind_sig: BlindSignature = undefined;
                try sslNegTry(ssl.RSA_private_encrypt(blind_sig.len, &blind_message, &blind_sig, rsaRef(sk.evp_pkey), ssl.RSA_NO_PADDING));
                return blind_sig;
            }

            /// Provides access to the raw RSA key components.
            pub const Components = struct {
                evp_pkey: *const EVP_PKEY,

                /// Returns the modulus (n) as big-endian bytes.
                pub fn n(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.n, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns the public exponent (e) as big-endian bytes.
                pub fn e(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.e, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns the private exponent (d) as big-endian bytes.
                pub fn d(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.d, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns the first prime factor (p) as big-endian bytes.
                pub fn p(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.p, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns the second prime factor (q) as big-endian bytes.
                pub fn q(self: Components, out: []u8) ![]u8 {
                    const bn = rsaParam(.q, self.evp_pkey);
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns d mod (p-1) as big-endian bytes.
                /// Returns error.CrtParameterNotSet if not precomputed.
                pub fn dmp1(self: Components, out: []u8) ![]u8 {
                    const bn = ssl.RSA_get0_dmp1(rsaRef(self.evp_pkey)) orelse return error.CrtParameterNotSet;
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns d mod (q-1) as big-endian bytes.
                /// Returns error.CrtParameterNotSet if not precomputed.
                pub fn dmq1(self: Components, out: []u8) ![]u8 {
                    const bn = ssl.RSA_get0_dmq1(rsaRef(self.evp_pkey)) orelse return error.CrtParameterNotSet;
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }

                /// Returns q^(-1) mod p as big-endian bytes.
                /// Returns error.CrtParameterNotSet if not precomputed.
                pub fn iqmp(self: Components, out: []u8) ![]u8 {
                    const bn = ssl.RSA_get0_iqmp(rsaRef(self.evp_pkey)) orelse return error.CrtParameterNotSet;
                    const len: usize = @intCast(ssl.BN_num_bytes(bn));
                    if (out.len < len) return error.OutputTooSmall;
                    _ = ssl.BN_bn2bin(bn, out.ptr);
                    return out[0..len];
                }
            };

            /// Returns an accessor for the raw RSA key components.
            pub fn components(sk: SecretKey) Components {
                return .{ .evp_pkey = sk.evp_pkey };
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
                const sk = try sslAlloc(RSA, ssl.RSA_new());
                errdefer ssl.RSA_free(sk);
                const e: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(e);
                try sslTry(ssl.BN_set_word(e, ssl.RSA_F4));
                try sslTry(ssl.RSA_generate_key_ex(sk, modulus_bits, e, null));
                const evp_pkey: *EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                defer ssl.EVP_PKEY_free(evp_pkey);
                _ = ssl.EVP_PKEY_up_ref(evp_pkey);
                _ = ssl.EVP_PKEY_assign(evp_pkey, ssl.EVP_PKEY_RSA, sk);
                const sk_ = SecretKey{ .evp_pkey = evp_pkey };
                return KeyPair{ .sk = sk_, .pk = try sk_.publicKey() };
            }
        };

        fn saltLength() usize {
            return salt_length;
        }

        fn hash(evp: *const EVP_MD, h: *[ssl.EVP_MAX_MD_SIZE]u8, prefix: ?MessageRandomizer, msg: []const u8) ![]u8 {
            const len = @as(usize, @intCast(ssl.EVP_MD_size(evp)));
            debug.assert(h.len >= len);
            const hash_ctx = try sslAlloc(EVP_MD_CTX, ssl.EVP_MD_CTX_new());
            defer ssl.EVP_MD_CTX_free(hash_ctx);
            try sslTry(ssl.EVP_DigestInit(hash_ctx, evp));
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

test "RSA blind signatures (RSABSSA-SHA384-PSS-Randomized)" {
    // Generate a new RSA-2048 key
    const kp = try BlindRsa(2048).KeyPair.generate();
    defer kp.deinit();

    const pk = kp.pk;
    const sk = kp.sk;

    // Blind a message with the server public key,
    // return the blinding factor and the blind message
    const msg = "msg";
    const blinding_result = try pk.blind(msg);

    // Compute a blind signature
    const blind_sig = try sk.blindSign(blinding_result.blind_message);

    // Compute the signature for the original message
    const sig = try pk.finalize(blind_sig, &blinding_result, msg);

    // Verify the non-blind signature
    try pk.verify(sig, blinding_result.msg_randomizer, msg);
}

test "Deterministic RSA blind signatures (RSABSSA-SHA384-PSSZERO-Deterministic)" {
    // Generate a new RSA-2048 key
    var kp = try BlindRsaDeterministic(2048).KeyPair.generate();
    defer kp.deinit();
    var pk = kp.pk;
    const sk = kp.sk;

    const msg = "msg";
    const blinding_result = try pk.blind(msg);
    const blind_sig = try sk.blindSign(blinding_result.blind_message);
    const sig = try pk.finalize(blind_sig, &blinding_result, msg);
    try pk.verify(sig, blinding_result.msg_randomizer, msg);
}

test "RSA export/import" {
    const kp = try BlindRsaCustom(2048, .sha256, .pss, .randomized).KeyPair.generate();
    defer kp.deinit();

    const pk = kp.pk;
    const sk = kp.sk;

    var buf: [2000]u8 = undefined;

    const serialized_sk = try sk.serialize(&buf);
    const recovered_sk = try BlindRsa(2048).SecretKey.import(serialized_sk);
    const serialized_sk2 = try recovered_sk.serialize(&buf);
    try testing.expectEqualSlices(u8, serialized_sk, serialized_sk2);

    const serialized_pk = try pk.serialize(&buf);
    const recovered_pk = try BlindRsa(2048).PublicKey.import(serialized_pk);
    const serialized_pk2 = try recovered_pk.serialize(&buf);
    try testing.expectEqualSlices(u8, serialized_pk, serialized_pk2);

    const recovered_pk2 = try sk.publicKey();
    const serialized_pk3 = try recovered_pk2.serialize(&buf);
    try testing.expectEqualSlices(u8, serialized_pk, serialized_pk3);
}

test "Test vector (RSABSSA-SHA384-PSS-Deterministic)" {
    const tv = .{
        .p = "e1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc75673488930559c120fd0410194fb8a0da55bd0b81227e843fdca6692ae80e5a5d414116d4803fca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d731684150b63c9a3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba6d6daf108602be26d7071803c67105a5426838e6889d77e8474b29244cefaf418e381b312048b457d73419213063c60ee7b0d81820165864fef93523c9635c22210956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627c42e84a9d3f2774017e32ebca06308a12ecc290c7cd1156dcccfb2311",
        .q = "c601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c806426b60718c05245650821d39445d3ab591ed10a7339f15d83fe13f6a3dfb20b9452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7d367e9b0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa19ecf962daa7916e21afad09eb62fe9f1cf91b77dc879b7974b490d3ebd2e95426057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd347e59f3f32ad9ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae133846304a2936ad7bc7c9803879d2fc4a28e69291d73dbd799f8bc238385",
        .n = "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5",
        .e = "010001",
        .d = "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051",
        .msg = "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d",
        .sig = "6fef8bf9bc182cd8cf7ce45c7dcf0e6f3e518ae48f06f3c670c649ac737a8b8119a34d51641785be151a697ed7825fdfece82865123445eab03eb4bb91cecf4d6951738495f8481151b62de869658573df4e50a95c17c31b52e154ae26a04067d5ecdc1592c287550bb982a5bb9c30fd53a768cee6baabb3d483e9f1e2da954c7f4cf492fe3944d2fe456c1ecaf0840369e33fb4010e6b44bb1d721840513524d8e9a3519f40d1b81ae34fb7a31ee6b7ed641cb16c2ac999004c2191de0201457523f5a4700dd649267d9286f5c1d193f1454c9f868a57816bf5ff76c838a2eeb616a3fc9976f65d4371deecfbab29362caebdff69c635fe5a2113da4d4d8c24f0b16a0584fa05e80e607c5d9a2f765f1f069f8d4da21f27c2a3b5c984b4ab24899bef46c6d9323df4862fe51ce300fca40fb539c3bb7fe2dcc9409e425f2d3b95e70e9c49c5feb6ecc9d43442c33d50003ee936845892fb8be475647da9a080f5bc7f8a716590b3745c2209fe05b17992830ce15f32c7b22cde755c8a2fe50bd814a0434130b807dc1b7218d4e85342d70695a5d7f29306f25623ad1e8aa08ef71b54b8ee447b5f64e73d09bdd6c3b7ca224058d7c67cc7551e9241688ada12d859cb7646fbd3ed8b34312f3b49d69802f0eaa11bc4211c2f7a29cd5c01ed01a39001c5856fab36228f5ee2f2e1110811872fe7c865c42ed59029c706195d52",
        .secret = "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260de57b02d72609c1e0e9f28e2040fc65b6f02d56dbd6aa9af8fde656f70495dfb723ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e445ad96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d9794a008be7ff2529f0ebb69decef646387dc767b74939265fec0223aa6d84d2a8a1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431bd5f2a0d2d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d46a8e1fc2c0c17520af1f4b5e25ba396afc4cd60c494a4c426448b35b49635b337cfb08e7c22a39b256dd032c00adddafb51a627f99a0e1704170ac1f1912e49d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6cd4cbc26f3201dd25c80960a1a111b32947bb78973d269fac7f5186530930ed19f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e04e3584bd7ca054df18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3eadbadf6136eee7a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b8adaad444674f512133ad80b9220e09158521614f1faadfe8505ef57b7df6813048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f",
        .blinded_message = "10c166c6a711e81c46f45b18e5873cc4f494f003180dd7f115585d871a28930259654fe28a54dab319cc5011204c8373b50a57b0fdc7a678bd74c523259dfe4fd5ea9f52f170e19dfa332930ad1609fc8a00902d725cfe50685c95e5b2968c9a2828a21207fcf393d15f849769e2af34ac4259d91dfd98c3a707c509e1af55647efaa31290ddf48e0133b798562af5eabd327270ac2fb6c594734ce339a14ea4fe1b9a2f81c0bc230ca523bda17ff42a377266bc2778a274c0ae5ec5a8cbbe364fcf0d2403f7ee178d77ff28b67a20c7ceec009182dbcaa9bc99b51ebbf13b7d542be337172c6474f2cd3561219fe0dfa3fb207cff89632091ab841cf38d8aa88af6891539f263adb8eac6402c41b6ebd72984e43666e537f5f5fe27b2b5aa114957e9a580730308a5f5a9c63a1eb599f093ab401d0c6003a451931b6d124180305705845060ebba6b0036154fcef3e5e9f9e4b87e8f084542fd1dd67e7782a5585150181c01eb6d90cb95883837384a5b91dbb606f266059ecc51b5acbaa280e45cfd2eec8cc1cdb1b7211c8e14805ba683f9b78824b2eb005bc8a7d7179a36c152cb87c8219e5569bba911bb32a1b923ca83de0e03fb10fba75d85c55907dda5a2606bf918b056c3808ba496a4d95532212040a5f44f37e1097f26dc27b98a51837daa78f23e532156296b64352669c94a8a855acf30533d8e0594ace7c442",
        .blind_sig = "364f6a40dbfbc3bbb257943337eeff791a0f290898a6791283bba581d9eac90a6376a837241f5f73a78a5c6746e1306ba3adab6067c32ff69115734ce014d354e2f259d4cbfb890244fd451a497fe6ecf9aa90d19a2d441162f7eaa7ce3fc4e89fd4e76b7ae585be2a2c0fd6fb246b8ac8d58bcb585634e30c9168a434786fe5e0b74bfe8187b47ac091aa571ffea0a864cb906d0e28c77a00e8cd8f6aba4317a8cc7bf32ce566bd1ef80c64de041728abe087bee6cadd0b7062bde5ceef308a23bd1ccc154fd0c3a26110df6193464fc0d24ee189aea8979d722170ba945fdcce9b1b4b63349980f3a92dc2e5418c54d38a862916926b3f9ca270a8cf40dfb9772bfbdd9a3e0e0892369c18249211ba857f35963d0e05d8da98f1aa0c6bba58f47487b8f663e395091275f82941830b050b260e4767ce2fa903e75ff8970c98bfb3a08d6db91ab1746c86420ee2e909bf681cac173697135983c3594b2def673736220452fde4ddec867d40ff42dd3da36c84e3e52508b891a00f50b4f62d112edb3b6b6cc3dbd546ba10f36b03f06c0d82aeec3b25e127af545fac28e1613a0517a6095ad18a98ab79f68801e05c175e15bae21f821e80c80ab4fdec6fb34ca315e194502b8f3dcf7892b511aee45060e3994cd15e003861bc7220a2babd7b40eda03382548a34a7110f9b1779bf3ef6011361611e6bc5c0dc851e1509de1a",
    };

    // PSS with deterministic message (salt_length=48, no msg_randomizer)
    const BRsa = BlindRsaPSSDeterministic(4096);

    var n: ?*BIGNUM = null;
    var e: ?*BIGNUM = null;
    var d: ?*BIGNUM = null;
    try sslNegTry(ssl.BN_hex2bn(&n, tv.n));
    errdefer ssl.BN_free(n);
    try sslNegTry(ssl.BN_hex2bn(&e, tv.e));
    errdefer ssl.BN_free(e);
    try sslNegTry(ssl.BN_hex2bn(&d, tv.d));
    errdefer ssl.BN_free(d);
    const sk_ = try sslAlloc(RSA, ssl.RSA_new());
    errdefer ssl.RSA_free(sk_);
    const pk_ = try sslAlloc(RSA, ssl.RSA_new());
    errdefer ssl.RSA_free(pk_);
    var n_: ?*BIGNUM = try sslAlloc(BIGNUM, ssl.BN_dup(n));
    errdefer ssl.BN_free(n_);
    var e_: ?*BIGNUM = try sslAlloc(BIGNUM, ssl.BN_dup(e));
    errdefer ssl.BN_free(e_);
    try sslTry(ssl.RSA_set0_key(sk_, n, e, d));
    n = null;
    e = null;
    d = null;
    try sslTry(ssl.RSA_set0_key(pk_, n_, e_, null));
    n_ = null;
    e_ = null;
    var msg: [tv.msg.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&msg, tv.msg);
    var secret: BRsa.Secret = undefined;
    _ = try fmt.hexToBytes(&secret, tv.secret);
    var blind_sig: BRsa.BlindSignature = undefined;
    _ = try fmt.hexToBytes(&blind_sig, tv.blind_sig);
    var blinded_message: [tv.blinded_message.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&blinded_message, tv.blinded_message);

    const sk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    defer ssl.EVP_PKEY_free(sk_evp_pkey);
    _ = ssl.EVP_PKEY_up_ref(sk_evp_pkey);
    _ = ssl.EVP_PKEY_assign(sk_evp_pkey, ssl.EVP_PKEY_RSA, sk_);
    const sk = BRsa.SecretKey{ .evp_pkey = sk_evp_pkey };
    const pk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    defer ssl.EVP_PKEY_free(pk_evp_pkey);
    _ = ssl.EVP_PKEY_up_ref(pk_evp_pkey);
    _ = ssl.EVP_PKEY_assign(pk_evp_pkey, ssl.EVP_PKEY_RSA, pk_);
    const pk = BRsa.PublicKey{
        .evp_pkey = pk_evp_pkey,
        .mont_ctx = try BRsa.newMontDomain(ssl.RSA_get0_n(pk_).?),
    };

    const blinding_result = BRsa.BlindingResult{
        .blind_message = blinded_message,
        .secret = secret,
        .msg_randomizer = null,
    };
    const sig = try pk.finalize(blind_sig, &blinding_result, &msg);
    try pk.verify(sig, blinding_result.msg_randomizer, &msg);

    const computed_blind_sig = try sk.blindSign(blinded_message);
    try testing.expectEqualSlices(u8, computed_blind_sig[0..], blind_sig[0..]);
}

test "SPKI import/export" {
    const modulus_bits = 2048;
    const BRsa = BlindRsa(modulus_bits);
    const kp = try BRsa.KeyPair.generate();
    defer kp.deinit();
    const pk = kp.pk;
    const sk = kp.sk;

    const msg = "This is just a test vector";
    const blinding_result = try pk.blind(msg);

    const blind_sig = try sk.blindSign(blinding_result.blind_message);
    const sig = try pk.finalize(blind_sig, &blinding_result, msg);
    try pk.verify(sig, blinding_result.msg_randomizer, msg);

    var spki_buf: [BRsa.PublicKey.max_spki_length]u8 = undefined;
    const spki = try pk.serialize_spki(&spki_buf);

    const pk2 = try BRsa.PublicKey.import_spki(spki);
    defer pk2.deinit();
    const spki2 = try pk2.serialize_spki(&spki_buf);
    try testing.expectEqualSlices(u8, spki, spki2);
}

test "import/export" {
    const modulus_bits = 2048;
    const BRsa = BlindRsa(modulus_bits);

    var kp = try BRsa.KeyPair.generate();
    defer kp.deinit();

    var buf: [1024]u8 = undefined;

    const der = try kp.pk.serialize_der(&buf);
    _ = try BRsa.PublicKey.import_der(der);

    const pem = try kp.pk.serialize(&buf);
    _ = try BRsa.PublicKey.import(pem);
}

fn testRfc9474Vector(
    comptime BRsa: type,
    comptime tv_n: []const u8,
    comptime tv_e: []const u8,
    comptime tv_d: []const u8,
    comptime tv_msg: []const u8,
    comptime tv_msg_prefix: []const u8,
    comptime tv_secret: []const u8,
    comptime tv_blinded_message: []const u8,
    comptime tv_blind_sig: []const u8,
    comptime tv_sig: []const u8,
) !void {
    var n: ?*BIGNUM = null;
    var e: ?*BIGNUM = null;
    var d: ?*BIGNUM = null;
    try sslNegTry(ssl.BN_hex2bn(&n, tv_n.ptr));
    errdefer ssl.BN_free(n);
    try sslNegTry(ssl.BN_hex2bn(&e, tv_e.ptr));
    errdefer ssl.BN_free(e);
    try sslNegTry(ssl.BN_hex2bn(&d, tv_d.ptr));
    errdefer ssl.BN_free(d);

    const sk_ = try sslAlloc(RSA, ssl.RSA_new());
    errdefer ssl.RSA_free(sk_);
    const pk_ = try sslAlloc(RSA, ssl.RSA_new());
    errdefer ssl.RSA_free(pk_);

    var n_: ?*BIGNUM = try sslAlloc(BIGNUM, ssl.BN_dup(n));
    errdefer ssl.BN_free(n_);
    var e_: ?*BIGNUM = try sslAlloc(BIGNUM, ssl.BN_dup(e));
    errdefer ssl.BN_free(e_);

    try sslTry(ssl.RSA_set0_key(sk_, n, e, d));
    n = null;
    e = null;
    d = null;
    try sslTry(ssl.RSA_set0_key(pk_, n_, e_, null));
    n_ = null;
    e_ = null;

    var msg: [tv_msg.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&msg, tv_msg);
    var secret: BRsa.Secret = undefined;
    _ = try fmt.hexToBytes(&secret, tv_secret);
    var blind_sig: BRsa.BlindSignature = undefined;
    _ = try fmt.hexToBytes(&blind_sig, tv_blind_sig);
    var blinded_message: BRsa.BlindMessage = undefined;
    _ = try fmt.hexToBytes(&blinded_message, tv_blinded_message);
    var expected_sig: BRsa.Signature = undefined;
    _ = try fmt.hexToBytes(&expected_sig, tv_sig);

    var msg_randomizer: ?BRsa.MessageRandomizer = null;
    if (tv_msg_prefix.len > 0) {
        msg_randomizer = [_]u8{0} ** @sizeOf(BRsa.MessageRandomizer);
        _ = try fmt.hexToBytes(&msg_randomizer.?, tv_msg_prefix);
    }

    const sk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    defer ssl.EVP_PKEY_free(sk_evp_pkey);
    _ = ssl.EVP_PKEY_up_ref(sk_evp_pkey);
    _ = ssl.EVP_PKEY_assign(sk_evp_pkey, ssl.EVP_PKEY_RSA, sk_);
    const sk = BRsa.SecretKey{ .evp_pkey = sk_evp_pkey };

    const pk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    defer ssl.EVP_PKEY_free(pk_evp_pkey);
    _ = ssl.EVP_PKEY_up_ref(pk_evp_pkey);
    _ = ssl.EVP_PKEY_assign(pk_evp_pkey, ssl.EVP_PKEY_RSA, pk_);
    const pk = BRsa.PublicKey{
        .evp_pkey = pk_evp_pkey,
        .mont_ctx = try BRsa.newMontDomain(ssl.RSA_get0_n(pk_).?),
    };

    const blinding_result = BRsa.BlindingResult{
        .blind_message = blinded_message,
        .secret = secret,
        .msg_randomizer = msg_randomizer,
    };

    const sig = try pk.finalize(blind_sig, &blinding_result, &msg);
    try testing.expectEqualSlices(u8, &sig, &expected_sig);
    try pk.verify(sig, msg_randomizer, &msg);

    const computed_blind_sig = try sk.blindSign(blinded_message);
    try testing.expectEqualSlices(u8, &computed_blind_sig, &blind_sig);
}

test "RFC9474: RSABSSA-SHA384-PSS-Randomized" {
    const BRsa = BlindRsa(4096);
    try testRfc9474Vector(
        BRsa,
        "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5",
        "010001",
        "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051",
        "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d",
        "8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b",
        "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260de57b02d72609c1e0e9f28e2040fc65b6f02d56dbd6aa9af8fde656f70495dfb723ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e445ad96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d9794a008be7ff2529f0ebb69decef646387dc767b74939265fec0223aa6d84d2a8a1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431bd5f2a0d2d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d46a8e1fc2c0c17520af1f4b5e25ba396afc4cd60c494a4c426448b35b49635b337cfb08e7c22a39b256dd032c00adddafb51a627f99a0e1704170ac1f1912e49d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6cd4cbc26f3201dd25c80960a1a111b32947bb78973d269fac7f5186530930ed19f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e04e3584bd7ca054df18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3eadbadf6136eee7a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b8adaad444674f512133ad80b9220e09158521614f1faadfe8505ef57b7df6813048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f",
        "aa3ee045138d874669685ffaef962c7694a9450aa9b4fd6465db9b3b75a522bb921c4c0fdcdfae9667593255099cff51f5d3fd65e8ffb9d3b3036252a6b51b6edfb3f40382b2bbf34c0055e4cbcc422850e586d84f190cd449af11dc65545f5fe26fd89796eb87da4bda0c545f397cddfeeb56f06e28135ec74fd477949e7677f6f36cfae8fd5c1c5898b03b9c244cf6d1a4fb7ad1cb43aff5e80cb462fac541e72f67f0a50f1843d1759edfaae92d1a916d3f0efaf4d650db416c3bf8abdb5414a78cebc97de676723cb119e77aea489f2bbf530c440ebc5a75dccd3ebf5a412a5f346badd61bee588e5917bdcce9dc33c882e39826951b0b8276c6203971947072b726e935816056ff5cb11a71ca2946478584126bb877acdf87255f26e6cca4e0878801307485d3b7bb89b289551a8b65a7a6b93db010423d1406e149c87731910306e5e410b41d4da3234624e74f92845183e323cf7eb244f212a695f8856c675fbc3a021ce649e22c6f0d053a9d238841cf3afdc2739f99672a419ae13c17f1f8a3bc302ec2e7b98e8c353898b7150ad8877ec841ea6e4b288064c254fefd0d049c3ad196bf7ffa535e74585d0120ce728036ed500942fbd5e6332c298f1ffebe9ff60c1e117b274cf0cb9d70c36ee4891528996ec1ed0b178e9f3c0c0e6120885f39e8ccaadbb20f3196378c07b1ff22d10049d3039a7a92fe7efdd95d",
        "3f4a79eacd4445fca628a310d41e12fcd813c4d43aa4ef2b81226953248d6d00adfee6b79cb88bfa1f99270369fd063c023e5ed546719b0b2d143dd1bca46b0e0e615fe5c63d95c5a6b873b8b50bc52487354e69c3dfbf416e7aca18d5842c89b676efdd38087008fa5a810161fcdec26f20ccf2f1e6ab0f9d2bb93e051cb9e86a9b28c5bb62fd5f5391379f887c0f706a08bcc3b9e7506aaf02485d688198f5e22eefdf837b2dd919320b17482c5cc54271b4ccb41d267629b3f844fd63750b01f5276c79e33718bb561a152acb2eb36d8be75bce05c9d1b94eb609106f38226fb2e0f5cd5c5c39c59dda166862de498b8d92f6bcb41af433d65a2ac23da87f39764cb64e79e74a8f4ce4dd567480d967cefac46b6e9c06434c3715635834357edd2ce6f105eea854ac126ccfa3de2aac5607565a4e5efaac5eed491c335f6fc97e6eb7e9cea3e12de38dfb315220c0a3f84536abb2fdd722813e083feda010391ac3d8fd1cd9212b5d94e634e69ebcc800c4d5c4c1091c64afc37acf563c7fc0a6e4c082bc55544f50a7971f3fb97d5853d72c3af34ffd5ce123998be5360d1059820c66a81e1ee6d9c1803b5b62af6bc877526df255b6d1d835d8c840bebbcd6cc0ee910f17da37caf8488afbc08397a1941fcc79e76a5888a95b3d5405e13f737bea5c78d716a48eb9dc0aec8de39c4b45c6914ad4a8185969f70b1adf46",
        "191e941c57510e22d29afad257de5ca436d2316221fe870c7cb75205a6c071c2735aed0bc24c37f3d5bd960ab97a829a508f966bbaed7a82645e65eadaf24ab5e6d9421392c5b15b7f9b640d34fec512846a3100b80f75ef51064602118c1a77d28d938f6efc22041d60159a518d3de7c4d840c9c68109672d743d299d8d2577ef60c19ab463c716b3fa75fa56f5735349d414a44df12bf0dd44aa3e10822a651ed4cb0eb6f47c9bd0ef14a034a7ac2451e30434d513eb22e68b7587a8de9b4e63a059d05c8b22c7c51e2cfee2d8bef511412e93c859a13726d87c57d1bc4c2e68ab121562f839c3a3d233e87ed63c69b7e57525367753fbebcc2a9805a2802659f5888b2c69115bf865559f10d906c09d048a0d71bfee4b33857393ec2b69e451433496d02c9a7910abb954317720bbde9e69108eafc3e90bad3d5ca4066d7b1e49013fa04e948104a1dd82b12509ecb146e948c54bd8bfb5e6d18127cd1f7a93c3cf9f2d869d5a78878c03fe808a0d799e910be6f26d18db61c485b303631d3568368fc41986d08a95ea6ac0592240c19d7b22416b9c82ae6241e211dd5610d0baaa9823158f9c32b66318f5529491b7eeadcaa71898a63bac9d95f4aa548d5e97568d744fc429104e32edd9c87519892a198a30d333d427739ffb9607b092e910ae37771abf2adb9f63bc058bf58062ad456cb934679795bbdfcdfad5e0f2",
    );
}

test "RFC9474: RSABSSA-SHA384-PSSZERO-Randomized" {
    const BRsa = BlindRsaPSSZeroRandomized(4096);
    try testRfc9474Vector(
        BRsa,
        "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5",
        "010001",
        "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051",
        "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d",
        "84ea86c8cf3beedfed73beceabd792027c609d1100bf041fdd60d826a718130d",
        "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260de57b02d72609c1e0e9f28e2040fc65b6f02d56dbd6aa9af8fde656f70495dfb723ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e445ad96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d9794a008be7ff2529f0ebb69decef646387dc767b74939265fec0223aa6d84d2a8a1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431bd5f2a0d2d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d46a8e1fc2c0c17520af1f4b5e25ba396afc4cd60c494a4c426448b35b49635b337cfb08e7c22a39b256dd032c00adddafb51a627f99a0e1704170ac1f1912e49d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6cd4cbc26f3201dd25c80960a1a111b32947bb78973d269fac7f5186530930ed19f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e04e3584bd7ca054df18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3eadbadf6136eee7a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b8adaad444674f512133ad80b9220e09158521614f1faadfe8505ef57b7df6813048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f",
        "4c1b82d9b97b968b2ce0754e326abd49e3d723ed937d84bead34b6a834483b43d510bf62ca47683ed366d94d3d357b270a85cf2cc2ddd171141b45d7549d5373cf67d14f6f462c14ebded906793144faba37f129c0f3172854ec0f854e555552eec5a30c87788f1039814594f04348709e26a883be82affff207b1886b75c037f43f847f45d89bcbf210c22ffcdf8118ce8a526b3723e6209c26319f8f5d2adcf0b637031c9fdf53470a915c587e30287ba88ed4f1cd5e93cf3d4990acf31fffdbfddec80ae0b728d5b4c612a396fd81acaa65566a4dc1c24624f44fd10cdba05f3d0bed2e69bb0d13d41a9f1b4e67aa566520778733ced5e6260f4d1982f63bb835442acffe3cb87f5f8ec6bb84226e0eab787159d08e57604b13557ceea97f2c4ad0631accf898f302df86f0b64354ec0b3bdf1b4e2a4deb4d38f655ea8d80de4cc19aa06ffcd56e348faf894c8774c53235ddcc152d80cf66b417eee4d182781bab8c979937a3c7502d8f39c57c4f09884de5a7247f2539910a96e4b15f9a3df88edc21a13030af357467a99dca50dba4afe4a6185a240ac8f1d8aab2e83443025f94e1af930f56f78661369cc6790701f31b83aec40f96a72c7f7ba13b4ebdd8e24e7351f4ffba0a7c072cb28f13aff06cd02368491044fcc536213b2e3b1cf6ca81cf2097b7b19d2b36bd246f390f53768f1c2e56113ea91b33c7cfa647",
        "4894f64d7214c216282d9842cbf7e7cccd9c0dcb1f4294a6bdeccd4c4c2446160d7cac7892f01b70dfa69f533891d2fbb447f7cf7541d1b504a2d46fc1bb6de26b345972aada8ebce280b906f3a10a13208f77ef896fbe6bc4504327fd4c5c8f03211d45ae9672e9f4be0f4900762ba2a7177a58b90d6dd1263faf2b7a5f15d50a7b00e733742c1b6a1ea4eb5fbfb407abf14496ab26b50cf1a5a56dea616b7a6a5595777400571a751c682b9fdd6badb3f72292f314f4ba2ba0f394f91676a4bb12e60ea08c977f7082be6357c1ca82fe3301fe5fb4128609bee2410db0481aea3a5737fb0bce9381272c2202644f662e99f64bf1190d66e230cc0371ec33fe32fe725dfd872041914d39462a909414a780c9aab394af443199eba56c83986d22d57d4421b41ff8e5bec537d271223adb34d26c64989048a88d8f352a06a7cc153e216a6bed9548bb38d2a1600b2f3403289df6df74aec525ef9e413b7140a7c1a914dedd74a336f1beed39a8e5e2cef76cac094df0dbb3fa55d4b7ee781c74bed3bd8bc7aa6ef3f1dbfa4674945720ec93dafa6d0650229ab75e3fae687327fac081cf4bb376e02a2b73314c54c12f88572c28980f13aba5731bc5a3a60575ea116c8ea2fe5009168deb1255026c9310783ff7f644255d3e1691e194db1babd7780b9a5dc0cb3de2b700d12f49cbe4db51ca2f3c8a58b09e854cc71e8070ab",
        "195363ba25e4bf763f6538c86865785f93f4ea6092da3ad200d41b99eb0eb0869fa792df619fd8fa5923d5d03d5882faae6d25054118deef5e4a6a252dd5afb0dac262b74c391090b1575fbafd959d26bc294f47fb45a2c1c209932c4f94b24394eded91fbdd015e1a85dde63c9e77a0283f812cad1192d86432c51331e46fd4f3771bbafb929f847a19cb05e5f79b6b519d67e8f005951e53656be97cb612d2f506618b366403b34648451d6fbc7318c2f3f583cc6fa17bf2108398f9284e0602187904406a9322f1e7b8016ca9ad11b835756df862c465c420535e25faa48bf341f7ee8192be47fa875791f32f56d5e631d237060688f052426dee5b0b2b74ca5f830e82a453379eedb541fa4fcdaa19dae6509401e3cdd4c40f5c9243db3f6d7115c4e8cd6db8290723ab01d9d0d7e355a97a01547800e43f11736668c3f8908848d759c33a67a2f506abc3f6871cbe625b1bc71eb06d785a59501396712c581a60d6ccc450d2f4eb4cf08ae0dbfa45c2860425be90cc4cd4c989495bbd2963e19c59ae5d90d1ca884e80d654b5f2cd6a80c3588b514ee91c802736f594c340397b316a97e9c70b0609955b6c3ee06f4760d9377f0797a0411a244db395bb8b711ef79fbcb5589226174029be79a72dcd6f4ca566b7b1b9a27e43b5c02a9a579d60bdda183398d66d76e0e8eceb1af2f27633589d043bcdc041683b31f7f1",
    );
}

test "RFC9474: RSABSSA-SHA384-PSS-Deterministic" {
    const BRsa = BlindRsaPSSDeterministic(4096);
    try testRfc9474Vector(
        BRsa,
        "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5",
        "010001",
        "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051",
        "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d",
        "",
        "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260de57b02d72609c1e0e9f28e2040fc65b6f02d56dbd6aa9af8fde656f70495dfb723ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e445ad96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d9794a008be7ff2529f0ebb69decef646387dc767b74939265fec0223aa6d84d2a8a1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431bd5f2a0d2d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d46a8e1fc2c0c17520af1f4b5e25ba396afc4cd60c494a4c426448b35b49635b337cfb08e7c22a39b256dd032c00adddafb51a627f99a0e1704170ac1f1912e49d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6cd4cbc26f3201dd25c80960a1a111b32947bb78973d269fac7f5186530930ed19f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e04e3584bd7ca054df18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3eadbadf6136eee7a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b8adaad444674f512133ad80b9220e09158521614f1faadfe8505ef57b7df6813048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f",
        "10c166c6a711e81c46f45b18e5873cc4f494f003180dd7f115585d871a28930259654fe28a54dab319cc5011204c8373b50a57b0fdc7a678bd74c523259dfe4fd5ea9f52f170e19dfa332930ad1609fc8a00902d725cfe50685c95e5b2968c9a2828a21207fcf393d15f849769e2af34ac4259d91dfd98c3a707c509e1af55647efaa31290ddf48e0133b798562af5eabd327270ac2fb6c594734ce339a14ea4fe1b9a2f81c0bc230ca523bda17ff42a377266bc2778a274c0ae5ec5a8cbbe364fcf0d2403f7ee178d77ff28b67a20c7ceec009182dbcaa9bc99b51ebbf13b7d542be337172c6474f2cd3561219fe0dfa3fb207cff89632091ab841cf38d8aa88af6891539f263adb8eac6402c41b6ebd72984e43666e537f5f5fe27b2b5aa114957e9a580730308a5f5a9c63a1eb599f093ab401d0c6003a451931b6d124180305705845060ebba6b0036154fcef3e5e9f9e4b87e8f084542fd1dd67e7782a5585150181c01eb6d90cb95883837384a5b91dbb606f266059ecc51b5acbaa280e45cfd2eec8cc1cdb1b7211c8e14805ba683f9b78824b2eb005bc8a7d7179a36c152cb87c8219e5569bba911bb32a1b923ca83de0e03fb10fba75d85c55907dda5a2606bf918b056c3808ba496a4d95532212040a5f44f37e1097f26dc27b98a51837daa78f23e532156296b64352669c94a8a855acf30533d8e0594ace7c442",
        "364f6a40dbfbc3bbb257943337eeff791a0f290898a6791283bba581d9eac90a6376a837241f5f73a78a5c6746e1306ba3adab6067c32ff69115734ce014d354e2f259d4cbfb890244fd451a497fe6ecf9aa90d19a2d441162f7eaa7ce3fc4e89fd4e76b7ae585be2a2c0fd6fb246b8ac8d58bcb585634e30c9168a434786fe5e0b74bfe8187b47ac091aa571ffea0a864cb906d0e28c77a00e8cd8f6aba4317a8cc7bf32ce566bd1ef80c64de041728abe087bee6cadd0b7062bde5ceef308a23bd1ccc154fd0c3a26110df6193464fc0d24ee189aea8979d722170ba945fdcce9b1b4b63349980f3a92dc2e5418c54d38a862916926b3f9ca270a8cf40dfb9772bfbdd9a3e0e0892369c18249211ba857f35963d0e05d8da98f1aa0c6bba58f47487b8f663e395091275f82941830b050b260e4767ce2fa903e75ff8970c98bfb3a08d6db91ab1746c86420ee2e909bf681cac173697135983c3594b2def673736220452fde4ddec867d40ff42dd3da36c84e3e52508b891a00f50b4f62d112edb3b6b6cc3dbd546ba10f36b03f06c0d82aeec3b25e127af545fac28e1613a0517a6095ad18a98ab79f68801e05c175e15bae21f821e80c80ab4fdec6fb34ca315e194502b8f3dcf7892b511aee45060e3994cd15e003861bc7220a2babd7b40eda03382548a34a7110f9b1779bf3ef6011361611e6bc5c0dc851e1509de1a",
        "6fef8bf9bc182cd8cf7ce45c7dcf0e6f3e518ae48f06f3c670c649ac737a8b8119a34d51641785be151a697ed7825fdfece82865123445eab03eb4bb91cecf4d6951738495f8481151b62de869658573df4e50a95c17c31b52e154ae26a04067d5ecdc1592c287550bb982a5bb9c30fd53a768cee6baabb3d483e9f1e2da954c7f4cf492fe3944d2fe456c1ecaf0840369e33fb4010e6b44bb1d721840513524d8e9a3519f40d1b81ae34fb7a31ee6b7ed641cb16c2ac999004c2191de0201457523f5a4700dd649267d9286f5c1d193f1454c9f868a57816bf5ff76c838a2eeb616a3fc9976f65d4371deecfbab29362caebdff69c635fe5a2113da4d4d8c24f0b16a0584fa05e80e607c5d9a2f765f1f069f8d4da21f27c2a3b5c984b4ab24899bef46c6d9323df4862fe51ce300fca40fb539c3bb7fe2dcc9409e425f2d3b95e70e9c49c5feb6ecc9d43442c33d50003ee936845892fb8be475647da9a080f5bc7f8a716590b3745c2209fe05b17992830ce15f32c7b22cde755c8a2fe50bd814a0434130b807dc1b7218d4e85342d70695a5d7f29306f25623ad1e8aa08ef71b54b8ee447b5f64e73d09bdd6c3b7ca224058d7c67cc7551e9241688ada12d859cb7646fbd3ed8b34312f3b49d69802f0eaa11bc4211c2f7a29cd5c01ed01a39001c5856fab36228f5ee2f2e1110811872fe7c865c42ed59029c706195d52",
    );
}

test "RFC9474: RSABSSA-SHA384-PSSZERO-Deterministic" {
    const BRsa = BlindRsaDeterministic(4096);
    try testRfc9474Vector(
        BRsa,
        "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5",
        "010001",
        "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051",
        "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d",
        "",
        "55f2053e9a4309ac61ac4da7f3a314e626f362e95f30337962d12f08b343165c8dea34d7812dc2dcb227cfa8de49bca57880ac55f6d77b37ed83a32eb33656ddf0cde29761aef9f86bd758280b3403a63b466831cba4c97e17e9a11e4139f9d84e5912b017eafbafdbb3ae59a1424feae6914eb1bf20922c6db5da8a538752b3b662ae15cae7beac9a0362b8836001c57b0c5167dceb9a66e6ab6a90e9898646b4274c3662e4316926c4da7caf5aeff611934b70581280ec68fb2ce04c5681ef95b086b7289afae8ecd669325659791853a9f4c0b784f6f60b212c3b39754d5539e3671d7930d1272e82b3853b6583a83d9ff70c00ce1938c05eccee531cb075564059b2749e84b45dff7d179c69c86c5d1870aeffd6281d099838a3a988ff9e2684f6cc896b5326275309187d9e3558163131e4d247c2ec8317a2c09f8079d32db8241c869bc5f773722ed8e68bfa5c518d20b955abf02103fce1a025149b14670fdfc8a3f0089516db047f86b9be626ff44989d6fcc162c9570da5b862b47304eca2aceba4dedd6a672458aae779004fe116009600a6a52eb6161a3d09fda09963b56f2870a150df7183bfa03ce735513e637631fb4f980657a8cdb953b2156594607f8ebf7de6999626197072afd7ff60a5d2f782dabe026e0f298df141b8a276aaf7202d959088d7721786b04c79e45c807eb46fcf3a94031ef351aff644",
        "0c86f078fe8fd2ea6b4e120d3fef7555701a7c6b7bd5606a7fb2ef2769d119f2639477a7904984d67f0ecf419059aac58041977871d8da253a1aee14cde49cfb919f502f4d79d56d473a95f450982ad83398c1f3dd3a3342a18df9e81447998eae6c7f9de94148a30de0846fc2402b17b2dfe233c450ba41f141ec14b27bf4e7d79a5c0fa23ad64c2d2fa33691a3048d835f7e477ecba458e4d58f8dbbcfec2a484e1442ab4b266cfc610fec95f6258ef137590254931dea30f58e96a64cef7aca013cb037259d4dec8a2298d3e2ce96c75a10f39dcdfe7e90eba200c73fc3f5fbbdc4d50d33990559504d0ddb4fe50407fc21321128f72866c780d1412f20d4788ad0ebc2077dca4ae87108e416c3510609867196f4fbb69ff6c3a4c0249e3d6bcf157636666a0e17d8dba9034d9875e40bbff075b0a936acd75baf15179042959d6b27f8e233b60db93a2abce81f47e259f76b5a68d58c21fd8ccd7e102fc9292ec5a1bad8618a94f09ca6a58b1c5c7062fb17bd62035d898b76ead5f52a9869d5b6fbbbf5cd07bc3c35adbff4f03949fe32b455cd5b3de07859d65045b72fb1f4a0ab5c80a27a60b57ebd9e0b173778d3be592e74cdc6a9ffa147cbb021a87b9a525bc9135114d4daacf0b111773551474ea98493ed8562dac1c9e6398ada60573ff550a01aa4468fd493fb69b3a98ab3790fc7f71ef5dfa3f1979ebe35af",
        "5ca77254ce107e6e6eedcf8ca03e08d4e92eeb0f4f08b2a2e7fb69da2f5db95f2167ce58a861e45a5cac1bf7d3df3edd64a2802bb5c16ceb62b2f5a0355c0d0f6d8270b658fa26e86afc18a88e91b0ec07e813d50ed4fb20376bf8470179a3a97d5a29f9f9fe931d6bff233c45d62cd91cdb9a692cda309fad962fd9f7f19f89cc48bc75f9b521aeca21921330c7e91ff7ff2af6e62fe3112f7ec675e866c5961556a1796f2fd4707dd9fcde702caf003b5acfde1cd97bc5d2a63d126ac0587bf8ed6a3064d20dbdef9e207423e678f36e516e4c2696cc74f0a74be4c3ddaaf6cdbc95c9d58d930f0f4e00dfa2bf5d0a333964ec03226073030b9b78210d3160ec2722abf3c01efa1636a28c6c5ac9d14913537322ee42d26ab26518ec2af03202ea0e190a4790b7a8951be98313000c62d1fe0ea05647c451348f97ef5ced6c6e83303aececcc508fcc8f18f7751e050f9f7a562f45b0d03159486d067ab4b3df1b0f270d009436f0305640929a2b61cfeef24a2e39a9a622c9d9d9e2c99245ea415243f472b226e068ebba7624ccf012b86b21d80cb2e3b718224b2f7b638a16b7665a1a493b014dd3d0f7b97ca290665b1f0972bc4a7d4051e843182771b6258d9d63f919fde109f8487f443ea54518c053acfbf7c0cfe60435b6966d42c034cf6ad3be2281fa2bf1a90f1d2cba55643e9ae37065a7534f53402e6f4c2a3a",
        "4454b6983ff01cb28545329f394936efa42ed231e15efbc025fdaca00277acf0c8e00e3d8b0ecebd35b057b8ebfc14e1a7097368a4abd20b555894ccef3d1b9528c6bcbda6b95376bef230d0f1feff0c1064c62c60a7ae7431d1fdfa43a81eed9235e363e1ffa0b2797aba6aad6082fcd285e14fc8b71de6b9c87cb4059c7dc1e96ae1e63795a1e9af86b9073d1d848aef3eca8a03421bcd116572456b53bcfd4dabb0a9691f1fabda3ed0ce357aee2cfee5b1a0eb226f69716d4e011d96eede5e38a9acb531a64336a0d5b0bae3ab085b658692579a376740ff6ce69e89b06f360520b864e33d82d029c808248a19e18e31f0ecd16fac5cd4870f8d3ebc1c32c718124152dc905672ab0b7af48bf7d1ac1ff7b9c742549c91275ab105458ae37621757add83482bbcf779e777bbd61126e93686635d4766aedf5103cf7978f3856ccac9e28d21a850dbb03c811128616d315d717be1c2b6254f8509acae862042c034530329ce15ca2e2f6b1f5fd59272746e3918c748c0eb810bf76884fa10fcf749326bbfaa5ba285a0186a22e4f628dbf178d3bb5dc7e165ca73f6a55ecc14c4f5a26c4693ce5da032264cbec319b12ddb9787d0efa4fcf1e5ccee35ad85ecd453182df9ed735893f830b570faae8be0f6fe2e571a4e0d927cba4debd368d3b4fca33ec6251897a137cf75474a32ac8256df5e5ffa518b88b43fb6f63a24",
    );
}
