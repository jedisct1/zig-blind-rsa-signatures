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
    @cInclude("openssl/x509.h");
});
const testing = std.testing;

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
    if (ssl.BN_bn2binpad(in, out, @intCast(c_int, out_len)) == out_len) {
        return 1;
    }
    return 0;
}

fn rsaRef(evp_pkey: *const EVP_PKEY) *RSA {
    return ssl.EVP_PKEY_get0_RSA(@intToPtr(*EVP_PKEY, @ptrToInt(evp_pkey))).?;
}

fn rsaBits(evp_pkey: *const EVP_PKEY) c_int {
    return ssl.RSA_bits(rsaRef(evp_pkey));
}

fn rsaSize(evp_pkey: *const EVP_PKEY) usize {
    return @intCast(usize, ssl.RSA_size(rsaRef(evp_pkey)));
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

/// Standard blind RSA signatures with a `modulus_bits` modulus size.
/// Recommended for most applications.
pub fn BlindRsa(comptime modulus_bits: u16) type {
    return BlindRsaCustom(modulus_bits, .sha384, HashParams.sha384.salt_length);
}

/// Blind RSA signatures with a `modulus_bits` modulus size.
/// Non-deterministic padding is recommended for most applications.
pub fn BlindRsaDeterministic(comptime modulus_bits: u16) type {
    return BlindRsaCustom(modulus_bits, .sha384, 0);
}

/// Blind RSA signatures with custom parameters.
pub fn BlindRsaCustom(
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

        /// The result of a blinding operation
        pub const BlindingResult = struct { blind_message: BlindMessage, secret: Secret };

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
                try sslNTry(EVP_PKEY, ssl.d2i_PublicKey(ssl.EVP_PKEY_RSA, &evp_pkey_, &der_ptr, @intCast(c_long, raw.len)));
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
                try sslNTry(ssl.X509_PUBKEY, ssl.d2i_X509_PUBKEY(&x509_pkey, &der_ptr, @intCast(c_long, der.len)));
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
                mem.copy(u8, serialized, @ptrCast([*]const u8, serialized_ptr.?)[0..@intCast(usize, len)]);
                return serialized[0..@intCast(usize, len)];
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
                mem.copy(u8, serialized, @ptrCast([*]const u8, serialized_ptr.?)[0..@intCast(usize, len)]);
                return serialized[0..@intCast(usize, len)];
            }

            /// Blind a message and return the random blinding secret and the blind message
            pub fn blind(pk: PublicKey, msg: []const u8) !BlindingResult {
                // Compute H(msg)
                const evp_md = Hash.evp_fn().?;
                var msg_hash_buf: [ssl.EVP_MAX_MD_SIZE]u8 = undefined;
                const msg_hash = try hash(evp_md, &msg_hash_buf, msg);

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
                return _blind(bn_ctx, padded, pk);
            }

            /// Compute a signature for the original message
            pub fn finalize(pk: PublicKey, blind_sig: BlindSignature, secret_s: Secret, msg: []const u8) !Signature {
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
                try verify(pk, sig, msg);
                return sig;
            }

            /// Verify a (non-blind) signature
            pub fn verify(pk: PublicKey, sig: Signature, msg: []const u8) !void {
                return rsaSsaPssVerify(pk, sig, msg);
            }

            fn _blind(bn_ctx: *BN_CTX, padded: [modulus_bytes]u8, pk: PublicKey) !BlindingResult {
                const m: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&padded, padded.len, m));

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
                };
            }

            fn rsaSsaPssVerify(pk: PublicKey, sig: Signature, msg: []const u8) !void {
                const evp_md = Hash.evp_fn().?;
                var msg_hash_buf: [ssl.EVP_MAX_MD_SIZE]u8 = undefined;
                const msg_hash = try hash(evp_md, &msg_hash_buf, msg);
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
                var raw = raw_ptr[0..@intCast(usize, raw_len)];
                defer ssl.OPENSSL_free(raw_ptr);
                const container_len = spki_tpl.len - 4 + raw.len;
                const out_len = spki_tpl.len + raw.len;
                if (out_len > buf.len) {
                    return error.Overflow;
                }
                var out = buf[0..out_len];
                mem.copy(u8, out[0..spki_tpl.len], spki_tpl[0..]);
                mem.copy(u8, out[spki_tpl.len..], raw);
                mem.writeIntBig(u16, out[2..4], @intCast(u16, container_len));
                out[66] = @intCast(u8, salt_length);
                mem.writeIntBig(u16, out[69..71], @intCast(u16, 1 + raw.len));

                var algor_mgf1 = try sslAlloc(X509_ALGOR, ssl.X509_ALGOR_new());
                defer ssl.X509_ALGOR_free(algor_mgf1);
                ssl.X509_ALGOR_set_md(algor_mgf1, Hash.evp_fn().?);
                var algor_mgf1_s_ptr: ?*ssl.ASN1_STRING = try sslAlloc(ssl.ASN1_STRING, ssl.ASN1_STRING_new());
                defer ssl.ASN1_STRING_free(algor_mgf1_s_ptr);
                var alg_rptr: *const ssl.ASN1_ITEM = &ssl.X509_ALGOR_it;
                try sslNTry(ssl.ASN1_STRING, ssl.ASN1_item_pack(algor_mgf1, alg_rptr, &algor_mgf1_s_ptr));
                const algor_mgf1_s_len = ssl.ASN1_STRING_length(algor_mgf1_s_ptr);
                const algor_mgf1_s = ssl.ASN1_STRING_get0_data(algor_mgf1_s_ptr)[0..@intCast(usize, algor_mgf1_s_len)];
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
                try sslNTry(EVP_PKEY, ssl.d2i_PrivateKey(ssl.EVP_PKEY_RSA, &evp_pkey, &der_ptr, @intCast(c_long, der.len)));
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
                mem.copy(u8, serialized, @ptrCast([*]const u8, serialized_ptr.?)[0..@intCast(usize, len)]);
                return serialized[0..@intCast(usize, len)];
            }

            /// Recover the public key
            pub fn publicKey(sk: SecretKey) !PublicKey {
                var serialized: [*c]u8 = null;
                const serialized_len_ = ssl.i2d_PublicKey(sk.evp_pkey, &serialized);
                if (serialized_len_ < 0) {
                    return error.InternalError;
                }
                const serialized_len = @intCast(usize, serialized_len_);
                defer ssl.OPENSSL_clear_free(serialized, serialized_len);
                return PublicKey.import(serialized[0..serialized_len]);
            }

            /// Compute a blind signature
            pub fn blindSign(sk: SecretKey, blind_message: BlindMessage) !BlindSignature {
                const n = rsaParam(.n, sk.evp_pkey);
                var n_s: [blind_message.len]u8 = undefined;
                try sslTry(bn2binPadded(&n_s, n_s.len, n));
                for (blind_message) |a, i| {
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
                const sk = try sslAlloc(RSA, ssl.RSA_new());
                errdefer ssl.RSA_free(sk);
                const e: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(e);
                try sslTry(ssl.BN_set_word(e, ssl.RSA_F4));
                try sslTry(ssl.RSA_generate_key_ex(sk, modulus_bits, e, null));
                var evp_pkey: *EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                _ = ssl.EVP_PKEY_assign(evp_pkey, ssl.EVP_PKEY_RSA, sk);
                const sk_ = SecretKey{ .evp_pkey = evp_pkey };
                return KeyPair{ .sk = sk_, .pk = try sk_.publicKey() };
            }
        };

        fn saltLength() usize {
            return salt_length;
        }

        fn hash(evp: *const EVP_MD, h: *[ssl.EVP_MAX_MD_SIZE]u8, msg: []const u8) ![]u8 {
            const len = @intCast(usize, ssl.EVP_MD_size(evp));
            debug.assert(h.len >= len);
            var hash_ctx = try sslAlloc(EVP_MD_CTX, ssl.EVP_MD_CTX_new());
            try sslTry(ssl.EVP_DigestInit(hash_ctx, evp));
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

test "RSA blind signatures" {
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
    const sig = try pk.finalize(blind_sig, blinding_result.secret, msg);

    // Verify the non-blind signature
    try pk.verify(sig, msg);
}

test "Deterministic RSA blind signatures" {
    // Generate a new RSA-2048 key
    var kp = try BlindRsaDeterministic(2048).KeyPair.generate();
    defer kp.deinit();
    var pk = kp.pk;
    const sk = kp.sk;

    const msg = "msg";
    const blinding_result = try pk.blind(msg);
    const blind_sig = try sk.blindSign(blinding_result.blind_message);
    const sig = try pk.finalize(blind_sig, blinding_result.secret, msg);
    try pk.verify(sig, msg);
}

test "RSA export/import" {
    const kp = try BlindRsaCustom(2048, .sha256, 32).KeyPair.generate();
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

test "Test vector" {
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

    const BRsa = BlindRsa(4096);

    var n: ?*BIGNUM = null;
    var e: ?*BIGNUM = null;
    var d: ?*BIGNUM = null;
    try sslNegTry(ssl.BN_hex2bn(&n, tv.n));
    try sslNegTry(ssl.BN_hex2bn(&e, tv.e));
    try sslNegTry(ssl.BN_hex2bn(&d, tv.d));
    const sk_ = try sslAlloc(RSA, ssl.RSA_new());
    try sslTry(ssl.RSA_set0_key(sk_, n, e, d));
    const pk_ = try sslAlloc(RSA, ssl.RSA_new());
    try sslTry(ssl.RSA_set0_key(pk_, n, e, null));
    var msg: [tv.msg.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&msg, tv.msg);
    var secret: BRsa.Secret = undefined;
    _ = try fmt.hexToBytes(&secret, tv.secret);
    var blind_sig: BRsa.BlindSignature = undefined;
    _ = try fmt.hexToBytes(&blind_sig, tv.blind_sig);
    var blinded_message: [tv.blinded_message.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&blinded_message, tv.blinded_message);

    var sk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    _ = ssl.EVP_PKEY_assign(sk_evp_pkey, ssl.EVP_PKEY_RSA, sk_);
    const sk = BRsa.SecretKey{ .evp_pkey = sk_evp_pkey };
    var pk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    _ = ssl.EVP_PKEY_assign(pk_evp_pkey, ssl.EVP_PKEY_RSA, pk_);
    const pk = BRsa.PublicKey{
        .evp_pkey = pk_evp_pkey,
        .mont_ctx = try BRsa.newMontDomain(ssl.RSA_get0_n(pk_).?),
    };

    const sig = try pk.finalize(blind_sig, secret, &msg);
    try pk.verify(sig, &msg);

    const computed_blind_sig = try sk.blindSign(blinded_message);
    try testing.expectEqualSlices(u8, computed_blind_sig[0..], blind_sig[0..]);
}

test "Test vector generation" {
    const modulus_bits = 2048;
    const BRsa = BlindRsa(modulus_bits);
    const kp = try BRsa.KeyPair.generate();
    defer kp.deinit();
    const pk = kp.pk;
    const sk = kp.sk;
    var p: [modulus_bits / 8 / 2]u8 = undefined;
    var q: [modulus_bits / 8 / 2]u8 = undefined;
    var n: [modulus_bits / 8]u8 = undefined;
    var d: [modulus_bits / 8]u8 = undefined;
    var e: [3]u8 = undefined;
    try sslTry(bn2binPadded(&p, p.len, rsaParam(.p, sk.evp_pkey)));
    try sslTry(bn2binPadded(&q, q.len, rsaParam(.q, sk.evp_pkey)));
    try sslTry(bn2binPadded(&n, n.len, rsaParam(.n, sk.evp_pkey)));
    try sslTry(bn2binPadded(&d, d.len, rsaParam(.d, sk.evp_pkey)));
    try sslTry(bn2binPadded(&e, e.len, rsaParam(.e, sk.evp_pkey)));
    debug.print("p: {s}\n", .{fmt.fmtSliceHexLower(&p)});
    debug.print("q: {s}\n", .{fmt.fmtSliceHexLower(&q)});
    debug.print("n: {s}\n", .{fmt.fmtSliceHexLower(&n)});
    debug.print("d: {s}\n", .{fmt.fmtSliceHexLower(&d)});
    debug.print("e: {s}\n", .{fmt.fmtSliceHexLower(&e)});

    const msg = "This is just a test vector";
    debug.print("msg: {s}\n", .{fmt.fmtSliceHexLower(msg)});
    const blinded_msg = try pk.blind(msg);
    debug.print("inv: {s}\n", .{fmt.fmtSliceHexLower(&blinded_msg.secret)});
    debug.print("blinded_message: {s}\n", .{fmt.fmtSliceHexLower(&blinded_msg.blind_message)});

    const blind_sig = try sk.blindSign(blinded_msg.blind_message);
    debug.print("blind_sig: {s}\n", .{fmt.fmtSliceHexLower(&blind_sig)});

    const sig = try pk.finalize(blind_sig, blinded_msg.secret, msg);
    debug.print("sig: {s}\n", .{fmt.fmtSliceHexLower(&sig)});

    var spki_buf: [BRsa.PublicKey.max_spki_length]u8 = undefined;
    const spki = try pk.serialize_spki(&spki_buf);
    const encoder = std.base64.standard.Encoder;
    var b64_buf: [encoder.calcSize(spki_buf.len)]u8 = undefined;
    const b64 = encoder.encode(&b64_buf, spki);
    debug.print("spki: {s}\n", .{b64});

    const pk2 = try BRsa.PublicKey.import_spki(spki);
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
