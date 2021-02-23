const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const ssl = @cImport({
    @cDefine("__FILE__", "\"blindrsa.zig\"");
    @cDefine("__LINE__", "0");

    @cInclude("openssl/bn.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/crypto.h");
});

const BN_CTX = ssl.BN_CTX;
const EVP_MD = ssl.EVP_MD;
const RSA = ssl.RSA;
const BIGNUM = ssl.BIGNUM;
const EVP_PKEY = ssl.EVP_PKEY;

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

const Hash = .{
    .digest_length = ssl.SHA384_DIGEST_LENGTH,
    .evp = ssl.EVP_sha384,
    .ctx = ssl.SHA512_CTX,
    .init = ssl.SHA384_Init,
    .update = ssl.SHA384_Update,
    .final = ssl.SHA384_Final,
};

// Blind RSA signatures with a modulus_bits modulus size
pub fn BlindRsa(comptime modulus_bits: u16) type {
    assert(modulus_bits >= 2048 and modulus_bits <= 4096);

    return struct {
        const modulus_bytes = modulus_bits / 8;

        // A secret blinding factor
        pub const Secret = [modulus_bytes]u8;

        // A blind message
        pub const BlindMessage = [modulus_bytes]u8;

        // A blind signature
        pub const BlindSignature = [modulus_bytes]u8;

        // A (non-blind) signature
        pub const Signature = [modulus_bytes]u8;

        // The result of a blinding operation
        pub const BlindingResult = struct { blind_message: BlindMessage, secret: Secret };

        // An RSA public key
        pub const PublicKey = struct {
            rsa: *RSA,

            pub fn deinit(pk: PublicKey) void {
                ssl.RSA_free(pk.rsa);
            }

            // Import a serialized RSA public key
            pub fn import(der: []const u8) !PublicKey {
                var evp_pkey: ?*EVP_PKEY = null;
                var der_ptr: [*c]const u8 = der.ptr;
                try sslNTry(EVP_PKEY, ssl.d2i_PrivateKey(ssl.EVP_PKEY_RSA, &evp_pkey, &der_ptr, @intCast(c_long, der.len)));
                defer ssl.EVP_PKEY_free(evp_pkey);
                var pk = try sslAlloc(RSA, ssl.EVP_PKEY_get1_RSA(evp_pkey));
                return PublicKey{ .rsa = pk };
            }

            // Serialize an RSA public key
            pub fn serialize(pk: PublicKey, serialized: []u8) ![]u8 {
                var evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                try sslTry(ssl.EVP_PKEY_set1_RSA(evp_pkey, pk.rsa));
                defer ssl.EVP_PKEY_free(evp_pkey);
                var serialized_ptr: [*c]u8 = null;
                const len = ssl.i2d_PrivateKey(evp_pkey, &serialized_ptr);
                try sslNTry(u8, serialized_ptr);
                defer ssl.OPENSSL_free(serialized_ptr);
                if (len < 0 or len > serialized.len) {
                    return error.Overflow;
                }
                mem.copy(u8, serialized, @ptrCast([*]const u8, serialized_ptr.?)[0..@intCast(usize, len)]);
                return serialized[0..@intCast(usize, len)];
            }

            // Blind a message and return the random blinding secret and the blind message
            pub fn blind(pk: PublicKey, msg: []const u8) !BlindingResult {
                // Compute H(msg)
                var msg_hash = try hash(msg);

                // PSS-MGF1 padding
                var padded: [modulus_bytes]u8 = undefined;
                var evp_md: *const EVP_MD = try sslConstPtr(EVP_MD, Hash.evp());
                try sslTry(ssl.RSA_padding_add_PKCS1_PSS_mgf1(pk.rsa, &padded, &msg_hash, evp_md, evp_md, -1));
                ssl.OPENSSL_cleanse(&msg_hash, msg_hash.len);

                // Blind the padded message
                var bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }
                return _blind(bn_ctx, padded, pk);
            }

            // Compute a signature for the original message
            pub fn finalize(pk: PublicKey, blind_sig: BlindSignature, secret_s: Secret, msg: []const u8) !Signature {
                var bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
                ssl.BN_CTX_start(bn_ctx);
                defer {
                    ssl.BN_CTX_end(bn_ctx);
                    ssl.BN_CTX_free(bn_ctx);
                }
                var secret: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                var blind_z: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                var z: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));

                try sslNTry(BIGNUM, ssl.BN_bin2bn(&secret_s, secret_s.len, secret));
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&blind_sig, blind_sig.len, blind_z));

                try sslTry(ssl.BN_mod_mul(z, blind_z, secret, ssl.RSA_get0_n(pk.rsa), bn_ctx));

                var sig: Signature = undefined;
                try sslTry(bn2binPadded(&sig, sig.len, z));
                try rsassa_pss_verify(pk, sig, msg);
                return sig;
            }

            // Verify a (non-blind) signature
            pub fn verify(pk: PublicKey, sig: Signature, msg: []const u8) !void {
                return rsassa_pss_verify(pk, sig, msg);
            }

            fn _blind(bn_ctx: *BN_CTX, padded: [modulus_bytes]u8, pk: PublicKey) !BlindingResult {
                var m: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                try sslNTry(BIGNUM, ssl.BN_bin2bn(&padded, padded.len, m));

                // Compute a blind factor and its inverse
                var secret_inv: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                var secret: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                while (true) {
                    try sslTry(ssl.BN_rand_range(secret_inv, ssl.RSA_get0_n(pk.rsa)));
                    if (!(ssl.BN_is_one(secret_inv) != 0 or ssl.BN_mod_inverse(secret, secret_inv, ssl.RSA_get0_n(pk.rsa), bn_ctx) == null)) {
                        break;
                    }
                }

                // Blind the message
                var x: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                var blind_m: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_CTX_get(bn_ctx));
                try sslTry(ssl.BN_mod_exp(x, secret_inv, ssl.RSA_get0_e(pk.rsa), ssl.RSA_get0_n(pk.rsa), bn_ctx));
                ssl.BN_clear(secret_inv);
                try sslTry(ssl.BN_mod_mul(blind_m, m, x, ssl.RSA_get0_n(pk.rsa), bn_ctx));

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

            fn rsassa_pss_verify(pk: PublicKey, sig: Signature, msg: []const u8) !void {
                const msg_hash = try hash(msg);
                var em: [modulus_bytes]u8 = undefined;
                try sslNegTry(ssl.RSA_public_decrypt(sig.len, &sig, &em, pk.rsa, ssl.RSA_NO_PADDING));

                var evp_md: *const EVP_MD = try sslConstPtr(EVP_MD, Hash.evp());
                try sslTry(ssl.RSA_verify_PKCS1_PSS_mgf1(pk.rsa, &msg_hash, evp_md, evp_md, &em, -1));
            }
        };

        pub const SecretKey = struct {
            rsa: *RSA,

            pub fn deinit(sk: SecretKey) void {
                ssl.RSA_free(sk.rsa);
            }

            // Import an RSA secret key
            pub fn import(der: []const u8) !SecretKey {
                var evp_pkey: ?*EVP_PKEY = null;
                var der_ptr: [*c]const u8 = der.ptr;
                try sslNTry(EVP_PKEY, ssl.d2i_PrivateKey(ssl.EVP_PKEY_RSA, &evp_pkey, &der_ptr, @intCast(c_long, der.len)));
                defer ssl.EVP_PKEY_free(evp_pkey);
                var sk = try sslAlloc(RSA, ssl.EVP_PKEY_get1_RSA(evp_pkey));
                return SecretKey{ .rsa = sk };
            }

            // Serialize an RSA secret key
            pub fn serialize(sk: SecretKey, serialized: []u8) ![]u8 {
                var evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                try sslTry(ssl.EVP_PKEY_set1_RSA(evp_pkey, sk.rsa));
                defer ssl.EVP_PKEY_free(evp_pkey);
                var serialized_ptr: [*c]u8 = null;
                const len = ssl.i2d_PrivateKey(evp_pkey, &serialized_ptr);
                try sslNTry(u8, serialized_ptr);
                defer ssl.OPENSSL_free(serialized_ptr);
                if (len < 0 or len > serialized.len) {
                    return error.Overflow;
                }
                mem.copy(u8, serialized, @ptrCast([*]const u8, serialized_ptr.?)[0..@intCast(usize, len)]);
                return serialized[0..@intCast(usize, len)];
            }

            // Compute a blind signature
            pub fn blind_sign(sk: SecretKey, blind_message: BlindMessage) !BlindSignature {
                var blind_sig: BlindSignature = undefined;
                try sslNegTry(ssl.RSA_private_encrypt(blind_sig.len, &blind_message, &blind_sig, sk.rsa, ssl.RSA_NO_PADDING));
                return blind_sig;
            }
        };

        // An RSA key pair
        pub const KeyPair = struct {
            pk: PublicKey,
            sk: SecretKey,

            pub fn deinit(kp: KeyPair) void {
                kp.pk.deinit();
                kp.sk.deinit();
            }

            // Generate a new key pair
            pub fn generate() !KeyPair {
                var sk = try sslAlloc(RSA, ssl.RSA_new());
                errdefer ssl.RSA_free(sk);
                var e: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(e);
                try sslTry(ssl.BN_set_word(e, ssl.RSA_F4));
                try sslTry(ssl.RSA_generate_key_ex(sk, modulus_bits, e, null));
                var pk = try sslAlloc(RSA, ssl.RSAPublicKey_dup(sk));
                return KeyPair{ .sk = SecretKey{ .rsa = sk }, .pk = PublicKey{ .rsa = pk } };
            }
        };

        fn hash(msg: []const u8) ![Hash.digest_length]u8 {
            var hash_ctx: Hash.ctx = undefined;
            var h: [Hash.digest_length]u8 = undefined;
            try sslTry(Hash.init(&hash_ctx));
            try sslTry(Hash.update(&hash_ctx, msg.ptr, msg.len));
            try sslTry(Hash.final(&h, &hash_ctx));
            return h;
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
    var blinding_result = try pk.blind(msg);

    // Compute a blind signature
    var blind_sig = try sk.blind_sign(blinding_result.blind_message);

    // Compute the signature for the original message
    var sig = try pk.finalize(blind_sig, blinding_result.secret, msg);

    // Verify the non-blind signature
    try pk.verify(sig, msg);
}
