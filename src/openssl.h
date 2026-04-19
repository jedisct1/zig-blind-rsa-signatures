#define __FILE__ "blind_rsa.zig"
#define __LINE__ 0
#define OPENSSL_API_COMPAT 10100

// zig translate-c cannot handle _Pragma(), so neutralize the pragma
// macros that BoringSSL defines in base.h. We pull in base.h first
// (if it exists) so the macros are defined, then override them.
#if __has_include(<openssl/base.h>)
#include <openssl/base.h>
#undef OPENSSL_GNUC_CLANG_PRAGMA
#define OPENSSL_GNUC_CLANG_PRAGMA(arg)
#undef OPENSSL_CLANG_PRAGMA
#define OPENSSL_CLANG_PRAGMA(arg)
#undef OPENSSL_MSVC_PRAGMA
#define OPENSSL_MSVC_PRAGMA(arg)
#undef OPENSSL_BEGIN_ALLOW_DEPRECATED
#define OPENSSL_BEGIN_ALLOW_DEPRECATED
#undef OPENSSL_END_ALLOW_DEPRECATED
#define OPENSSL_END_ALLOW_DEPRECATED
#endif

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
