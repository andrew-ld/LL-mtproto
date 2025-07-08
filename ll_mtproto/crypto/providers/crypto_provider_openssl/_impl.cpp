#include <Python.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#if defined(__SSE2__)
#include <emmintrin.h>
#define HAS_EMMINTRIN
#elif defined(__ARM_NEON)
#include <arm_neon.h>
#define HAS_ARM_NEON
#endif

#if defined(_MSC_VER)
#define ALWAYS_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define ALWAYS_INLINE inline
#endif

#if defined(__x86_64__)
#include <immintrin.h>
#define HAS_IMMINTRIN
#endif

#if defined(HAS_IMMINTRIN)
#define COUNT_TRAILING_ZEROS(x) _tzcnt_u64(x)
#elif defined(__GNUC__) || defined(__clang__)
#define COUNT_TRAILING_ZEROS(x) __builtin_ctzll(x)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

#if defined(__GNUC__) || defined(__clang__)
#define PREFETCH_READ_NTA(addr) __builtin_prefetch((addr), 0, 0)
#define PREFETCH_WRITE_NTA(addr) __builtin_prefetch((addr), 1, 0)
#else
#define PREFETCH_READ_NTA(addr)
#define PREFETCH_WRITE_NTA(addr)
#endif

namespace detail {
#if defined(HAS_EMMINTRIN)
struct alignas(16) SimdBlock128SSE2 {
  __m128i value;

  SimdBlock128SSE2() = default;

  ALWAYS_INLINE explicit SimdBlock128SSE2(const void *p)
      : value(_mm_loadu_si128(static_cast<const __m128i *>(p))) {}

  ALWAYS_INLINE void store(void *p) const {
    _mm_storeu_si128(static_cast<__m128i *>(p), value);
  }

  ALWAYS_INLINE SimdBlock128SSE2
  operator^(const SimdBlock128SSE2 &other) const {
    SimdBlock128SSE2 result{};
    result.value = _mm_xor_si128(value, other.value);
    return result;
  }

  [[nodiscard]] ALWAYS_INLINE const uint8_t *raw() const {
    return reinterpret_cast<const uint8_t *>(this);
  }

  ALWAYS_INLINE uint8_t *raw() { return reinterpret_cast<uint8_t *>(this); }
};
#endif

#if defined(HAS_ARM_NEON)
struct alignas(16) SimdBlock128NEON {
  uint8x16_t value;

  SimdBlock128NEON() = default;
  ALWAYS_INLINE explicit SimdBlock128NEON(const void *p)
      : value(vld1q_u8(static_cast<const uint8_t *>(p))) {}
  ALWAYS_INLINE void store(void *p) const {
    vst1q_u8(static_cast<uint8_t *>(p), value);
  }
  ALWAYS_INLINE SimdBlock128NEON
  operator^(const SimdBlock128NEON &other) const {
    SimdBlock128NEON result;
    result.value = veorq_u8(value, other.value);
    return result;
  }
  ALWAYS_INLINE const uint8_t *raw() const {
    return reinterpret_cast<const uint8_t *>(this);
  }
  ALWAYS_INLINE uint8_t *raw() { return reinterpret_cast<uint8_t *>(this); }
};
#endif

struct alignas(16) SimdBlock128Fallback {
  uint64_t value[2]{};

  SimdBlock128Fallback() = default;

  ALWAYS_INLINE explicit SimdBlock128Fallback(const void *p) {
    memcpy(value, p, 16);
  }

  ALWAYS_INLINE void store(void *p) const { memcpy(p, value, 16); }
  ALWAYS_INLINE SimdBlock128Fallback
  operator^(const SimdBlock128Fallback &other) const {
    SimdBlock128Fallback result;
    result.value[0] = value[0] ^ other.value[0];
    result.value[1] = value[1] ^ other.value[1];
    return result;
  }

  [[nodiscard]] ALWAYS_INLINE const uint8_t *raw() const {
    return reinterpret_cast<const uint8_t *>(this);
  }

  ALWAYS_INLINE uint8_t *raw() { return reinterpret_cast<uint8_t *>(this); }
};
} // namespace detail

#if defined(HAS_EMMINTRIN)
using SimdBlock128 = detail::SimdBlock128SSE2;
#elif defined(HAS_ARM_NEON)
using SimdBlock128 = detail::SimdBlock128NEON;
#else
using SimdBlock128 = detail::SimdBlock128Fallback;
#endif

static void set_openssl_error(const char *msg) {
  std::string err_msg = msg;
  unsigned long err_code;
  char err_buf[256];
  while ((err_code = ERR_get_error()) != 0) {
    ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
    err_msg += "; ";
    err_msg += err_buf;
  }
  PyErr_SetString(PyExc_ValueError, err_msg.c_str());
}

struct PyBufferGuard {
  Py_buffer &view;

  explicit PyBufferGuard(Py_buffer &v) : view(v) {}

  ~PyBufferGuard() { PyBuffer_Release(&view); }
};

struct Slice {
  const uint8_t *data_ = nullptr;
  size_t size_ = 0;

  Slice(const void *data, const size_t size)
      : data_(static_cast<const uint8_t *>(data)), size_(size) {}

  [[nodiscard]] const uint8_t *ubegin() const { return data_; }
  [[nodiscard]] size_t size() const { return size_; }
};

struct MutableSlice {
  uint8_t *data_ = nullptr;
  size_t size_ = 0;

  MutableSlice(void *data, const unsigned long size)
      : data_(static_cast<uint8_t *>(data)), size_(size) {}

  [[nodiscard]] uint8_t *ubegin() const { return data_; }
  [[nodiscard]] size_t size() const { return size_; }
  [[nodiscard]] Slice as_slice() const { return {data_, size_}; }
};

namespace Random {
static uint64_t state;

void seed() { RAND_bytes(reinterpret_cast<uint8_t *>(&state), sizeof(state)); }

uint64_t fast_uint64() {
  // https://en.wikipedia.org/wiki/Xorshift#xorshift*
  uint64_t x = state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  state = x;
  return x * 0x2545F4914F6CDD1DULL;
}
} // namespace Random

#ifdef COUNT_TRAILING_ZEROS
static uint64_t pq_gcd(uint64_t a, uint64_t b) {
  // https://en.wikipedia.org/wiki/Binary_GCD_algorithm
  if (UNLIKELY(a == 0))
    return b;
  if (UNLIKELY(b == 0))
    return a;

  const unsigned long a_tz = COUNT_TRAILING_ZEROS(a);
  const unsigned long b_tz = COUNT_TRAILING_ZEROS(b);
  const unsigned long common_factor_pow2 = std::min(a_tz, b_tz);

  a >>= a_tz;
  b >>= b_tz;

  while (true) {
    if (a > b) {
      a -= b;
      a >>= COUNT_TRAILING_ZEROS(a);
    } else if (b > a) {
      b -= a;
      b >>= COUNT_TRAILING_ZEROS(b);
    } else {
      break;
    }
  }

  return a << common_factor_pow2;
}
#else
static uint64_t pq_gcd(uint64_t a, uint64_t b) {
  while (b) {
    a %= b;
    std::swap(a, b);
  }
  return a;
}
#endif

#if defined(HAS_IMMINTRIN)
static uint64_t pq_add_mul(const uint64_t c, const uint64_t a, const uint64_t b,
                           const uint64_t pq) {
  unsigned long long low, high;
  low = _mulx_u64(a, b, &high);
  const unsigned char carry = _addcarry_u64(0, low, c, &low);
  _addcarry_u64(carry, high, 0, &high);
  const __uint128_t res = static_cast<__uint128_t>(high) << 64 | low;
  return static_cast<uint64_t>(res % static_cast<__uint128_t>(pq));
}
#else
static uint64_t pq_add_mul(uint64_t c, uint64_t a, uint64_t b, uint64_t pq) {
  __int128_t res = c;
  res += (__int128_t)a * b;
  return res % pq;
}
#endif

uint64_t factorize_u64(const uint64_t pq) {
  // https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm
  // https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_tortoise_and_hare
  // https://maths-people.anu.edu.au/~brent/pd/rpb051i.pdf
  uint64_t y = Random::fast_uint64() % (pq - 1) + 1;
  const uint64_t c = Random::fast_uint64() % (pq - 1) + 1;
  uint64_t g = 1, r = 1, q = 1, x = 0, ys = 0;

  static constexpr uint64_t M = 128;

  while (g == 1) {
    x = y;
    for (uint64_t i = 0; i < r; i++) {
      y = pq_add_mul(c, y, y, pq);
    }
    uint64_t k = 0;
    while (k < r && g == 1) {
      ys = y;
      const uint64_t iterations = std::min(M, r - k);
      for (uint64_t i = 0; i < iterations; i++) {
        y = pq_add_mul(c, y, y, pq);
        const uint64_t diff = x > y ? x - y : y - x;
        q = pq_add_mul(0, q, diff, pq);
      }
      g = pq_gcd(q, pq);
      k += iterations;
    }
    r *= 2;
  }

  if (UNLIKELY(g == pq)) {
    g = 1;
    y = ys;
    while (g == 1) {
      y = pq_add_mul(c, y, y, pq);
      g = pq_gcd(x > y ? x - y : y - x, pq);
    }
  }

  if (LIKELY(g > 1 && g < pq)) {
    const uint64_t other = pq / g;
    return std::min(g, other);
  }

  return 1;
}

struct Provider {
  OSSL_FUNC_cipher_newctx_fn *newctx;
  OSSL_FUNC_cipher_freectx_fn *freectx;
  OSSL_FUNC_cipher_encrypt_init_fn *encrypt_init;
  OSSL_FUNC_cipher_decrypt_init_fn *decrypt_init;
  OSSL_FUNC_cipher_update_fn *update;
  OSSL_FUNC_cipher_set_ctx_params_fn *set_ctx_params;
};

static Provider *get_aes_256_ecb_provider() {
  thread_local Provider cache;
  thread_local bool initialized = false;

  if (LIKELY(initialized)) {
    return &cache;
  }

  OSSL_PROVIDER *prov = OSSL_PROVIDER_load(nullptr, "default");

  if (UNLIKELY(!prov)) {
    return nullptr;
  }

  int no_cache = 0;

  const OSSL_ALGORITHM *algorithm =
      OSSL_PROVIDER_query_operation(prov, OSSL_OP_CIPHER, &no_cache);

  const OSSL_DISPATCH *dispatch = nullptr;

  while (algorithm->algorithm_names) {
    if (strstr(algorithm->algorithm_names, "AES-256-ECB")) {
      dispatch = algorithm->implementation;
      break;
    }
    algorithm++;
  }

  if (UNLIKELY(!dispatch)) {
    return nullptr;
  }

  while (dispatch->function_id) {
    switch (dispatch->function_id) {
    case OSSL_FUNC_CIPHER_NEWCTX:
      cache.newctx =
          reinterpret_cast<OSSL_FUNC_cipher_newctx_fn *>(dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_FREECTX:
      cache.freectx =
          reinterpret_cast<OSSL_FUNC_cipher_freectx_fn *>(dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_ENCRYPT_INIT:
      cache.encrypt_init = reinterpret_cast<OSSL_FUNC_cipher_encrypt_init_fn *>(
          dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_DECRYPT_INIT:
      cache.decrypt_init = reinterpret_cast<OSSL_FUNC_cipher_decrypt_init_fn *>(
          dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_UPDATE:
      cache.update =
          reinterpret_cast<OSSL_FUNC_cipher_update_fn *>(dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_SET_CTX_PARAMS:
      cache.set_ctx_params =
          reinterpret_cast<OSSL_FUNC_cipher_set_ctx_params_fn *>(
              dispatch->function);
      break;
    default:
      break;
    }
    dispatch++;
  }

  OSSL_PROVIDER_unload(prov);

  initialized = true;
  return &cache;
}

template <bool IsEncrypt> class Evp {
  void *provctx_ = nullptr;
  const Provider *provfunc_ = nullptr;

public:
  Evp() {
    provfunc_ = get_aes_256_ecb_provider();
    if (provfunc_ && provfunc_->newctx)
      provctx_ = provfunc_->newctx(nullptr);
  }

  ~Evp() {
    if (provctx_ && provfunc_ && provfunc_->freectx)
      provfunc_->freectx(provctx_);
  }

  [[nodiscard]] bool init(const Slice key) const {
    if (!provctx_ || !provfunc_)
      return false;

    int padding_len = 0;

    const OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_PADDING, &padding_len),
        OSSL_PARAM_END};

    provfunc_->set_ctx_params(provctx_, params);

    int ret;

    if constexpr (IsEncrypt) {
      ret = provfunc_->encrypt_init(provctx_, key.ubegin(), key.size(), nullptr,
                                    0, nullptr);
    } else {
      ret = provfunc_->decrypt_init(provctx_, key.ubegin(), key.size(), nullptr,
                                    0, nullptr);
    }
    return ret == 1;
  }

  [[nodiscard]] bool update(const uint8_t *src, uint8_t *dst,
                            const size_t dst_len) const {
    size_t out;
    return provfunc_->update(provctx_, dst, &out, dst_len, src, dst_len) == 1 &&
           out == dst_len;
  }
};

template <bool IsEncrypt>
auto aes_ige_crypt_impl(const Slice key, const MutableSlice iv,
                        const Slice from, const MutableSlice to) -> bool {
  // https://github.com/tdlib/td/blob/5d1fe744712fbc752840176135b39e82086f5578/tdutils/td/utils/crypto.cpp#L487
  const uint8_t *in = from.ubegin();
  uint8_t *out = to.ubegin();
  const size_t len = from.size();
  const size_t num_blocks = len / 16;

  SimdBlock128 encrypted_iv(iv.ubegin());
  SimdBlock128 plaintext_iv(iv.ubegin() + 16);

  const Evp<IsEncrypt> evp;
  if (UNLIKELY(!evp.init(key)))
    return false;

  auto process_block = [&](const uint8_t *current_in,
                           uint8_t *current_out) -> bool {
    const SimdBlock128 in_block(current_in);
    SimdBlock128 temp_block;

    if constexpr (IsEncrypt) {
      temp_block = in_block ^ encrypted_iv;
    } else {
      temp_block = in_block ^ plaintext_iv;
    }

    if (UNLIKELY(!evp.update(temp_block.raw(), current_out, 16)))
      return false;

    SimdBlock128 out_block(current_out);
    if constexpr (IsEncrypt) {
      out_block = out_block ^ plaintext_iv;
    } else {
      out_block = out_block ^ encrypted_iv;
    }
    out_block.store(current_out);

    if constexpr (IsEncrypt) {
      plaintext_iv = in_block;
      encrypted_iv = out_block;
    } else {
      encrypted_iv = in_block;
      plaintext_iv = out_block;
    }
    return true;
  };

  size_t i = 0;

  for (; i + 4 <= num_blocks; i += 4) {
    const size_t offset = i << 4;
    const size_t prefetch_offset = offset + 64;

    PREFETCH_WRITE_NTA(out + prefetch_offset);
    PREFETCH_READ_NTA(in + prefetch_offset);

    if (UNLIKELY(!process_block(in + offset, out + offset)))
      return false;
    if (UNLIKELY(!process_block(in + offset + 16, out + offset + 16)))
      return false;
    if (UNLIKELY(!process_block(in + offset + 32, out + offset + 32)))
      return false;
    if (UNLIKELY(!process_block(in + offset + 48, out + offset + 48)))
      return false;
  }

  for (; i < num_blocks; i++) {
    const size_t offset = i << 4;
    if (UNLIKELY(!process_block(in + offset, out + offset)))
      return false;
  }

  encrypted_iv.store(iv.ubegin());
  plaintext_iv.store(iv.ubegin() + 16);
  return true;
}

bool aes_ige_crypt(const Slice key, const MutableSlice iv, const bool encrypt,
                   const Slice from, const MutableSlice to) {
  if (encrypt) {
    return aes_ige_crypt_impl<true>(key, iv, from, to);
  } else {
    return aes_ige_crypt_impl<false>(key, iv, from, to);
  }
}

static PyObject *py_secure_random([[maybe_unused]] PyObject *self,
                                  PyObject *args) {
  int nbytes;
  if (UNLIKELY(!PyArg_ParseTuple(args, "i", &nbytes)))
    return nullptr;
  if (UNLIKELY(nbytes < 0)) {
    PyErr_SetString(PyExc_ValueError, "nbytes must be non-negative");
    return nullptr;
  }

  PyObject *result = PyBytes_FromStringAndSize(nullptr, nbytes);
  if (UNLIKELY(!result)) {
    return nullptr;
  }

  char *buffer = PyBytes_AS_STRING(result);

  int is_success;
  Py_BEGIN_ALLOW_THREADS;
  is_success = RAND_bytes(reinterpret_cast<uint8_t *>(buffer), nbytes);
  Py_END_ALLOW_THREADS;

  if (UNLIKELY(is_success != 1)) {
    set_openssl_error("RAND_bytes failed");
    Py_DECREF(result);
    return nullptr;
  }

  return result;
}

static PyObject *py_factorize_pq([[maybe_unused]] PyObject *self,
                                 PyObject *args) {
  PyObject *pq_py;
  if (UNLIKELY(!PyArg_ParseTuple(args, "O!", &PyLong_Type, &pq_py)))
    return nullptr;

  if (UNLIKELY(_PyLong_NumBits(pq_py) > 64)) {
    PyErr_SetString(PyExc_ValueError,
                    "Number is larger than 64 bits and not supported.");
    return nullptr;
  }

  const uint64_t pq = PyLong_AsUnsignedLongLong(pq_py);
  if (UNLIKELY(PyErr_Occurred())) {
    return nullptr;
  }

  uint64_t p;

  Py_BEGIN_ALLOW_THREADS;
  unsigned int retries = 0;
retry:
  p = factorize_u64(pq);
  if (UNLIKELY(p <= 1)) {
    if (LIKELY(retries < 3)) {
      retries += 1;
      // This is a probabilistic algorithm.
      goto retry;
    }
  }
  Py_END_ALLOW_THREADS;

  if (UNLIKELY(p <= 1 || pq % p != 0)) {
    PyErr_SetString(PyExc_ValueError, "Factorization failed.");
    return nullptr;
  }
  const uint64_t q = pq / p;

  PyObject *p_py = PyLong_FromUnsignedLongLong(p);
  PyObject *q_py = PyLong_FromUnsignedLongLong(q);

  if (UNLIKELY(!p_py || !q_py)) {
    Py_XDECREF(p_py);
    Py_XDECREF(q_py);
    return nullptr;
  }

  return Py_BuildValue("(NN)", p_py, q_py);
}

static PyObject *py_crypt_aes_ige([[maybe_unused]] PyObject *self,
                                  PyObject *args, const bool encrypt) {
  Py_buffer data, key, iv;
  if (UNLIKELY(!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv)))
    return nullptr;

  PyBufferGuard data_guard(data);
  PyBufferGuard key_guard(key);
  PyBufferGuard iv_guard(iv);

  if (UNLIKELY(key.len != 32 || iv.len != 32 || data.len % 16 != 0)) {
    PyErr_SetString(PyExc_ValueError,
                    "Key/IV must be 32 bytes and data length a multiple of 16");
    return nullptr;
  }

  PyObject *result_bytes = PyBytes_FromStringAndSize(nullptr, data.len);
  PyObject *next_iv_bytes = PyBytes_FromStringAndSize(nullptr, iv.len);

  if (UNLIKELY(!result_bytes || !next_iv_bytes)) {
    Py_XDECREF(result_bytes);
    Py_XDECREF(next_iv_bytes);
    return PyErr_NoMemory();
  }

  const auto out_data_ptr =
      reinterpret_cast<uint8_t *>(PyBytes_AS_STRING(result_bytes));
  auto *next_iv_ptr =
      reinterpret_cast<uint8_t *>(PyBytes_AS_STRING(next_iv_bytes));

  memcpy(next_iv_ptr, iv.buf, iv.len);

  bool success;
  Py_BEGIN_ALLOW_THREADS;
  success = aes_ige_crypt(
      Slice(key.buf, key.len), MutableSlice(next_iv_ptr, iv.len), encrypt,
      Slice(data.buf, data.len), MutableSlice(out_data_ptr, data.len));
  Py_END_ALLOW_THREADS;

  if (UNLIKELY(!success)) {
    set_openssl_error("AES-IGE operation failed");
    Py_DECREF(result_bytes);
    Py_DECREF(next_iv_bytes);
    return nullptr;
  }

  return Py_BuildValue("(NN)", result_bytes, next_iv_bytes);
}

static PyObject *py_encrypt_aes_ige(PyObject *self, PyObject *args) {
  return py_crypt_aes_ige(self, args, true);
}

static PyObject *py_decrypt_aes_ige(PyObject *self, PyObject *args) {
  return py_crypt_aes_ige(self, args, false);
}

static PyMethodDef CryptoMethods[] = {
    {"secure_random", py_secure_random, METH_VARARGS,
     "Generate cryptographically secure random bytes."},
    {"factorize_pq", py_factorize_pq, METH_VARARGS,
     "Factorize a 64-bit composite number pq into p and q."},
    {"encrypt_aes_ige", py_encrypt_aes_ige, METH_VARARGS,
     "Encrypt data using AES-256-IGE. Returns (ciphertext, next_iv)."},
    {"decrypt_aes_ige", py_decrypt_aes_ige, METH_VARARGS,
     "Decrypt data using AES-256-IGE. Returns (plaintext, next_iv)."},
    {nullptr, nullptr, 0, nullptr}};

static PyModuleDef crypto_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "_impl",
    .m_doc = "Low-level crypto functions using OpenSSL 3.",
    .m_size = -1,
    .m_methods = CryptoMethods,
    .m_slots = nullptr,
    .m_traverse = nullptr,
    .m_clear = nullptr,
    .m_free = nullptr};

PyMODINIT_FUNC PyInit__impl(void) { // NOLINT(*-reserved-identifier)
  Random::seed();
  return PyModule_Create(&crypto_module);
}
