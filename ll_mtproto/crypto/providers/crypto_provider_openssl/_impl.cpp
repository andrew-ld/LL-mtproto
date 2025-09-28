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
#include <utility>

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

namespace detail {
#if defined(HAS_EMMINTRIN)
struct alignas(16) SimdBlock128SSE2 {
  __m128i value;

  SimdBlock128SSE2() = default;

  ALWAYS_INLINE explicit SimdBlock128SSE2(const void *p)
      : value(_mm_load_si128(static_cast<const __m128i *>(p))) {}

  ALWAYS_INLINE void store(void *p) const {
    _mm_store_si128(static_cast<__m128i *>(p), value);
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

  MutableSlice(void *data, const size_t size)
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
  if (!a || !b) [[unlikely]]
    return a | b;

  const unsigned long a_tz = COUNT_TRAILING_ZEROS(a);
  const unsigned long b_tz = COUNT_TRAILING_ZEROS(b);
  const unsigned long common_factor_pow2 = std::min(a_tz, b_tz);

  a >>= a_tz;
  b >>= b_tz;

  while (a != b) {
    const uint64_t mask = -static_cast<uint64_t>(a > b);
    const uint64_t diff = a - b;

    const uint64_t new_a = (diff & mask) | (a & ~mask);
    const uint64_t new_b = ((-diff) & ~mask) | (b & mask);

    a = new_a >> (COUNT_TRAILING_ZEROS(new_a) & mask);
    b = new_b >> (COUNT_TRAILING_ZEROS(new_b) & ~mask);
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
  __uint128_t res = c;
  res += static_cast<__uint128_t>(a) * b;
  return static_cast<uint64_t>(res % pq);
}
#endif

static uint64_t abs_diff_u64(const uint64_t x, const uint64_t y) {
  const uint64_t diff = x - y;
  const uint64_t mask = -static_cast<uint64_t>(y > x);
  return (diff ^ mask) - mask;
}

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

      uint64_t i = 0;

      for (; i + 3 < iterations; i += 4) {
        y = pq_add_mul(c, y, y, pq);
        const uint64_t d1 = abs_diff_u64(x, y);
        y = pq_add_mul(c, y, y, pq);
        const uint64_t d2 = abs_diff_u64(x, y);
        y = pq_add_mul(c, y, y, pq);
        const uint64_t d3 = abs_diff_u64(x, y);
        y = pq_add_mul(c, y, y, pq);
        const uint64_t d4 = abs_diff_u64(x, y);

        const uint64_t m1 = pq_add_mul(0, d1, d2, pq);
        const uint64_t m2 = pq_add_mul(0, d3, d4, pq);
        const uint64_t diff_product = pq_add_mul(0, m1, m2, pq);

        q = pq_add_mul(0, q, diff_product, pq);
      }

      for (; i < iterations; i++) {
        y = pq_add_mul(c, y, y, pq);
        const uint64_t diff = abs_diff_u64(x, y);
        q = pq_add_mul(0, q, diff, pq);
      }

      g = pq_gcd(q, pq);
      k += iterations;
    }
    r *= 2;
  }

  if (g == pq) [[unlikely]] {
    g = 1;
    y = ys;
    while (g == 1) {
      y = pq_add_mul(c, y, y, pq);
      g = pq_gcd(abs_diff_u64(x, y), pq);
    }
  }

  if (g > 1 && g < pq) [[likely]] {
    const uint64_t other = pq / g;
    return std::min(g, other);
  }

  return 1;
}

struct alignas(16) Provider {
  OSSL_FUNC_cipher_update_fn *update;
  OSSL_FUNC_cipher_newctx_fn *newctx;
  OSSL_FUNC_cipher_freectx_fn *freectx;
  OSSL_FUNC_cipher_encrypt_init_fn *encrypt_init;
  OSSL_FUNC_cipher_decrypt_init_fn *decrypt_init;
  OSSL_FUNC_cipher_set_ctx_params_fn *set_ctx_params;
};

static Py_tss_t provider_cache_key{};

static Provider *get_aes_256_ecb_provider() {
  if (const auto provider =
          static_cast<Provider *>(PyThread_tss_get(&provider_cache_key));
      provider != nullptr) [[likely]] {
    return provider;
  }

  OSSL_PROVIDER *prov = OSSL_PROVIDER_load(nullptr, "default");

  if (!prov) [[unlikely]] {
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

  if (!dispatch) [[unlikely]] {
    OSSL_PROVIDER_unload(prov);
    return nullptr;
  }

  auto *provider_cache = new Provider();

  if (PyThread_tss_set(&provider_cache_key, provider_cache) != 0) [[unlikely]] {
    delete provider_cache;
    return nullptr;
  }

  while (dispatch->function_id) {
    switch (dispatch->function_id) {
    case OSSL_FUNC_CIPHER_NEWCTX:
      provider_cache->newctx =
          reinterpret_cast<OSSL_FUNC_cipher_newctx_fn *>(dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_FREECTX:
      provider_cache->freectx =
          reinterpret_cast<OSSL_FUNC_cipher_freectx_fn *>(dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_ENCRYPT_INIT:
      provider_cache->encrypt_init =
          reinterpret_cast<OSSL_FUNC_cipher_encrypt_init_fn *>(
              dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_DECRYPT_INIT:
      provider_cache->decrypt_init =
          reinterpret_cast<OSSL_FUNC_cipher_decrypt_init_fn *>(
              dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_UPDATE:
      provider_cache->update =
          reinterpret_cast<OSSL_FUNC_cipher_update_fn *>(dispatch->function);
      break;
    case OSSL_FUNC_CIPHER_SET_CTX_PARAMS:
      provider_cache->set_ctx_params =
          reinterpret_cast<OSSL_FUNC_cipher_set_ctx_params_fn *>(
              dispatch->function);
      break;
    default:
      break;
    }
    dispatch++;
  }

  OSSL_PROVIDER_unload(prov);

  return provider_cache;
}

template <bool IsEncrypt> class Evp {
  void *provctx_ = nullptr;
  const Provider *provfunc_ = nullptr;

public:
  Evp() {
    provfunc_ = get_aes_256_ecb_provider();
    if (provfunc_ && provfunc_->newctx) [[likely]]
      provctx_ = provfunc_->newctx(nullptr);
  }

  ~Evp() {
    if (provctx_ && provfunc_ && provfunc_->freectx) [[likely]]
      provfunc_->freectx(provctx_);
  }

  [[nodiscard]] bool init(const Slice key) const {
    if (!provctx_ || !provfunc_ || !provfunc_->set_ctx_params ||
        !provfunc_->encrypt_init || !provfunc_->decrypt_init) [[unlikely]]
      return false;

    int padding_len = 0;

    const OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_PADDING, &padding_len),
        OSSL_PARAM_END};

    provfunc_->set_ctx_params(provctx_, params);

    if (padding_len != 0) [[unlikely]] {
      return false;
    }

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
    if (!provctx_ || !provfunc_ || !provfunc_->update) [[unlikely]]
      return false;

    size_t out;

    const int res =
        provfunc_->update(provctx_, dst, &out, dst_len, src, dst_len);

    return res == 1 && out == dst_len;
  }
};

struct IgeState {
  SimdBlock128 encrypted_iv;
  SimdBlock128 plaintext_iv;
};

template <bool IsEncrypt>
static ALWAYS_INLINE bool
process_aes_block_in_place(const Evp<IsEncrypt> &evp,
                           const SimdBlock128 &in_block, IgeState &state,
                           SimdBlock128 &out_block) {
  SimdBlock128 temp_block;
  if constexpr (IsEncrypt) {
    temp_block = in_block ^ state.encrypted_iv;
  } else {
    temp_block = in_block ^ state.plaintext_iv;
  }

  alignas(16) uint8_t out_buffer[16];
  if (!evp.update(temp_block.raw(), out_buffer, 16)) [[unlikely]] {
    return false;
  }

  SimdBlock128 encrypted_block(out_buffer);
  if constexpr (IsEncrypt) {
    out_block = encrypted_block ^ state.plaintext_iv;
  } else {
    out_block = encrypted_block ^ state.encrypted_iv;
  }

  if constexpr (IsEncrypt) {
    state.plaintext_iv = in_block;
    state.encrypted_iv = out_block;
  } else {
    state.encrypted_iv = in_block;
    state.plaintext_iv = out_block;
  }

  return true;
}

template <bool IsEncrypt>
static std::pair<IgeState, bool>
aes_ige_loop_impl(const Evp<IsEncrypt> &evp, IgeState current_state,
                  const Slice from, const MutableSlice to) {
  const uint8_t *in_ptr = from.ubegin();
  uint8_t *out_ptr = to.ubegin();
  const size_t num_blocks = from.size() / 16;
  const uint8_t *const in_end = in_ptr + from.size();

  const size_t unrolled_block_count = (num_blocks / 4) * 4;
  const uint8_t *const unroll_end = from.ubegin() + unrolled_block_count * 16;

  while (in_ptr < unroll_end) {
    const SimdBlock128 in_block1(in_ptr);
    const SimdBlock128 in_block2(in_ptr + 16);
    const SimdBlock128 in_block3(in_ptr + 32);
    const SimdBlock128 in_block4(in_ptr + 48);

    SimdBlock128 out_block1{}, out_block2{}, out_block3{}, out_block4{};

    bool success = true;

    success &= process_aes_block_in_place<IsEncrypt>(evp, in_block1,
                                                     current_state, out_block1);
    success &= process_aes_block_in_place<IsEncrypt>(evp, in_block2,
                                                     current_state, out_block2);
    success &= process_aes_block_in_place<IsEncrypt>(evp, in_block3,
                                                     current_state, out_block3);
    success &= process_aes_block_in_place<IsEncrypt>(evp, in_block4,
                                                     current_state, out_block4);

    if (!success) [[unlikely]] {
      return {current_state, false};
    }

    out_block1.store(out_ptr);
    out_block2.store(out_ptr + 16);
    out_block3.store(out_ptr + 32);
    out_block4.store(out_ptr + 48);

    in_ptr += 64;
    out_ptr += 64;
  }

  while (in_ptr < in_end) {
    const SimdBlock128 in_block(in_ptr);
    SimdBlock128 out_block;

    if (!process_aes_block_in_place<IsEncrypt>(evp, in_block, current_state,
                                               out_block)) [[unlikely]] {
      return {current_state, false};
    }

    out_block.store(out_ptr);

    in_ptr += 16;
    out_ptr += 16;
  }

  return {current_state, true};
}

template <bool IsEncrypt>
auto aes_ige_crypt_impl(const Slice key, const MutableSlice iv,
                        const Slice from, const MutableSlice to) -> bool {
  IgeState initial_state{SimdBlock128(iv.ubegin()),
                         SimdBlock128(iv.ubegin() + 16)};

  const Evp<IsEncrypt> evp;
  if (!evp.init(key)) [[unlikely]]
    return false;

  auto [final_state, success] =
      aes_ige_loop_impl<IsEncrypt>(evp, initial_state, from, to);

  if (!success) [[unlikely]] {
    return false;
  }

  final_state.encrypted_iv.store(iv.ubegin());
  final_state.plaintext_iv.store(iv.ubegin() + 16);

  return true;
}

static PyObject *py_secure_random([[maybe_unused]] PyObject *self,
                                  PyObject *args) {
  int nbytes;
  if (!PyArg_ParseTuple(args, "i", &nbytes)) [[unlikely]]
    return nullptr;
  if (nbytes < 0) [[unlikely]] {
    PyErr_SetString(PyExc_ValueError, "nbytes must be non-negative");
    return nullptr;
  }

  PyObject *result = PyBytes_FromStringAndSize(nullptr, nbytes);
  if (!result) [[unlikely]] {
    return nullptr;
  }

  char *buffer = PyBytes_AS_STRING(result);

  int is_success;
  Py_BEGIN_ALLOW_THREADS;
  is_success = RAND_bytes(reinterpret_cast<uint8_t *>(buffer), nbytes);
  Py_END_ALLOW_THREADS;

  if (is_success != 1) [[unlikely]] {
    set_openssl_error("RAND_bytes failed");
    Py_DECREF(result);
    return nullptr;
  }

  return result;
}

static PyObject *py_factorize_pq([[maybe_unused]] PyObject *self,
                                 PyObject *args) {
  PyObject *pq_py;
  if (!PyArg_ParseTuple(args, "O!", &PyLong_Type, &pq_py)) [[unlikely]]
    return nullptr;

  if (_PyLong_NumBits(pq_py) > 64) [[unlikely]] {
    PyErr_SetString(PyExc_ValueError,
                    "Number is larger than 64 bits and not supported.");
    return nullptr;
  }

  const uint64_t pq = PyLong_AsUnsignedLongLong(pq_py);
  if (PyErr_Occurred()) [[unlikely]] {
    return nullptr;
  }

  uint64_t p;

  Py_BEGIN_ALLOW_THREADS;
  unsigned int retries = 0;
retry:
  p = factorize_u64(pq);
  if (p <= 1) [[unlikely]] {
    if (retries < 3) [[likely]] {
      retries += 1;
      // This is a probabilistic algorithm.
      goto retry;
    }
  }
  Py_END_ALLOW_THREADS;

  if (p <= 1 || pq % p != 0) [[unlikely]] {
    PyErr_SetString(PyExc_ValueError, "Factorization failed.");
    return nullptr;
  }
  const uint64_t q = pq / p;

  PyObject *p_py = PyLong_FromUnsignedLongLong(p);
  PyObject *q_py = PyLong_FromUnsignedLongLong(q);

  if (!p_py || !q_py) [[unlikely]] {
    Py_XDECREF(p_py);
    Py_XDECREF(q_py);
    return nullptr;
  }

  return Py_BuildValue("(NN)", p_py, q_py);
}

template <bool IsEncrypt>
static PyObject *py_crypt_aes_ige([[maybe_unused]] PyObject *self,
                                  PyObject *args) {
  Py_buffer data, key, iv;
  if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv)) [[unlikely]]
    return nullptr;

  PyBufferGuard data_guard(data);
  PyBufferGuard key_guard(key);
  PyBufferGuard iv_guard(iv);

  if (key.len != 32 || iv.len != 32 || data.len % 16 != 0) [[unlikely]] {
    PyErr_SetString(PyExc_ValueError,
                    "Key/IV must be 32 bytes and data length a multiple of 16");
    return nullptr;
  }

  PyObject *result_bytes = PyBytes_FromStringAndSize(nullptr, data.len);

  if (!result_bytes) [[unlikely]] {
    Py_XDECREF(result_bytes);
    return PyErr_NoMemory();
  }

  const auto out_data_ptr =
      reinterpret_cast<uint8_t *>(PyBytes_AS_STRING(result_bytes));

  alignas(16) uint8_t next_iv_buffer[32];
  memcpy(next_iv_buffer, iv.buf, iv.len);

  bool success;
  Py_BEGIN_ALLOW_THREADS;
  success = aes_ige_crypt_impl<IsEncrypt>(
      Slice(key.buf, key.len), MutableSlice(next_iv_buffer, iv.len),
      Slice(data.buf, data.len), MutableSlice(out_data_ptr, data.len));
  Py_END_ALLOW_THREADS;

  if (!success) [[unlikely]] {
    set_openssl_error("AES-IGE operation failed");
    Py_DECREF(result_bytes);
    return nullptr;
  }

  PyObject *next_iv_bytes = PyBytes_FromStringAndSize(
      reinterpret_cast<char *>(next_iv_buffer), iv.len);

  if (!next_iv_bytes) [[unlikely]] {
    Py_DECREF(result_bytes);
    return PyErr_NoMemory();
  }

  return Py_BuildValue("(NN)", result_bytes, next_iv_bytes);
}

static PyObject *py_encrypt_aes_ige(PyObject *self, PyObject *args) {
  return py_crypt_aes_ige<true>(self, args);
}

static PyObject *py_decrypt_aes_ige(PyObject *self, PyObject *args) {
  return py_crypt_aes_ige<false>(self, args);
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

  if (PyThread_tss_create(&provider_cache_key) != 0) {
    return PyErr_NoMemory();
  }

  return PyModule_Create(&crypto_module);
}
