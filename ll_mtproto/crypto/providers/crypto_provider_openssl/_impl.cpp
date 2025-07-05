// https://github.com/tdlib/td/blob/5d1fe744712fbc752840176135b39e82086f5578/tdutils/td/utils/crypto.cpp
// https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm#Variants

#include <Python.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

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

struct Slice {
  const uint8_t *data_ = nullptr;
  size_t size_ = 0;
  Slice(const void *data, size_t size)
      : data_(static_cast<const uint8_t *>(data)), size_(size) {}
  const uint8_t *ubegin() const { return data_; }
  size_t size() const { return size_; }
};

struct MutableSlice {
  uint8_t *data_ = nullptr;
  size_t size_ = 0;
  MutableSlice(void *data, size_t size)
      : data_(static_cast<uint8_t *>(data)), size_(size) {}
  uint8_t *ubegin() { return data_; }
  size_t size() const { return size_; }
  Slice as_slice() const { return Slice(data_, size_); }
};

namespace Random {
thread_local static uint64_t state = 0xDEADBEEFCAFEBABEULL;

uint64_t fast_uint64() {
  uint64_t x = state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  state = x;
  return x * 0x2545F4914F6CDD1DULL;
}
}

static uint64_t pq_gcd(uint64_t a, uint64_t b) {
  while (b) {
    a %= b;
    std::swap(a, b);
  }
  return a;
}

static uint64_t pq_add_mul(uint64_t c, uint64_t a, uint64_t b, uint64_t pq) {
  __int128_t res = c;
  res += (__int128_t)a * b;
  return res % pq;
}

uint64_t factorize_u64(uint64_t pq) {
  if (pq <= 1)
    return 1;
  if (pq % 2 == 0)
    return 2;
  if (pq % 3 == 0)
    return 3;
  if (pq % 5 == 0)
    return 5;

  uint64_t root = sqrt(pq);
  if (root * root == pq)
    return root;

  uint64_t y = Random::fast_uint64() % (pq - 1) + 1;
  uint64_t c = Random::fast_uint64() % (pq - 1) + 1;
  uint64_t m = Random::fast_uint64() % (pq - 1) + 1;
  uint64_t g = 1, r = 1, q = 1, x = 0, ys = 0;

  while (g == 1) {
    x = y;
    for (uint64_t i = 0; i < r; i++) {
      y = pq_add_mul(c, y, y, pq);
    }
    uint64_t k = 0;
    while (k < r && g == 1) {
      ys = y;
      for (uint64_t i = 0; i < std::min(m, r - k); i++) {
        y = pq_add_mul(c, y, y, pq);
        q = pq_add_mul(0, q, (x > y ? x - y : y - x), pq);
      }
      g = pq_gcd(q, pq);
      k += m;
    }
    r *= 2;
  }

  if (g == pq) {
    y = ys;
    while (true) {
      y = pq_add_mul(c, y, y, pq);
      g = pq_gcd((x > y ? x - y : y - x), pq);
      if (g > 1)
        break;
    }
  }

  if (g > 1 && g < pq) {
    uint64_t other = pq / g;
    return std::min(g, other);
  }

  return 1;
}

struct AesBlock {
  uint64_t hi, lo;
  void load(const uint8_t *from) { memcpy(this, from, sizeof(*this)); }
  void store(uint8_t *to) const { memcpy(to, this, sizeof(*this)); }
  uint8_t *raw() { return reinterpret_cast<uint8_t *>(this); }
  const uint8_t *raw() const { return reinterpret_cast<const uint8_t *>(this); }
  void operator^=(const AesBlock &b) {
    hi ^= b.hi;
    lo ^= b.lo;
  }
};

class Evp {
  EVP_CIPHER_CTX *ctx_ = nullptr;

public:
  Evp() { ctx_ = EVP_CIPHER_CTX_new(); }
  ~Evp() {
    if (ctx_)
      EVP_CIPHER_CTX_free(ctx_);
  }
  bool is_valid() const { return ctx_ != nullptr; }

  bool init(bool is_encrypt, const EVP_CIPHER *cipher, Slice key) {
    if (EVP_CipherInit_ex(ctx_, cipher, nullptr, key.ubegin(), nullptr,
                          is_encrypt ? 1 : 0) != 1) {
      set_openssl_error("EVP_CipherInit_ex failed");
      return false;
    }
    EVP_CIPHER_CTX_set_padding(ctx_, 0);
    return true;
  }

  bool update(const uint8_t *src, uint8_t *dst, int size) {
    int len;
    if (EVP_CipherUpdate(ctx_, dst, &len, src, size) != 1 || len != size) {
      set_openssl_error("EVP_CipherUpdate failed");
      return false;
    }
    return true;
  }
};

struct EvpCipherDeleter {
  void operator()(EVP_CIPHER *p) { EVP_CIPHER_free(p); }
};
using EvpCipherPtr = std::unique_ptr<EVP_CIPHER, EvpCipherDeleter>;

static const EVP_CIPHER *get_ecb_cipher() {
  thread_local static EvpCipherPtr ecb_cipher;
  if (!ecb_cipher) {
    ecb_cipher.reset(EVP_CIPHER_fetch(nullptr, "AES-256-ECB", nullptr));
  }
  if (!ecb_cipher) {
    set_openssl_error("EVP_CIPHER_fetch failed for AES-256-ECB");
    return nullptr;
  }
  return ecb_cipher.get();
}

bool aes_ige_crypt(Slice key, MutableSlice iv, bool encrypt, Slice from,
                   MutableSlice to) {
  const uint8_t *in = from.ubegin();
  uint8_t *out = to.ubegin();
  size_t len = from.size();

  AesBlock encrypted_iv, plaintext_iv;
  encrypted_iv.load(iv.ubegin());
  plaintext_iv.load(iv.ubegin() + 16);

  Evp evp;
  const EVP_CIPHER *cipher = get_ecb_cipher();
  if (!cipher || !evp.is_valid())
    return false;

  if (!evp.init(encrypt, cipher, key))
    return false;

  if (encrypt) {
    for (size_t i = 0; i < len; i += 16) {
      AesBlock block;
      block.load(in + i);
      block ^= encrypted_iv;

      if (!evp.update(block.raw(), block.raw(), 16))
        return false;

      block ^= plaintext_iv;
      block.store(out + i);

      plaintext_iv.load(in + i);
      encrypted_iv = block;
    }
  } else {
    for (size_t i = 0; i < len; i += 16) {
      AesBlock block;
      block.load(in + i);
      block ^= plaintext_iv;

      if (!evp.update(block.raw(), block.raw(), 16))
        return false;

      block ^= encrypted_iv;
      block.store(out + i);

      encrypted_iv.load(in + i);
      plaintext_iv = block;
    }
  }

  encrypted_iv.store(iv.ubegin());
  plaintext_iv.store(iv.ubegin() + 16);
  return true;
}

static PyObject *py_secure_random(PyObject *self, PyObject *args) {
  (void)self;
  int nbytes;
  if (!PyArg_ParseTuple(args, "i", &nbytes))
    return NULL;
  if (nbytes < 0) {
    PyErr_SetString(PyExc_ValueError, "nbytes must be non-negative");
    return NULL;
  }
  std::vector<uint8_t> buffer(nbytes);
  if (RAND_bytes(buffer.data(), nbytes) != 1) {
    set_openssl_error("RAND_bytes failed");
    return NULL;
  }
  return PyBytes_FromStringAndSize((char *)buffer.data(), nbytes);
}

static PyObject *py_factorize_pq(PyObject *self, PyObject *args) {
  (void)self;
  PyObject *pq_py;
  if (!PyArg_ParseTuple(args, "O!", &PyLong_Type, &pq_py))
    return NULL;

  if (_PyLong_NumBits(pq_py) > 64) {
    PyErr_SetString(PyExc_ValueError,
                    "Number is larger than 64 bits and not supported.");
    return NULL;
  }

  uint64_t pq = PyLong_AsUnsignedLongLong(pq_py);
  if (PyErr_Occurred()) {
    return NULL;
  }

  uint64_t p = factorize_u64(pq);

  if (p <= 1 || pq % p != 0) {
    PyErr_SetString(PyExc_ValueError, "Factorization failed.");
    return NULL;
  }
  uint64_t q = pq / p;

  PyObject *p_py = PyLong_FromUnsignedLongLong(p);
  PyObject *q_py = PyLong_FromUnsignedLongLong(q);

  if (!p_py || !q_py) {
    Py_XDECREF(p_py);
    Py_XDECREF(q_py);
    return NULL;
  }

  return Py_BuildValue("(NN)", p_py, q_py);
}

static PyObject *py_crypt_aes_ige(PyObject *self, PyObject *args,
                                  bool encrypt) {
  (void)self;
  Py_buffer data, key, iv;
  if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
    return NULL;

  auto guard = std::shared_ptr<void>(nullptr, [&](void *) {
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);
  });

  if (key.len != 32 || iv.len != 32 || data.len % 16 != 0) {
    PyErr_SetString(PyExc_ValueError,
                    "Key/IV must be 32 bytes and data length a multiple of 16");
    return NULL;
  }

  std::vector<uint8_t> out_data(data.len);
  std::vector<uint8_t> next_iv(iv.len);
  memcpy(next_iv.data(), iv.buf, iv.len);

  if (!aes_ige_crypt(Slice(key.buf, key.len),
                     MutableSlice(next_iv.data(), next_iv.size()), encrypt,
                     Slice(data.buf, data.len),
                     MutableSlice(out_data.data(), out_data.size()))) {
    return NULL;
  }

  PyObject *result_bytes =
      PyBytes_FromStringAndSize((char *)out_data.data(), out_data.size());
  PyObject *next_iv_bytes =
      PyBytes_FromStringAndSize((char *)next_iv.data(), next_iv.size());
  if (!result_bytes || !next_iv_bytes) {
    Py_XDECREF(result_bytes);
    Py_XDECREF(next_iv_bytes);
    return NULL;
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
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef crypto_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "_impl",
    .m_doc = "Low-level crypto functions using OpenSSL 3.",
    .m_size = -1,
    .m_methods = CryptoMethods,
    .m_slots = NULL,
    .m_traverse = NULL,
    .m_clear = NULL,
    .m_free = NULL};

PyMODINIT_FUNC PyInit__impl(void) { return PyModule_Create(&crypto_module); }
