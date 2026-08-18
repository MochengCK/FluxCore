/***
 * This software was written by Nils Maier. No copyright is claimed, and the
 * software is hereby placed in the public domain.
 *
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void in your jurisdiction, then the
 * software is Copyright 2004,2013 Nils Maier and it is hereby released to the
 * general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef BIGNUM_H
#define BIGNUM_H

#include <cstring>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <stdint.h>

#include "a2functional.h"

namespace bignum {

template <size_t dim> class ulong {

public:
  typedef char char_t;
  typedef std::make_unsigned<char_t>::type uchar_t;

private:
  std::unique_ptr<uchar_t[]> buf_;

public:
  inline ulong() : buf_(aria2::make_unique<uchar_t[]>(dim)) {}
  inline ulong(size_t t) : buf_(aria2::make_unique<uchar_t[]>(dim))
  {
    memcpy(buf_.get(), (uchar_t*)&t, sizeof(t));
  }
  inline ulong(const ulong<dim>& rhs) : buf_(aria2::make_unique<uchar_t[]>(dim))
  {
    memcpy(buf_.get(), rhs.buf_.get(), dim);
  }
  explicit inline ulong(const uchar_t* data, size_t size)
      : buf_(aria2::make_unique<uchar_t[]>(dim))
  {
    if (size > dim) {
      throw std::bad_alloc();
    }
    memcpy(buf_.get(), data, size);
  }

  virtual ~ulong() = default;

  ulong<dim>& operator=(const ulong<dim>& rhs)
  {
    memcpy(buf_.get(), rhs.buf_.get(), dim);
    return *this;
  }

  bool operator==(const ulong<dim>& rhs) const
  {
    return memcmp(buf_.get(), rhs.buf_.get(), dim) == 0;
  }
  bool operator!=(const ulong<dim>& rhs) const
  {
    return memcmp(buf_.get(), rhs.buf_.get(), dim) != 0;
  }
  bool operator>(const ulong<dim>& rhs) const
  {
    const auto b1 = buf_.get();
    const auto b2 = rhs.buf_.get();
    for (ssize_t i = dim - 1; i >= 0; --i) {
      for (ssize_t j = 1; j >= 0; --j) {
        uchar_t t = ((uchar_t)(b1[i] << 4 * (1 - j))) >> 4;
        uchar_t r = ((uchar_t)(b2[i] << 4 * (1 - j))) >> 4;
        if (t != r) {
          return t > r;
        }
      }
    }
    return false;
  }
  bool operator>=(const ulong<dim>& rhs) const
  {
    return *this == rhs || *this > rhs;
  }
  bool operator<(const ulong<dim>& rhs) const { return !(*this >= rhs); }
  bool operator<=(const ulong<dim>& rhs) const
  {
    return *this == rhs || *this < rhs;
  }

  ulong<dim> operator+(const ulong<dim>& rhs) const
  {
    ulong<dim> rv;
    const auto b1 = buf_.get();
    const auto b2 = rhs.buf_.get();
    const auto rb = rv.buf_.get();
    bool base = false;
    for (size_t i = 0; i < dim; ++i) {
      for (ssize_t j = 0; j < 2; ++j) {
        uchar_t t = ((uchar_t)(b1[i] << 4 * (1 - j))) >> 4;
        uchar_t r = ((uchar_t)(b2[i] << 4 * (1 - j))) >> 4;
        if (base) {
          t++;
        }
        if (r + t >= 16) {
          rb[i] += (t + r - 16) << j * 4;
          base = true;
        }
        else {
          rb[i] += (t + r) << j * 4;
          base = false;
        }
      }
    }
    return rv;
  }
  ulong<dim>& operator+=(const ulong<dim>& rhs)
  {
    *this = *this + rhs;
    return *this;
  }
  ulong<dim>& operator++()
  {
    *this = *this + 1;
    return *this;
  }
  ulong<dim> operator++(int)
  {
    ulong<dim> tmp = *this;
    *this = *this + 1;
    return tmp;
  }

  ulong<dim> operator-(const ulong<dim>& rhs) const
  {
    ulong<dim> rv;
    const auto b1 = buf_.get();
    const auto b2 = rhs.buf_.get();
    const auto rb = rv.buf_.get();
    bool base = false;
    for (size_t i = 0; i < dim; ++i) {
      for (ssize_t j = 0; j < 2; ++j) {
        // 必须用有符号整数：当前 nibble 为 0 且需要借位时，
        // uchar_t 的 t-- 会下溢到 255，误判"够减"且丢失借位，
        // 污染当前字节并向高位传播错误（例如 1024-1000 算成
        // 0x118=280）。DH/除法全部依赖本运算，借位从 0 借的场景
        // 在随机大数间几乎必然出现。
        int t = ((uchar_t)(b1[i] << 4 * (1 - j))) >> 4;
        int r = ((uchar_t)(b2[i] << 4 * (1 - j))) >> 4;
        if (base) {
          t--;
        }
        if (t >= r) {
          rb[i] += (t - r) << j * 4;
          base = false;
        }
        else {
          rb[i] += (t + 16 - r) << j * 4;
          base = true;
        }
      }
    }
    return rv;
  }
  ulong<dim>& operator-=(const ulong<dim>& rhs)
  {
    *this = *this - rhs;
    return *this;
  }
  ulong<dim>& operator--()
  {
    *this = *this - 1;
    return *this;
  }
  ulong<dim> operator--(int)
  {
    ulong<dim> tmp = *this;
    *this = *this - 1;
    return tmp;
  }

  ulong<dim> operator*(const ulong<dim>& rhs) const
  {
    ulong<dim> c = rhs, rv;
    const ulong<dim> null;
    size_t cap = c.capacity();
    while (c != null) {
      ulong<dim> tmp = *this;
      tmp.mul(cap - 1);
      rv += tmp;

      ulong<dim> diff(1);
      diff.mul(cap - 1);
      c -= diff;

      cap = c.capacity();
    }
    return rv;
  }
  ulong<dim>& operator*=(const ulong<dim>& rhs)
  {
    *this = *this * rhs;
    return *this;
  }

  ulong<dim> operator/(const ulong<dim>& rhs) const
  {
    ulong<dim> quotient, remainder;
    div(rhs, quotient, remainder);
    return quotient;
  }
  ulong<dim>& operator/=(const ulong<dim>& rhs)
  {
    *this = *this / rhs;
    return *this;
  }

  ulong<dim> operator%(const ulong<dim>& rhs) const
  {
    ulong<dim> quotient, remainder;
    div(rhs, quotient, remainder);
    return remainder;
  }
  ulong<dim>& operator%=(const ulong<dim>& rhs)
  {
    *this = *this % rhs;
    return *this;
  }

  ulong<dim> mul_mod(const ulong<dim>& mul, const ulong<dim>& mod) const
  {
    // capacity() 以 nibble（半个字节）计，与 dim（字节数）比较时
    // 必须换算成 dim * 2。此前误写为 capacity + capacity <= dim，
    // 单位错了一倍，导致永远走 2dim 扩展路径（白白多分配一倍内存
    // 并拖慢 DH 模幂）。
    if (capacity() + mul.capacity() <= dim * 2) {
      return (*this * mul) % mod;
    }
    ulong<dim * 2> et(buf_.get(), dim), emul(mul.buf_.get(), dim),
        emod(mod.buf_.get(), dim), erv = (et * emul) % emod;
    ulong<dim> rv;
    erv.binary(rv.buf_.get(), dim);
    return rv;
  }

  // Modular exponentiation: (*this)^power % mod.
  //
  // DH (MSE/BEP 8) requires g^x mod p. The stock operators (* and /
  // via nibble-wise shift-and-subtract) are far too slow for 768-bit
  // operands (seconds per exponentiation), so this implementation uses
  // byte-wise schoolbook multiplication and Knuth algorithm D division
  // internally — milliseconds per exponentiation.
  //
  // Note: the reference InternalDHKeyExchange shipped with aria2 calls
  // mul_mod (g*x mod p) here, which is mathematically wrong for DH; that
  // path is never enabled in official builds (they always have OpenSSL /
  // GMP), so the bug went unnoticed. This engine builds without those
  // libraries, so a correct pow_mod is required.
  ulong<dim> pow_mod(const ulong<dim>& power, const ulong<dim>& mod) const
  {
    const ulong<dim> zero;
    if (mod == zero) {
      throw std::invalid_argument("pow_mod: modulus is zero");
    }
    if (power == zero) {
      // x^0 == 1 mod m
      return ulong<dim>(1) % mod;
    }

    // Effective byte lengths (little-endian buffers, high zero bytes
    // trimmed). buf_ 的有效长度；溢出高位即视为 0。
    const auto mb = mod.buf_.get();
    size_t mlen = dim;
    while (mlen > 0 && mb[mlen - 1] == 0) {
      --mlen;
    }
    // mlen >= 1 here (mod != 0)

    // Reduce the base first.
    std::unique_ptr<uchar_t[]> tmp(new uchar_t[2 * dim]);
    std::unique_ptr<uchar_t[]> prod(new uchar_t[2 * dim]);
    auto base = aria2::make_unique<uchar_t[]>(dim);
    auto res = aria2::make_unique<uchar_t[]>(dim);

    size_t alen = trimmedLength();
    std::memcpy(tmp.get(), buf_.get(), alen);
    std::memset(tmp.get() + alen, 0, 2 * dim - alen);
    modBytes(tmp.get(), alen, mb, mlen, base.get());

    // res = 1 % mod
    {
      auto one = aria2::make_unique<uchar_t[]>(dim);
      std::fill(one.get(), one.get() + dim, 0);
      one[0] = 1;
      modBytes(one.get(), 1, mb, mlen, res.get());
    }

    // Find the most significant set bit of the exponent.
    ssize_t topByte = -1;
    for (ssize_t i = static_cast<ssize_t>(dim) - 1; i >= 0; --i) {
      if (power.buf_[i] != 0) {
        topByte = i;
        break;
      }
    }
    for (ssize_t i = topByte; i >= 0; --i) {
      const uchar_t byte = power.buf_[i];
      for (ssize_t j = 7; j >= 0; --j) {
        // res = res*res % mod — squaring is skipped before the first
        // set bit (1*1 == 1).
        mulBytes(res.get(), res.get(), prod.get());
        modBytes(prod.get(), 2 * dim, mb, mlen, res.get());
        if ((byte >> j) & 1) {
          mulBytes(res.get(), base.get(), prod.get());
          modBytes(prod.get(), 2 * dim, mb, mlen, res.get());
        }
      }
    }
    return ulong<dim>(res.get(), dim);
  }

  std::unique_ptr<uchar_t[]> binary() const
  {
    ulong<dim> c = *this;
    std::unique_ptr<uchar_t[]> rv;
    rv.swap(c.buf_);
    return rv;
  }
  void binary(uchar_t* buf, size_t len) const
  {
    memcpy(buf, buf_.get(), std::min(dim, len));
  }

  size_t length() const { return dim; }

private:
  size_t trimmedLength() const
  {
    size_t rv = dim;
    const auto b = buf_.get();
    while (rv > 0 && b[rv - 1] == 0) {
      --rv;
    }
    return rv;
  }

  // Byte-wise schoolbook multiplication for pow_mod:
  // prod[0 .. 2*dim) = a * b (both little-endian, dim bytes each).
  // Skips zero bytes of a; the final carry always stays in buffer
  // because the product fits in 2*dim bytes.
  static void mulBytes(const uchar_t* a, const uchar_t* b, uchar_t* prod)
  {
    std::memset(prod, 0, 2 * dim);
    for (size_t i = 0; i < dim; ++i) {
      if (a[i] == 0) {
        continue;
      }
      unsigned int carry = 0;
      // 内层多算一个字节（bj = 0）：i+dim 位置此前可能已被低轮次
      // 写入，统一走加法进位链，数学上保证不越过 2*dim。
      for (size_t j = 0; j <= dim; ++j) {
        const unsigned bj = j < dim ? b[j] : 0;
        const unsigned int cur =
            prod[i + j] + static_cast<unsigned int>(a[i]) * bj + carry;
        prod[i + j] = static_cast<uchar_t>(cur & 0xff);
        carry = cur >> 8;
      }
    }
  }

  // Knuth algorithm D (division) specialized to remainder extraction:
  // computes a mod d. a is little-endian with alen significant bytes
  // (buffer may hold up to 2*dim bytes), d has dlen significant bytes;
  // the remainder (dim bytes, zero-padded, little-endian) is written
  // to r. dlen >= 1 and d[dlen-1] != 0 are required.
  static void modBytes(const uchar_t* a, size_t alen, const uchar_t* d,
                       size_t dlen, uchar_t* r)
  {
    std::memset(r, 0, dim);
    if (alen == 0) {
      return; // 0 mod d == 0
    }
    if (alen < dlen || (alen == dlen && cmpBytes(a, d, alen) < 0)) {
      std::memcpy(r, a, alen);
      return;
    }
    if (dlen == 1) {
      // 单字节除数：直接按字节流水取模。
      unsigned acc = 0;
      for (size_t i = alen; i-- > 0;) {
        acc = (acc * 256 + a[i]) % d[0];
      }
      r[0] = static_cast<uchar_t>(acc);
      return;
    }

    // 归一化：左移 s 位使除数最高字节 ≥ 128，保证算法 D 的商估计
    // 至多偏大 2（未归一化时误差无界）。
    int s = 0;
    {
      unsigned t = d[dlen - 1];
      if (t < 128) {
        while (!(t & 0x80)) {
          t <<= 1;
          ++s;
        }
      }
    }

    auto rem = std::unique_ptr<unsigned char[]>(new unsigned char[alen + 2]);
    // shlBytes 会写 dst[n]（进位字节；对归一化的除数恒为 0，
    // 但仍需分配到 dlen+1 以避免越界写）。
    auto dn = std::unique_ptr<unsigned char[]>(new unsigned char[dlen + 1]);
    if (s > 0) {
      shlBytes(rem.get(), a, alen, s);
      shlBytes(dn.get(), d, dlen, s);
    }
    else {
      std::memcpy(rem.get(), a, alen);
      rem[alen] = 0;
      std::memcpy(dn.get(), d, dlen);
    }
    rem[alen + 1] = 0;

    const unsigned dh = dn[dlen - 1];
    const unsigned dh2 = dn[dlen - 2];

    for (size_t qi = alen - dlen + 1; qi-- > 0;) {
      // 用最高三个字节估计商字节并修正（Hacker's Delight divmnu）。
      unsigned num =
          static_cast<unsigned>(rem[qi + dlen]) * 256 + rem[qi + dlen - 1];
      unsigned qhat = num / dh;
      unsigned rhat = num % dh;
      while (qhat >= 256 || qhat * dh2 > rhat * 256 + rem[qi + dlen - 2]) {
        --qhat;
        rhat += dh;
        if (rhat >= 256) {
          break;
        }
      }

      // rem -= qhat * dn << (8*qi)
      int borrow = 0;
      unsigned carry = 0;
      for (size_t j = 0; j < dlen; ++j) {
        const unsigned p = qhat * dn[j] + carry;
        carry = p >> 8;
        const int t = static_cast<int>(rem[qi + j]) -
                      static_cast<int>(p & 0xff) - borrow;
        rem[qi + j] = static_cast<unsigned char>(t & 0xff);
        borrow = t < 0 ? 1 : 0;
      }
      const int t =
          static_cast<int>(rem[qi + dlen]) - static_cast<int>(carry) - borrow;
      rem[qi + dlen] = static_cast<unsigned char>(t & 0xff);
      borrow = t < 0 ? 1 : 0;

      if (borrow) {
        // qhat 偏大 1：加回除数。
        --qhat;
        unsigned c = 0;
        for (size_t j = 0; j < dlen; ++j) {
          const unsigned u = rem[qi + j] + dn[j] + c;
          rem[qi + j] = static_cast<unsigned char>(u & 0xff);
          c = u >> 8;
        }
        rem[qi + dlen] =
            static_cast<unsigned char>((rem[qi + dlen] + c) & 0xff);
      }
    }
    // 余数反归一化（右移 s 位）。
    if (s > 0) {
      shrBytes(rem.get(), dlen, s);
    }
    std::memcpy(r, rem.get(), dlen);
  }

  // dst[0..n) = src << s（s ∈ [0,7]），dst 容量 ≥ n+1。
  static void shlBytes(uchar_t* dst, const uchar_t* src, size_t n, int s)
  {
    unsigned carry = 0;
    for (size_t i = 0; i < n; ++i) {
      const unsigned v = (static_cast<unsigned>(src[i]) << s) | carry;
      dst[i] = static_cast<uchar_t>(v & 0xff);
      carry = v >> 8;
    }
    dst[n] = static_cast<uchar_t>(carry);
  }

  // buf[0..n) >>= s（s ∈ [0,7]）。
  static void shrBytes(uchar_t* buf, size_t n, int s)
  {
    if (s == 0) {
      return;
    }
    for (size_t i = 0; i < n; ++i) {
      const unsigned hi = i + 1 < n ? buf[i + 1] : 0;
      buf[i] = static_cast<uchar_t>((buf[i] >> s) | (hi << (8 - s)));
    }
  }

  // Three-way byte compare (little-endian, same length n):
  // returns <0, 0, >0 as a<n b, a==b, a>n b.
  static int cmpBytes(const uchar_t* a, const uchar_t* b, size_t n)
  {
    for (size_t i = n; i-- > 0;) {
      if (a[i] != b[i]) {
        return a[i] < b[i] ? -1 : 1;
      }
    }
    return 0;
  }

  size_t capacity() const
  {
    size_t rv = dim * 2;
    const auto b = buf_.get();
    for (ssize_t i = dim - 1; i >= 0; --i) {
      uchar_t f = b[i] >> 4;
      uchar_t s = (b[i] << 4) >> 4;
      if (!f && !s) {
        rv -= 2;
        continue;
      }
      if (!f) {
        --rv;
      }
      return rv;
    }
    return rv;
  }

  void mul(size_t digits)
  {
    ulong<dim> tmp = *this;
    auto bt = tmp.buf_.get();
    auto b = buf_.get();
    memset(b, 0, dim);
    const size_t npar = digits % 2;
    const size_t d2 = digits / 2;
    for (size_t i = d2; i < dim; ++i) {
      for (size_t j = 0; j < 2; ++j) {
        uchar_t c = ((uchar_t)(bt[(dim - 1) - i] << 4 * (1 - j))) >> 4;
        uchar_t r = c << (npar * (1 - j) * 4 + (1 - npar) * j * 4);
        ssize_t idx = i - d2 - npar * j;
        if (idx >= 0) {
          b[(dim - 1) - idx] += r;
        }
      }
    }
  }

  void div(const ulong<dim>& d, ulong<dim>& q, ulong<dim>& r) const
  {
    ulong<dim> tmp = d;
    r = *this;
    q = 0;
    size_t cr = r.capacity();
    const size_t cd = d.capacity();
    while (cr > cd) {
      tmp = d;
      tmp.mul(cr - cd - 1);
      ulong<dim> qt(1);
      qt.mul(cr - cd - 1);
      ulong<dim> t = tmp;
      t.mul(1);
      if (r >= t) {
        tmp = t;
        qt.mul(1);
      }
      while (r >= tmp) {
        r -= tmp;
        q += qt;
      }
      cr = r.capacity();
    }
    while (r >= d) {
      r -= d;
      ++q;
    }
  }
};

} // namespace bignum

#endif
