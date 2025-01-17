#ifndef MATH_MERSENNE_HPP
#define MATH_MERSENNE_HPP

#include "Math/Mersenne.h"
#include "Mersenne.h"


template<int L>
constexpr true_type Mersenne<L>::prime_field;

template<int L>
constexpr true_type Mersenne<L>::invertible;

// Warning: we do not check for x <= prime in the constructor!!
template<int L>
inline Mersenne<L>::Mersenne(value_type x): value(x) {}

template<int L>
inline Mersenne<L>::Mersenne(int x): value(x < 0 ? x + prime : x) {}

template<int L>
inline Mersenne<L>::Mersenne(long x): value(x < 0 ? x + prime : x) {}

template<int L>
inline Mersenne<L>::Mersenne(long long x): value(x < 0 ? x + prime : x) {}

template<int L>
template<typename T>
inline Mersenne<L>::Mersenne(IntBase<T> x): Mersenne(x.get()) {}

template<int L>
inline Mersenne<L>::Mersenne(const mpz_class& x): Mersenne(x.get_si()) {}

template<int L>
inline Mersenne<L>::Mersenne(const Mersenne& rhs): value(rhs.value) {}


template<int L>
inline Mersenne<L>& Mersenne<L>::operator=(int rhs) {
    value = rhs < 0 ? rhs + prime : rhs;
    return *this;
}

template <int L>
inline Mersenne<L> Mersenne<L>::from_uint_mod(value_type x)
{
    return Mersenne(x % prime);
}

template <int L>
inline Mersenne<L> &Mersenne<L>::operator=(Mersenne rhs)
{
    value = rhs.value;
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator+=(Mersenne rhs) {
    value += rhs.value;
    if (value >= prime) {
        value -= prime;
    }
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator-=(Mersenne rhs) {
    if (value < rhs.value) {
        value += prime;
    }
    value -= rhs.value;
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator*=(Mersenne rhs) {
    dvalue_type tmp = static_cast<dvalue_type>(value) * rhs.value;
    value = static_cast<value_type>(tmp & prime) + static_cast<value_type>(tmp >> bit_length);
    if (value >= prime) {
        value -= prime;
    }
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator/=(Mersenne rhs) {
    return *this *= rhs.invert();
}

// Warning: we do not check n in the shift operators!!

template<int L>
inline Mersenne<L>& Mersenne<L>::operator<<=(int n) {
    value <<= n;
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator>>=(int n) {
    value >>= n;
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator<<(int n) const {
    Mersenne result = *this;
    result <<= n;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator>>(int n) const {
    Mersenne result = *this;
    result >>= n;
    return result;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator<<=(Mersenne n) {
    value <<= n.value;
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator>>=(Mersenne n) {
    value >>= n.value;
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator<<(Mersenne n) const {
    Mersenne result = *this;
    result <<= n;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator>>(Mersenne n) const {
    Mersenne result = *this;
    result >>= n;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator+(Mersenne rhs) const {
    Mersenne result = *this;
    result += rhs;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator-(Mersenne rhs) const {
    Mersenne result = *this;
    result -= rhs;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator*(Mersenne rhs) const {
    Mersenne result = *this;
    result *= rhs;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator/(Mersenne rhs) const {
    Mersenne result = *this;
    result /= rhs;
    return result;
}

template<int L>
inline bool Mersenne<L>::operator==(Mersenne rhs) const {
    return value == rhs.value;
}

template<int L>
inline bool Mersenne<L>::operator!=(Mersenne rhs) const {
    return !(*this == rhs);
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator&=(Mersenne rhs) {
    value &= rhs.value;
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator|=(Mersenne rhs) {
    value |= rhs.value;
    return *this;
}

template<int L>
inline Mersenne<L>& Mersenne<L>::operator^=(Mersenne rhs) {
    value ^= rhs.value;
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator&(Mersenne rhs) const {
    Mersenne result = *this;
    result &= rhs;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator|(Mersenne rhs) const {
    Mersenne result = *this;
    result |= rhs;
    return result;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator^(Mersenne rhs) const {
    Mersenne result = *this;
    result ^= rhs;
    return result;
}

template<int L>
Mersenne<L> Mersenne<L>::dot_product(const vector<Mersenne<L>>& a, const vector<Mersenne<L>>& b) {
    // Warning: we do not check for the sizes of a and b, so make sure they are the same!!

    if constexpr (L == 61) {
        static constexpr int max_batch = 63; // The maximum batch size before potential overflow
        value_type result = 0;
        const int size = a.size();
        int start = 0;
        int end;

        while (start < size) {
            end = std::min(start + max_batch, size);
            for (int i = start; i < end; ++i) {
                result += a[i].value * b[i].value;
            }
            result = modp(result);
            start = end;
        }

        return {result};
    } else {
        // There are three ways for L == 31:
        // 1. Use __uint128_t to store the result, then modp, 
        //    the maximum size is 2^(128 - 2 * 31) - 1 = 2^66 - 1, but using __uint128_t has overhead
        // 2. Use uint64_t to store the result, then modp, 
        //    the maximum size is 2^(64 - 2 * 31) - 1 = 3, this is rather small, so maybe inefficient
        // 3. Use trivial multiplication and modp
        //
        // We choose the third option for now, but we haven't done any benchmarking
        
        Mersenne result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result += a[i] * b[i];
        }
        return result;
    }
}

template<int L>
Mersenne<L> Mersenne<L>::invert() const {
    value_type a = prime;
    value_type b = value;
    value_type x = 0, y = 1;
    value_type u = 1, v = 0;
    
    while (b != 0) {
        value_type q = a / b;
        value_type r = a % b;
        value_type m = x - u * q;
        value_type n = y - v * q;
        a = b;
        b = r;
        x = u;
        y = v;
        u = m;
        v = n;
    }

    if (x >= prime) {
        x += prime;
    }
    
    return {x};
}

template<int L>
Mersenne<L> Mersenne<L>::sqrRoot() const {
    // For Mersenne primes p = 2^L - 1, where L is prime
    // If x is a quadratic residue, then x^((p+1)/4) is a square root of x
    // Warning: we do not check whether the number is a quadratic residue!!!!
    // We are assuming that the input is a quadratic residue

    if (is_zero() || is_one()) {
        // TODO: maybe we don't need this
        return *this;
    }

    // Compute (p+1)/4 = (2^L)/4 = 2^(L-2)
    static constexpr value_type exp = (1ULL << (L-2));
    
    // Square and multiply algorithm for x^exp
    Mersenne result(1);
    Mersenne base(*this);
    
    value_type mask = exp;
    while (mask > 0) {
        result *= result;
        if (mask & exp) {
            result *= base;
        }
        mask >>= 1;
    }

    // This is not done in gfp_, so we are being consistent
    // if (result.negative()) {
    //     result.value = prime - result.value;
    // }

    // Check if the result is correct (omitted for now)
    // Mersenne check = result;
    // check *= check;
    // if (check != *this) {
    //     throw runtime_error("No square root exists");
    // }
    
    return result;
}

template<int L>
Mersenne<L> Mersenne<L>::truncate(int f) {
    if (negative()) {
        return {prime - ((prime - value) >> f)};
    }
    return {value >> f};
}

template<int L>
inline std::ostream& operator<<(std::ostream& os, Mersenne<L> rhs) {
    rhs.output(os, true);
    return os;
}

template<int L>
inline std::istream& operator>>(std::istream& is, Mersenne<L>& rhs) {
    rhs.input(is, true);
    return is;
}

template<int L>
inline Mersenne<L> operator+(Mersenne<L> lhs, Mersenne<L> rhs) {
    lhs += rhs;
    return lhs;
}

template<int L>
inline Mersenne<L> operator-(Mersenne<L> lhs, Mersenne<L> rhs) {
    lhs -= rhs;
    return lhs;
}

template<int L>
inline Mersenne<L> operator*(Mersenne<L> lhs, Mersenne<L> rhs) {
    lhs *= rhs;
    return lhs;
}

template<int L>
inline Mersenne<L> operator/(Mersenne<L> lhs, Mersenne<L> rhs) {
    lhs /= rhs;
    return lhs;
}

template<int L>
inline bool operator==(Mersenne<L> lhs, Mersenne<L> rhs) {
    return lhs.value == rhs.value;
}

template<int L>
inline bool operator!=(Mersenne<L> lhs, Mersenne<L> rhs) {
    return lhs.value != rhs.value;
}

template<int L>
bool Mersenne<L>::negative() const { 
    return value > max_positive; 
}

template<int L>
typename Mersenne<L>::signed_value_type Mersenne<L>::to_signed() const { 
    return negative() ? value - prime : value; 
}

template<int L>
typename Mersenne<L>::value_type Mersenne<L>::get() const { 
    return value; 
}

template<int L>
bool Mersenne<L>::is_zero() const { 
    return value == 0; 
}

template<int L>
bool Mersenne<L>::is_one() const { 
    return value == 1; 
}

template<int L>
bool Mersenne<L>::is_bit() const { 
    return is_zero() || is_one(); 
}

template<int L>
void Mersenne<L>::input(istream& is, bool human) {
    if (human) {
        signed_value_type x;
        is >> x;
        value = x < 0 ? x + prime : x;
    } else {
        is.read((char*)&value, sizeof(value));
    }
}

template<int L>
void Mersenne<L>::output(ostream& os, bool human, bool signed_) const {
    if (human) {
        if (signed_) {
            os << to_signed();
        } else {
            os << value;
        }
    } else {
        os.write((char*)&value, sizeof(value));
    }
}

template<int L>
void Mersenne<L>::assign(const void* buffer) { 
    value = *static_cast<const value_type*>(buffer); 
}

template<int L>
void Mersenne<L>::pack(octetStream& os) const { 
    os.store(value); 
}

template<int L>
void Mersenne<L>::unpack(octetStream& os) { 
    os.get(value); 
}

template<int L>
void Mersenne<L>::randomize(PRNG& G) { 
    G.get_octets<sizeof(value_type)>((octet*)&value);
    value &= prime; // This actually mods (2^L), not (2^L-1), but it fails with negligible probability
}

template<int L>
void Mersenne<L>::convert_destroy(bigint& a) { 
    *this = a; 
}

template<int L>
void Mersenne<L>::to(bigint& res) const { 
    res = *this; 
}

template<int L>
DataFieldType Mersenne<L>::field_type() { 
    return DATA_INT; 
}

template<int L>
char Mersenne<L>::type_char() { 
    return 'p'; 
}

template<int L>
string Mersenne<L>::type_short() { 
    return {"p"}; 
}

template<int L>
string Mersenne<L>::type_string() { 
    return {"Mersenne"}; 
}

template<int L>
int Mersenne<L>::size() { 
    return sizeof(value_type); 
}

template<int L>
constexpr int Mersenne<L>::length() { 
    return bit_length; 
}

template<int L>
bool Mersenne<L>::allows(Dtype type) { 
    return type <= DATA_INVERSE; 
}

template<int L>
void Mersenne<L>::reqbl(int n) {
    if (n < 0) {
        throw Processor_Error(
            "Program compiled for rings not fields, "
            "run compile.py without -R");
    }
}

template<int L>
void Mersenne<L>::specification(octetStream& os) { 
    os.store(prime); 
}

template<int L>
Mersenne<L> Mersenne<L>::power_of_two(bool bit, int exp) {
    assert(exp >= 0);
    if (bit) {
        return (Mersenne(1) << exp);
    } else {
        return 0;
    }
}

template<int L>
uint64_t Mersenne<L>::modp(uint64_t x) {
    uint64_t res = (x >> bit_length) + (x & prime);
    return res >= prime ? res - prime : res;
}

template<int L>
uint64_t Mersenne<L>::modp(__uint128_t x) {
    uint64_t upper = x >> (2 * bit_length);
    uint64_t middle = (x >> bit_length) & prime;
    uint64_t lower = x & prime;
    return modp(upper + middle + lower);
}

#endif // MATH_MERSENNE_HPP