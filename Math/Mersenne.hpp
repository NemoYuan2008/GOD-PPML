#ifndef MATH_MERSENNE_HPP
#define MATH_MERSENNE_HPP

#include "Math/Mersenne.h"


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

template<int L>
inline Mersenne<L>& Mersenne<L>::operator=(Mersenne rhs) {
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
Mersenne<L> Mersenne<L>::invert() const {
    value_type a = value;
    value_type b = prime;
    value_type x = 1, y = 0;
    value_type u = 0, v = 1;
    
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

#endif // MATH_MERSENNE_HPP