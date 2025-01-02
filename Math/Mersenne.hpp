#ifndef MATH_MERSENNE_HPP
#define MATH_MERSENNE_HPP

#include "Math/Mersenne.h"


// Warning: we do not check for x <= prime in the constructor!!
template<int L>
inline Mersenne<L>::Mersenne(value_type x): value(x) {}

template<int L>
inline Mersenne<L>::Mersenne(signed_value_type x): value(x < 0 ? x + prime : x) {}

template<int L>
inline Mersenne<L>::Mersenne(int x): value(x < 0 ? x + prime : x) {}

template<int L>
inline Mersenne<L> Mersenne<L>::operator=(int rhs) {
    value = rhs < 0 ? rhs + prime : rhs;
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator+=(Mersenne rhs) {
    value += rhs.value;
    if (value >= prime) {
        value -= prime;
    }
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator-=(Mersenne rhs) {
    if (value < rhs.value) {
        value += prime;
    }
    value -= rhs.value;
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator*=(Mersenne rhs) {
    dvalue_type tmp = static_cast<dvalue_type>(value) * rhs.value;
    value = static_cast<value_type>(tmp & prime) + static_cast<value_type>(tmp >> bit_length);
    if (value >= prime) {
        value -= prime;
    }
    return *this;
}

template<int L>
inline Mersenne<L> Mersenne<L>::operator/=(Mersenne rhs) {
    return *this *= rhs.invert();
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
std::ostream& operator<<(std::ostream& os, const Mersenne<L>& rhs) {
    os << rhs.value;
    return os;
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

#endif // MATH_MERSENNE_HPP