#ifndef MATH_MERSENNE_H
#define MATH_MERSENNE_H

#include "Math/ValueInterface.h"

template <int L>
class Mersenne;

template <int L>
std::ostream& operator<<(std::ostream& os, const Mersenne<L>& rhs);

template <int L>
Mersenne<L> operator+(Mersenne<L> lhs, Mersenne<L> rhs);

template <int L>
Mersenne<L> operator-(Mersenne<L> lhs, Mersenne<L> rhs);

template <int L>
Mersenne<L> operator*(Mersenne<L> lhs, Mersenne<L> rhs);

template <int L>
Mersenne<L> operator/(Mersenne<L> lhs, Mersenne<L> rhs);

template <int L>
bool operator==(Mersenne<L> lhs, Mersenne<L> rhs);

/*
 * Mersenne prime fields of bit length 31 and 61
 */
template <int L>
class Mersenne : public ValueInterface {
    static_assert(L == 31 || L == 61,
                  "Only Mersenne prime fields of bit length 31 and 61 are supported");

public:
    using value_type = std::conditional_t<L == 31, uint32_t, uint64_t>;
    using dvalue_type = std::conditional_t<L == 31, uint64_t, __uint128_t>;
    using signed_value_type = std::make_signed_t<value_type>;

    static constexpr value_type prime = std::conditional_t<L == 31,
            std::integral_constant<uint32_t, 0x7fffffffU>, // 2^31 - 1
            std::integral_constant<uint64_t, 0x1fffffffffffffffULL> // 2^61 - 1
        >::value;

    static constexpr value_type max_positive = (prime - 1) / 2;
    static constexpr int bit_length = L;

    static const true_type prime_field;
    static const true_type invertible;

    inline Mersenne() = default;
    inline Mersenne(value_type x);
    inline Mersenne(signed_value_type x);
    inline Mersenne(int x);

    Mersenne operator=(int rhs);

    // the Mersenne class is very small, so we prefer to pass by value
    inline Mersenne operator+=(Mersenne rhs);
    inline Mersenne operator-=(Mersenne rhs);
    inline Mersenne operator*=(Mersenne rhs);
    inline Mersenne operator/=(Mersenne rhs);

    friend std::ostream& operator<<<>(std::ostream& os, const Mersenne& rhs);
    friend Mersenne operator+<>(Mersenne lhs, Mersenne rhs);
    friend Mersenne operator-<>(Mersenne lhs, Mersenne rhs);
    friend Mersenne operator*<>(Mersenne lhs, Mersenne rhs);
    friend Mersenne operator/<>(Mersenne lhs, Mersenne rhs);
    friend bool operator==<>(Mersenne lhs, Mersenne rhs);

    Mersenne invert() const;

private:
    value_type value = 0;
};


#endif // MATH_MERSENNE_H