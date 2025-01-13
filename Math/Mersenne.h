#ifndef MATH_MERSENNE_H
#define MATH_MERSENNE_H

#include <iostream>
#include <vector>

#include "Math/ValueInterface.h"
#include "Math/field_types.h"
#include "Tools/octetStream.h"
#include "Tools/random.h"

template <int L> class Mersenne;
template <class T> class IntBase;

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

template <int L>
bool operator!=(Mersenne<L> lhs, Mersenne<L> rhs);


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

    // All of the constructors do not perform any modulo operation (for efficiency)
    // It is the caller's responsibility to ensure that the input is in the correct range
    inline Mersenne() = default;
    inline Mersenne(const Mersenne& rhs);
    inline Mersenne(value_type x);
    inline Mersenne(int x);
    inline Mersenne(long x);
    inline Mersenne(long long x);
    template <typename T> inline Mersenne(IntBase<T> x);
    inline Mersenne(const mpz_class& x);

    inline Mersenne& operator=(Mersenne rhs);
    inline Mersenne& operator=(int rhs);

    // This constructor performs modulo operation
    inline static Mersenne from_uint_mod(value_type x);

    // the Mersenne class is very small, so we prefer to pass by value
    friend Mersenne operator+<>(Mersenne lhs, Mersenne rhs);
    friend Mersenne operator-<>(Mersenne lhs, Mersenne rhs);
    friend Mersenne operator*<>(Mersenne lhs, Mersenne rhs);
    friend Mersenne operator/<>(Mersenne lhs, Mersenne rhs);
    friend bool operator==<>(Mersenne lhs, Mersenne rhs);
    friend bool operator!=<>(Mersenne lhs, Mersenne rhs);

    inline Mersenne& operator+=(Mersenne rhs);
    inline Mersenne& operator-=(Mersenne rhs);
    inline Mersenne& operator*=(Mersenne rhs);
    inline Mersenne& operator/=(Mersenne rhs);

    inline Mersenne operator+(Mersenne rhs) const;
    inline Mersenne operator-(Mersenne rhs) const;
    inline Mersenne operator*(Mersenne rhs) const;
    inline Mersenne operator/(Mersenne rhs) const;

    inline bool operator==(Mersenne rhs) const;
    inline bool operator!=(Mersenne rhs) const;

    inline Mersenne& operator<<=(int n);
    inline Mersenne& operator>>=(int n);
    inline Mersenne operator<<(int n) const;
    inline Mersenne operator>>(int n) const;

    inline Mersenne& operator<<=(Mersenne n);
    inline Mersenne& operator>>=(Mersenne n);
    inline Mersenne operator<<(Mersenne n) const;
    inline Mersenne operator>>(Mersenne n) const;

    inline Mersenne& operator&=(Mersenne rhs);
    inline Mersenne& operator|=(Mersenne rhs);
    inline Mersenne& operator^=(Mersenne rhs);
    inline Mersenne operator&(Mersenne rhs) const;
    inline Mersenne operator|(Mersenne rhs) const;
    inline Mersenne operator^(Mersenne rhs) const;

    static inline Mersenne dot_product(
        const vector <Mersenne>& a, const vector <Mersenne>& b);

    inline Mersenne invert() const;
    inline Mersenne sqrRoot() const;
    inline Mersenne truncate(int f);

    inline bool negative() const;
    inline signed_value_type to_signed() const;
    inline value_type get() const;
    inline bool is_zero() const;
    inline bool is_one() const;
    inline bool is_bit() const;

    inline void input(istream& is, bool human);
    inline void output(ostream& os, bool human, bool signed_ = false) const;
    inline void assign(const void* buffer);

    inline void pack(octetStream& os) const;
    inline void unpack(octetStream& os);
    inline void randomize(PRNG& G);

    inline void convert_destroy(bigint& a);
    inline void to(bigint& res) const;

    // Some less significant methods and typedefs required by the interface
    using Scalar = Mersenne<L>;
    using next = Mersenne<L>;
    static inline DataFieldType field_type();
    static inline char type_char();
    static inline string type_short();
    static inline string type_string();
    static inline int size();
    static constexpr inline int length();
    static inline bool allows(Dtype type);
    static inline void reqbl(int n);
    static inline void specification(octetStream& os);
    static Mersenne power_of_two(bool bit, int exp);

private:
    value_type value = 0;

    // Helper functions
    static inline uint64_t modp(uint64_t x);
    static inline uint64_t modp(__uint128_t x); 
};

template<int L>
std::ostream& operator<<(std::ostream& os, Mersenne<L> rhs);

template<int L>
std::istream& operator>>(std::istream& is, Mersenne<L>& rhs);

#endif // MATH_MERSENNE_H