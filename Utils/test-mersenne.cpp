/*
 * This file is used to test the correctness of the Mersenne class.
 */

#include <cassert>
#include <random>
#include <iostream>
#include <sstream>

#include "Math/Mersenne.h"
#include "Math/Mersenne.hpp"
#include "Math/gfp.h"
#include "Math/gfp.hpp"
#include "Tools/random.h"

using field = Mersenne<61>;
using field_gfp = gfp_<0, 1>;
SeededPRNG G;

void test_conversion() {
    std::default_random_engine eng(std::random_device{}());
    std::uniform_int_distribution<int> dist;

    for (int i = 0; i < 100; ++i) {
        int x = dist(eng);
        field x_field(x);
        field_gfp x_gfp(x);
        Integer x_integer(x);
        
        // Test conversion to bigint
        assert(bigint(x_field) == bigint(x_gfp));

        // Test conversion to Integer
        assert(Integer(x_field) == Integer(x_gfp));

        // Test Integer::convert_unsigned
        assert(Integer::convert_unsigned(x_field) == Integer::convert_unsigned(x_gfp));

        // Test conversion from Integer
        assert(bigint(field(x_integer)) == bigint(field_gfp(x_integer)));

        // Test convert_destroy()
        bigint z(x);
        x_field.convert_destroy(z);
        z = x;
        x_gfp.convert_destroy(z);
        assert(bigint(x_field) == bigint(x_gfp));
    }
}

void test_mul() {
    for (int i = 0; i < 100; ++i) {
        field x, y;
        x.randomize(G);
        y.randomize(G);
        field_gfp x_gfp = bigint(x), y_gfp = bigint(y);
        
        // Test multiplication, use field_gfp as reference
        assert(bigint(x * y) == bigint(x_gfp * y_gfp));
        
        // Test commutativity
        assert(x * y == y * x);
        
        // Test multiplication with 1
        assert(x * field(1) == x);
        
        // Test multiplication with 0
        assert(x * field(0) == field(0));
    }
}

void test_inversion() {
    field one = 1;

    // Test 1: x * x^(-1) = 1
    for (int i = 0; i < 100; ++i) {
        field x;
        x.randomize(G);
        field x_inv = x.invert();
        assert(x * x_inv == one);
    }

    // Test 2: Special case - multiplicative identity
    assert(one.invert() == one);

    // Test 3: (x*y)^(-1) = y^(-1) * x^(-1)
    for (int i = 0; i < 100; ++i) {
        field x, y;
        x.randomize(G);
        y.randomize(G);
        field xy_inv = (x * y).invert();
        field x_inv_y_inv = y.invert() * x.invert();
        assert(xy_inv == x_inv_y_inv);
    }
}

void test_sqrRoot() {
    for (int i = 0; i < 100; ++i) {
        field x;
        x.randomize(G);
        field y = x * x;
        assert(y.sqrRoot() * y.sqrRoot() == y);
    }

    // Test 2: Special cases
    field one = 1, zero = 0;
    assert(one.sqrRoot() == one);
    assert(zero.sqrRoot() == zero);
}

void test_bit_gen() {
    int one_cnt = 0, zero_cnt = 0;
    for (int i = 0; i < 100; ++i) {
        field x;
        x.randomize(G);
        field bit = ((x * x).sqrRoot() / x + 1) / 2;
        
        assert(bit.is_bit());
        
        if (bit == 1) {
            one_cnt++;
        } else {
            zero_cnt++;
        }
    }
    cout << "Bit generation: #one=" << one_cnt << ", #zero=" << zero_cnt << '\n';
}

void test_dot_product() {
    const size_t vector_size = 1000;
    const int num_tests = 100;

    for (int test = 0; test < num_tests; ++test) {
        vector<field> a(vector_size), b(vector_size);
        field expected = 0;
        
        for (size_t i = 0; i < vector_size; ++i) {
            a[i].randomize(G);
            b[i].randomize(G);
            expected += a[i] * b[i];
        }

        field result = field::dot_product(a, b);
        assert(result == expected);
    }
}


int main() {
    field_gfp::init_field("0x1fffffffffffffff"); // 2^61 - 1
    
    test_conversion();
    test_mul();
    test_inversion();
    test_sqrRoot();
    test_bit_gen();
    cout << "All tests passed!\n";

    return 0;
}