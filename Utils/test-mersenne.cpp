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
    cout << "One count: " << one_cnt << ", Zero count: " << zero_cnt << '\n';
}

void test_truncate() {
    field x;
    x.randomize(G);
    int f = 13;
    field y = x.truncate(f);
    cout << "Trunc test: " << x << ' ' << y << '\n';
}

int main() {
    field_gfp::init_field("0x1fffffffffffffff"); // 2^61 - 1
    
    test_mul();
    test_inversion();
    test_sqrRoot();
    test_bit_gen();
    test_truncate();
    cout << "All tests passed!\n";

    field x(-1);
    field_gfp x_gfp(-1);

    cout << x << ' ' << x_gfp << '\n';

    cout << Integer(x) << ' ' << Integer(x_gfp) << '\n';
    cout << Integer::convert_unsigned(x) << ' ' << Integer::convert_unsigned(x_gfp) << '\n';
    cout << field(Integer(-1)) << ' ' << field_gfp(Integer(-1)) << '\n';

    cout << field(bigint(-1)) << ' ' << field_gfp(bigint(-1)) << '\n';

    bigint z(-1);
    x.convert_destroy(z);
    z = -1;
    x_gfp.convert_destroy(z);
    cout << x << ' ' << x_gfp << '\n';
    
    cout << bigint(field(-1)) << ' ' << bigint(field_gfp(-1)) << '\n';
    cout << bigint(field(-56)) << ' ' << bigint(field_gfp(-56)) << '\n';

    cout << field(1).sqrRoot() << ' ' << field_gfp(1).sqrRoot() << '\n';
    cout << field(4).sqrRoot() << ' ' << field_gfp(4).sqrRoot() << '\n';
    cout << field(9).sqrRoot() << ' ' << field_gfp(9).sqrRoot() << '\n';
    cout << field(16).sqrRoot() << ' ' << field_gfp(16).sqrRoot() << '\n';
    cout << field(25).sqrRoot() << ' ' << field_gfp(25).sqrRoot() << '\n';
    cout << field(36).sqrRoot() << ' ' << field_gfp(36).sqrRoot() << '\n';


    return 0;
}