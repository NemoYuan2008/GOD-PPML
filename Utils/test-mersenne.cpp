#include "Math/Mersenne.h"
#include "Math/Mersenne.hpp"
#include <cassert>
#include <random>

using field = Mersenne<61>;

void test_mersenne_inversion() {
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, field::prime - 1);

    // Test 1: x * x^(-1) = 1
    for (int i = 0; i < 100; i++) {
        field x(dis(gen));
        field x_inv = x.invert();
        assert(x * x_inv == field(1));
    }

    // Test 2: Special case - multiplicative identity
    field one = 1;
    assert(one.invert() == one);

    // Test 3: (x*y)^(-1) = y^(-1) * x^(-1)
    for (int i = 0; i < 100; i++) {
        field x = dis(gen);
        field y = dis(gen);
        field xy_inv = (x * y).invert();
        field x_inv_y_inv = y.invert() * x.invert();
        assert(xy_inv == x_inv_y_inv);
    }
}

int main() {
    test_mersenne_inversion();
    cout << "All tests passed!\n";

    return 0;
}