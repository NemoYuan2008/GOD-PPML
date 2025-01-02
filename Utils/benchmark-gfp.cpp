#include "Math/gfp.h"
#include "Math/gfp.hpp"
#include "Math/Mersenne.h"
#include "Math/Mersenne.hpp"
#include "Math/Setup.h"
#include "Tools/time-func.h"
#include <random>

template<typename T>
void cleanup(vector<T>& v) {
    v.clear();
    v.shrink_to_fit();
}

int main() {
    const int kIterations = 50'000'000;

    long long p = 2305843009213693951LL; // 2^61 - 1
    bigint bg_p(to_string(p)); // 2^61 - 1
    
    Timer timer;

    std::default_random_engine gen(std::random_device{}());
    std::uniform_int_distribution<long long> dis;

    vector<long long> a, b;
    a.reserve(kIterations);
    b.reserve(kIterations);

    cout << "Generating random numbers...\n";
    timer.start();
    for (int i = 0; i < kIterations; i++) {
        a.emplace_back(dis(gen) & p);
        b.emplace_back(dis(gen) & p);
    }
    timer.stop();
    cout << "Time to generate random numbers: " << timer.elapsed() << " seconds\n\n";
    timer.reset();


    using field1 = gfp_<0, 1>;
    field1::init_field(bg_p, true);

    cout << "Initializing and copying vectors for gfp_ with Montgomery multiplication...\n";
    vector<field1> a_f1, b_f1, c_f1;
    a_f1.reserve(kIterations);
    b_f1.reserve(kIterations);
    c_f1.reserve(kIterations);

    timer.start();
    for (int i = 0; i < kIterations; i++) {
        a_f1.emplace_back(a[i]);
        b_f1.emplace_back(b[i]);
        c_f1.emplace_back();
    }
    timer.stop();
    cout << "Time to initialize and copy vectors: " << timer.elapsed() << " seconds\n";
    timer.reset();

    cout << "Multiplying vectors with Montgomery multiplication...\n";
    timer.start();
    for (int i = 0; i < kIterations; i++) {
        c_f1[i] = a_f1[i] * b_f1[i];
    }
    timer.stop();
    cout << "Time with Montgomery multiplication: " << timer.elapsed() << " seconds\n\n";
    timer.reset();
    cleanup(a_f1); cleanup(b_f1); cleanup(c_f1);


    using field2 = gfp_<1, 1>;
    field2::init_field(bg_p, false);

    cout << "Initializing and copying vectors for gfp_ without Montgomery multiplication...\n";
    vector<field2> a_f2, b_f2, c_f2;
    a_f2.reserve(kIterations);
    b_f2.reserve(kIterations);
    c_f2.reserve(kIterations);
    
    timer.start();
    for (int i = 0; i < kIterations; i++) {
        a_f2.emplace_back(a[i]);
        b_f2.emplace_back(b[i]);
        c_f2.emplace_back();
    }
    timer.stop();
    cout << "Time to initialize and copy vectors: " << timer.elapsed() << " seconds\n";
    timer.reset();

    cout << "Multiplying vectors without Montgomery multiplication...\n";
    timer.start();
    for (int i = 0; i < kIterations; i++) {
        c_f2[i] = a_f2[i] * b_f2[i];
    }
    timer.stop();
    cout << "Time without Montgomery multiplication: " << timer.elapsed() << " seconds\n\n";
    timer.reset();
    cleanup(a_f2); cleanup(b_f2); cleanup(c_f2);


    using field3 = Mersenne<61>;
    field3::init_field(bg_p, false); // Does nothing

    cout << "Copying vectors for Mersenne multiplication...\n";
    vector<field3> a_f3, b_f3, c_f3;
    a_f3.reserve(kIterations);
    b_f3.reserve(kIterations); 
    c_f3.reserve(kIterations);

    timer.start();
    for (int i = 0; i < kIterations; i++) {
        a_f3.emplace_back(a[i]);
        b_f3.emplace_back(b[i]);
        c_f3.emplace_back();
    }
    timer.stop();
    cout << "Time to initialize and copy vectors: " << timer.elapsed() << " seconds\n";
    timer.reset();

    cout << "Multiplying vectors with Mersenne multiplication...\n";
    timer.start();
    for (int i = 0; i < kIterations; i++) {
        c_f3[i] = a_f3[i] * b_f3[i];
    }
    timer.stop();
    cout << "Time with Mersenne multiplication: " << timer.elapsed() << " seconds\n\n";


    int i = rand() % kIterations;
    cout << a_f3[i] << ' ' << b_f3[i] << ' ' << c_f3[i] << '\n'; // To prevent compiler optimization

    return 0;
}