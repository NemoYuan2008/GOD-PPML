/*
 * AtlasGsz.hpp
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_HPP_
#define PROTOCOLS_ATLASGSZ_HPP_

#include <algorithm>
#include <numeric>

#include "AtlasGsz.h"

#define DEBUG_CHECK


template<class T>
AtlasGsz<T>::AtlasGsz(Player& P) : honest(P), P(P)
{
    // TODO: maybe use a power of 2 for the batch size
    x_verify.reserve(OnlineOptions::singleton.batch_size);
    y_verify.reserve(OnlineOptions::singleton.batch_size);
}


template<class T>
AtlasGsz<T>::~AtlasGsz()
{
    check();
}

template<class T>
void AtlasGsz<T>::init_mul()
{
    honest.init_mul();
}

template<class T>
void AtlasGsz<T>::prepare_mul(const T& x, const T& y, int)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul(x, y);
}

// template<class T>
// void AtlasGsz<T>::prepare(const typename T::open_type& product)
// {
//     honest.prepare(product);
// }

template<class T>
void AtlasGsz<T>::exchange()
{
    honest.exchange();
}

template<class T>
T AtlasGsz<T>::finalize_mul(int)
{
    T res = honest.finalize_mul();
    z_verify.push_back(res);
    return res;
}

// Dot product operations
template<class T>
void AtlasGsz<T>::init_dotprod()
{
    honest.init_dotprod();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod(const T& x, const T& y)
{
    honest.prepare_dotprod(x, y);
}

template<class T>
void AtlasGsz<T>::next_dotprod()
{
    honest.next_dotprod();
}

template<class T>
T AtlasGsz<T>::finalize_dotprod(int length)
{
    return honest.finalize_dotprod(length);
}

// Copied from the class Atlas to avoid making the *_mul_trunc functions virtual
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

// Copied from the class Atlas to avoid making the *_mul_trunc functions virtual
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

// Copied from the class Atlas to avoid making the *_mul_trunc functions virtual
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type)
{
    // Parse the arguments
    struct MultTruncInfo {
        int dest_base;       // Destination register
        int x_base;         // First operand
        int y_base;         // Second operand 
        int k;             // Bit length
        int f;             // Number of bits to truncate

        MultTruncInfo(const vector<int>& regs, int offset)
        {
            dest_base = regs[offset];
            x_base = regs[offset + 1]; 
            y_base = regs[offset + 2];
            k = regs[offset + 3];
            f = regs[offset + 4];
        }
    };

    vector<MultTruncInfo> infos;
    for (size_t i = 0; i < regs.size(); i += 5) 
    {
        infos.emplace_back(regs, i);
    }

    init_mul_trunc(infos.size() * size);

    for (const auto& info : infos)
    {
        for (int i = 0; i < size; ++i)
        {
            T x = proc.get_S_ref(info.x_base + i);
            T y = proc.get_S_ref(info.y_base + i);
            
            prepare_mul_trunc(x, y, info.k, info.f, proc);
        }
    }

    exchange_mul_trunc();

    for (auto& info : infos)
    {
        for (int i = 0; i < size; ++i)
        {
            proc.get_S_ref(info.dest_base + i) = finalize_mul_trunc(info.k, info.f);
        }
    }
}


template<class T>
void AtlasGsz<T>::init_mul_trunc(int length)
{
    honest.init_mul_trunc(length);
}

template<class T>
void AtlasGsz<T>::prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc)
{
    honest.prepare_mul_trunc(x, y, k, f, proc);
}

template<class T>
void AtlasGsz<T>::exchange_mul_trunc()
{
    honest.exchange_mul_trunc();
}

template<class T>
T AtlasGsz<T>::finalize_mul_trunc(int k, int f)
{
    return honest.finalize_mul_trunc(k, f);
}


// Truncated dot product operations
template<class T>
void AtlasGsz<T>::init_dotprod_trunc()
{
    honest.init_dotprod_trunc();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
    honest.prepare_dotprod_trunc(x, y);
}

template<class T>
void AtlasGsz<T>::next_dotprod_trunc(int k, int f, SubProcessor<T>& proc)
{
    honest.next_dotprod_trunc(k, f, proc);
}

template<class T>
void AtlasGsz<T>::exchange_dotprod_trunc()
{
    honest.exchange_dotprod_trunc();
}

template<class T>
T AtlasGsz<T>::finalize_dotprod_trunc(int length, int k, int f)
{
    return honest.finalize_dotprod_trunc(length, k, f);
}

template<class T>
void AtlasGsz<T>::prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc)
{
    honest.prepare_with_solved_bits(product, k, f, proc);
}


/**
 * Verification protocol in GSZ20
 * 
 * We only implement compression factor 2, 
 * i.e., the vector is divided into two parts in each iteration.
 * 
 * See https://ia.cr/2020/134 for details.
 */
template<class T>
void AtlasGsz<T>::check()
{
    if (x_verify.empty()) {
        return;
    }

#ifdef DEBUG_CHECK
    typename T::MAC_Check debug_mc;
    vector<typename T::open_type> x_open, y_open, z_open;
    
    debug_mc.POpen(x_open, x_verify, this->P);
    debug_mc.POpen(y_open, y_verify, this->P);
    debug_mc.POpen(z_open, z_verify, this->P);

    cerr << "\nCheck\n" << "x_verify: ";
    for (auto x: x_open) {
        cerr << x << " ";
    }
    cerr << '\n' << "y_verify: ";
    for (auto y: y_open) {
        cerr << y << " ";
    }
    cerr << '\n' << "z_verify: ";
    for (auto z: z_open) {
        cerr << z << " ";
    }
    cerr << '\n';
#endif

    de_linearization();
    while (x_verify.size() > 1) {
        dimension_reduction();
    }
    randomization();
    
    x_verify.clear();
    y_verify.clear();
    z_verify.clear();
}

template<class T>
void AtlasGsz<T>::de_linearization()
{
    z_de_linearized = 0;

    typename T::open_type r = 100;  // TODO: r should be a random number
    vector<typename T::open_type> random_coeffs(x_verify.size());
    random_coeffs[0] = r;

    // We store the random coefficients, not compute it on the fly, 
    // to enable the use of std algorithms, which may be faster
    for (size_t i = 1; i < x_verify.size(); ++i) {
        random_coeffs[i] = random_coeffs[i - 1] * r;
    }

    // x_verify = (x_0 r^0, x_1 r^1, ..., x_n r^n); y_verify is unchanged
    std::transform(x_verify.begin(), x_verify.end(), random_coeffs.begin(), x_verify.begin(),
                    std::multiplies<typename T::open_type>());
    // z_de_linearized = z_0 r^0 + z_1 r^1 + ... + z_n r^n
    z_de_linearized = std::inner_product(z_verify.begin(), z_verify.end(), random_coeffs.begin(), T{0});

    z_verify.clear();
}

/**
 * Protocol 14 and 12 in https://ia.cr/2020/134
 */
template<class T>
void AtlasGsz<T>::dimension_reduction()
{
    if (x_verify.size() & 1) {
        x_verify.emplace_back(0);
        y_verify.emplace_back(0);
    }
    int half_size = x_verify.size() / 2;

    // Stored as f_i(x) = f_coeffs[i][0] + f_coeffs[i][1] * x
    vector<vector<typename T::clear>> f_coeffs(half_size, vector<typename T::clear>(2));
    vector<vector<typename T::clear>> g_coeffs(half_size, vector<typename T::clear>(2));

    // TODO: maybe use iterators for better cache performance
    for (int i = 0; i < half_size; ++i) {
        // Let f_i(0) = x_verify[i], f_i(1) = x_verify[i + half_size], we compute the coefficients
        f_coeffs[i][0] = x_verify[i];
        f_coeffs[i][1] = x_verify[i + half_size] - f_coeffs[i][0];
        // same for g(x)
        g_coeffs[i][0] = y_verify[i];
        g_coeffs[i][1] = y_verify[i + half_size] - g_coeffs[i][0];
    }

    honest.init_dotprod();

    // c_0 = a_0 dot b_0
    for (int i = 0; i < half_size; ++i) {
        honest.prepare_dotprod(x_verify[i], y_verify[i]);
    }
    x_verify.clear();
    y_verify.clear();
    honest.next_dotprod();

    // c_2 = f(2) dot g(2)
    for (int i = 0; i < half_size; ++i) {
        // f_i(2) * g_i(2)
        honest.prepare_dotprod(
            f_coeffs[i][0] + f_coeffs[i][1] * 2,
            g_coeffs[i][0] + g_coeffs[i][1] * 2
        );
    }
    honest.next_dotprod();

    honest.exchange();

    T c_0 = honest.finalize_dotprod();
    T c_1 = z_de_linearized - c_0;
    T c_2 = honest.finalize_dotprod();

    // Let h(0) = c_0, h(1) = c_1, h(2) = c_2, we compute the coefficients
    static const typename T::clear two_inverse = (typename T::clear(2)).invert();
    vector<typename T::clear> h_coeffs(3);
    h_coeffs[0] = c_0;
    h_coeffs[1] = c_1 * 2 - two_inverse * (c_0 * 3 + c_2);
    h_coeffs[2] = (c_0 + c_2) * two_inverse - c_1;


    T random_point = 100; // TODO: get a random point

    // Evaluate f_i(random_point) and g_i(random_point), just put them in x_verify and y_verify
    for (int i = 0; i < half_size; ++i) {
        x_verify.push_back(f_coeffs[i][0] + f_coeffs[i][1] * random_point);
        y_verify.push_back(g_coeffs[i][0] + g_coeffs[i][1] * random_point);
    }
    // Evaluate h(random_point), put it in z_de_linearized
    z_de_linearized = h_coeffs[0] + h_coeffs[1] * random_point + h_coeffs[2] * random_point * random_point;


#ifdef DEBUG_CHECK
    typename T::MAC_Check debug_mc;
    for (int i = 0; i < half_size; ++i) {
        auto f_0_open = debug_mc.POpen(f_coeffs[i][0], this->P);
        auto f_1_open = debug_mc.POpen(f_coeffs[i][1], this->P);
        auto g_0_open = debug_mc.POpen(g_coeffs[i][0], this->P);
        auto g_1_open = debug_mc.POpen(g_coeffs[i][1], this->P);
        cerr << "f_" << i << "(x) = " << f_0_open << " + " << f_1_open << "x\n"
             << "g_" << i << "(x) = " << g_0_open << " + " << g_1_open << "x\n";
    }
    auto h_0_open = debug_mc.POpen(h_coeffs[0], this->P);
    auto h_1_open = debug_mc.POpen(h_coeffs[1], this->P);
    auto h_2_open = debug_mc.POpen(h_coeffs[2], this->P);
    cerr << "h(x) = " << h_0_open << " + " << h_1_open << "x + " << h_2_open << "x^2\n";

    auto c_0_open = debug_mc.POpen(c_0, this->P);
    auto c_1_open = debug_mc.POpen(c_1, this->P);
    auto c_2_open = debug_mc.POpen(c_2, this->P);
    cerr << "c_0=" << c_0_open << " c_1=" << c_1_open << " c_2=" << c_2_open << '\n';

    vector<typename T::open_type> x_verify_open, y_verify_open;
    debug_mc.POpen(x_verify_open, x_verify, this->P);
    debug_mc.POpen(y_verify_open, y_verify, this->P);
    cerr << "random_point = " << random_point << '\n';
    cerr << "x_verify: ";
    for (auto x: x_verify_open) {
        cerr << x << " ";
    }
    cerr << '\n' << "y_verify: ";
    for (auto y: y_verify_open) {
        cerr << y << " ";
    }
    cerr << '\n' << "z_de_linearized: " << debug_mc.POpen(z_de_linearized, this->P) << '\n';
#endif
}

/**
 * Protocol 15 in https://ia.cr/2020/134
 * 
 */
template<class T>
void AtlasGsz<T>::randomization()
{
    local_mc.init_open(P, 3);

    // TODO: need another triple to randomize
    local_mc.prepare_open(x_verify[0]);
    local_mc.prepare_open(y_verify[0]);
    local_mc.prepare_open(z_de_linearized);
    local_mc.exchange(P);
    auto x_open = local_mc.finalize_open();
    auto y_open = local_mc.finalize_open();
    auto z_open = local_mc.finalize_open();
    if (x_open * y_open != z_open) {
        throw mac_fail("Incorrect multiplication result");
    }
}

#endif /* PROTOCOLS_ATLASGSZ_HPP_ */
