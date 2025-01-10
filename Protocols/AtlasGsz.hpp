/*
 * AtlasGsz.hpp
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_HPP_
#define PROTOCOLS_ATLASGSZ_HPP_

#include "AtlasGsz.h"

#include <algorithm>
#include <numeric>

#include "BufferScope.h"

// #define DEBUG_CHECK
// #define DEBUG_DE_LINEARIZATION
// #define DEBUG_DIM_REDUCTION


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
T AtlasGsz<T>::get_random()
{
    return honest.get_random();
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

template<class T>
void AtlasGsz<T>::init_dotprod()
{
    honest.init_dotprod();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
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
    dotprod_info[z_verify.size()] = length;

    T res = honest.finalize_dotprod(length);
    z_verify.push_back(res);

    // The dot product result is stored in the first element,
    // the rest are padded with zeros to maintain 
    // z_verify is of the same length as x_verify and y_verify
    z_verify.insert(z_verify.end(), length - 1, T{0});
    return res;
}

template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

/**
 * @brief Multiplycation with truncation, called by the instruction mul_trunc
 */
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type)
{
    /*
     * We do not call honest.mul_trunc, 
     * because we need the intermediate results for verification.
     * Hence, we copied the code from honest.mul_trunc
     * to call the *_mul_trunc functions defined in this class.
     * These functions in turn call the corresponding functions in honest,
     * and store the intermediate results for verification.
     */

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
    x_verify.push_back(x);
    y_verify.push_back(y);
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
    T pre_trunc;
    T res = honest.finalize_mul_trunc(k, f, &pre_trunc);
    z_verify.push_back(pre_trunc);

    return res;
}

template<class T>
void AtlasGsz<T>::init_dotprod_trunc()
{
    honest.init_dotprod_trunc();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
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
    dotprod_info[z_verify.size()] = length;
    T pre_trunc;
    T res = honest.finalize_dotprod_trunc(length, k, f, &pre_trunc);
    z_verify.push_back(pre_trunc);
    z_verify.insert(z_verify.end(), length - 1, T{0});

    return res;
}

template<class T>
void AtlasGsz<T>::prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc)
{
    honest.prepare_with_solved_bits(product, k, f, proc);
}


/**
 * @brief Verification protocol in GSZ20
 * 
 * @details
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

    // Not sure if this will increase performance
    // BufferScope _(honest, 2 * x_verify.size());

    de_linearization();
    while (x_verify.size() > 1) {
        dimension_reduction();
    }
    randomization();
    
    x_verify.clear();
    y_verify.clear();
    // z_verify and dotprod_info are cleared in de_linearization
}

template<class T>
void AtlasGsz<T>::de_linearization()
{
    z_de_linearized = 0;

    // Random coin
    typename T::open_type r = local_mc.POpen(get_random(), this->P);

    vector<typename T::open_type> random_coeffs(x_verify.size());
    random_coeffs[0] = r;

    // We compute and store the random coefficients, not compute it on the fly, 
    // to enable the use of std algorithms, which may be faster
    
    // Special case for the first element
    int i;
    if (const auto it = dotprod_info.find(0); it != dotprod_info.end()) {
        // Use the same random coefficient for one dot product
        std::fill_n(random_coeffs.begin(), it->second, r);
        i = it->second;
    } else {
        i = 1;
    }
    // Compute the rest of the coefficients
    for (; i < static_cast<int>(x_verify.size()); ++i) {
        auto it = dotprod_info.find(i);
        if (it != dotprod_info.end()) {
            // Use the same random coefficient for one dot product
            std::fill_n(random_coeffs.begin() + i, it->second, random_coeffs[i - 1] * r);
            i += it->second - 1;
        } else {
            random_coeffs[i] = random_coeffs[i - 1] * r;
        }
    }
    dotprod_info.clear();

    // x_verify = (x_0 r^0, x_1 r^1, ..., x_n r^n); y_verify is unchanged
    std::transform(x_verify.begin(), x_verify.end(), random_coeffs.begin(), x_verify.begin(),
                    std::multiplies<typename T::open_type>());
    
    // z_de_linearized = z_0 r^0 + z_1 r^1 + ... + z_n r^n
    z_de_linearized = std::inner_product(z_verify.begin(), z_verify.end(), random_coeffs.begin(), T{0});
    z_verify.clear();

#ifdef DEBUG_DE_LINEARIZATION
    typename T::MAC_Check debug_mc;
    vector<typename T::open_type> x_verify_open, y_verify_open;
    debug_mc.POpen(x_verify_open, x_verify, this->P);
    debug_mc.POpen(y_verify_open, y_verify, this->P);
    
    cerr << "\nDe-linearization\n";
    cerr << "random_coeffs: ";
    for (auto c: random_coeffs) {
        cerr << c << " ";
    }
    cerr << "\nx_verify: ";
    for (auto x: x_verify_open) {
        cerr << x << " ";
    }
    cerr << "\ny_verify: ";
    for (auto y: y_verify_open) {
        cerr << y << " ";
    }
    cerr << "\nz_de_linearized: " << debug_mc.POpen(z_de_linearized, this->P) << '\n';
#endif
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


    T random_point = local_mc.POpen(get_random(), this->P);

    // Evaluate f_i(random_point) and g_i(random_point), just put them in x_verify and y_verify
    for (int i = 0; i < half_size; ++i) {
        x_verify.push_back(f_coeffs[i][0] + f_coeffs[i][1] * random_point);
        y_verify.push_back(g_coeffs[i][0] + g_coeffs[i][1] * random_point);
    }
    // Evaluate h(random_point), put it in z_de_linearized
    z_de_linearized = h_coeffs[0] + h_coeffs[1] * random_point + h_coeffs[2] * random_point * random_point;


#ifdef DEBUG_DIM_REDUCTION
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
 * Verify the last triple from dimension_reduction
 * 
 * Since we have only one triple left,
 * we use the triple sacrifice technique instead of
 * the original protocol in https://ia.cr/2020/134.
 */
template<class T>
void AtlasGsz<T>::randomization()
{

    T a = get_random();
    T b = get_random();
    T c = this->mul(a, b);

    typename T::clear alpha = local_mc.POpen(get_random(), P);
    T rho = alpha * x_verify[0] + a;
    T sigma = y_verify[0] + b;

    local_mc.init_open(P, 2);
    local_mc.prepare_open(rho);
    local_mc.prepare_open(sigma);
    local_mc.exchange(P);
    auto rho_open = local_mc.finalize_open();
    auto sigma_open = local_mc.finalize_open();

    T v = alpha * z_de_linearized - c + sigma_open * a + rho_open * b - rho_open * sigma_open;
    auto v_open = local_mc.POpen(v, P);

    if (v_open != 0) {
        throw mac_fail("AtlasGsz: Verification failed");
    }
}

#endif /* PROTOCOLS_ATLASGSZ_HPP_ */
