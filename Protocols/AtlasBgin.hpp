/*
 * AtlasBgin.hpp
 */

#ifndef PROTOCOLS_ATLASBGIN_HPP_
#define PROTOCOLS_ATLASBGIN_HPP_

#include "AtlasBgin.h"

// #define DEBUG_CHECK
#define DEBUG_DE_LINEARIZATION

template<class T>
AtlasBgin<T>::AtlasBgin(Player& P) : honest(P), P(P)
{
    x_verify.reserve(OnlineOptions::singleton.batch_size);
    y_verify.reserve(OnlineOptions::singleton.batch_size);
}

template<class T>
AtlasBgin<T>::~AtlasBgin()
{
    check();
}

template<class T>
void AtlasBgin<T>::init(Preprocessing<T>& prep, typename T::MAC_Check& MC)
{
    honest.init(prep, MC);
    this->prep = &prep;
    (void) MC;
}

template<class T>
void AtlasBgin<T>::init_mul()
{
    honest.init_mul();
}

template<class T>
void AtlasBgin<T>::prepare_mul(const T& x, const T& y, int)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul(x, y);
}

template<class T>
void AtlasBgin<T>::exchange()
{
    honest.exchange();
}

template<class T>
T AtlasBgin<T>::finalize_mul(int)
{
    T res = honest.finalize_mul();
    z_verify.push_back(res);
    return res;
}

template<class T>
T AtlasBgin<T>::get_random()
{
    return honest.get_random();
}

template<class T>
void AtlasBgin<T>::init_dotprod()
{
    honest.init_dotprod();
}

template<class T>
void AtlasBgin<T>::prepare_dotprod(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_dotprod(x, y);
}

template<class T>
void AtlasBgin<T>::next_dotprod()
{
    honest.next_dotprod();
}

template<class T>
T AtlasBgin<T>::finalize_dotprod(int length)
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
void AtlasBgin<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

template<class T>
void AtlasBgin<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

template<class T>
void AtlasBgin<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type)
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
            prepare_mul_trunc(x, y, info.k, info.f);
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
void AtlasBgin<T>::init_mul_trunc(int length)
{
    honest.init_mul_trunc(length);
}

template<class T>
void AtlasBgin<T>::prepare_mul_trunc(const T& x, const T& y, int k, int f)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul_trunc(x, y, k, f);
}

template<class T>
void AtlasBgin<T>::exchange_mul_trunc()
{
    honest.exchange_mul_trunc();
}

template<class T>
T AtlasBgin<T>::finalize_mul_trunc(int k, int f)
{
    T pre_trunc;
    T res = honest.finalize_mul_trunc(k, f, &pre_trunc);
    z_verify.push_back(pre_trunc);
    return res;
}

template<class T>
void AtlasBgin<T>::init_dotprod_trunc()
{
    honest.init_dotprod_trunc();
}

template<class T>
void AtlasBgin<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_dotprod_trunc(x, y);
}

template<class T>
void AtlasBgin<T>::next_dotprod_trunc(int k, int f)
{
    honest.next_dotprod_trunc(k, f);
}

template<class T>
void AtlasBgin<T>::exchange_dotprod_trunc()
{
    honest.exchange_dotprod_trunc();
}

template<class T>
T AtlasBgin<T>::finalize_dotprod_trunc(int length, int k, int f)
{
    dotprod_info[z_verify.size()] = length;
    T pre_trunc;
    T res = honest.finalize_dotprod_trunc(length, k, f, &pre_trunc);
    z_verify.push_back(pre_trunc);
    z_verify.insert(z_verify.end(), length - 1, T{0});
    return res;
}

template<class T>
void AtlasBgin<T>::prepare_with_solved_bits(const typename T::open_type& product, int k, int f)
{
    honest.prepare_with_solved_bits(product, k, f);
}

template<class T>
void AtlasBgin<T>::check()
{
    if (x_verify.empty())
        return;

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
    
    x_verify.clear();
    y_verify.clear();
    // z_verify and dotprod_info are cleared in de_linearization       
}


template<class T>
void AtlasBgin<T>::de_linearization()
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

    // z_de_linearized = z_0 r^0 + z_1 r^1 + ... + z_n r^n
    z_de_linearized = std::inner_product(z_verify.begin(), z_verify.end(), random_coeffs.begin(), T{0});
    z_verify.clear();

    // x_verify = (x_0 r^0, x_1 r^1, ..., x_n r^n); y_verify is unchanged
    std::transform(x_verify.begin(), x_verify.end(), random_coeffs.begin(), x_verify.begin(),
                    std::multiplies<typename T::open_type>());
    
    T psi_2t = std::inner_product(x_verify.begin(), x_verify.end(), y_verify.begin(), T{0});
    auto rec_factor = Shamir<T>::get_rec_factor(P.my_num(), P.num_players());
    T psi_additive = rec_factor * psi_2t;

#ifdef DEBUG_DE_LINEARIZATION
    typename T::MAC_Check debug_mc;
    typename T::MAC_Check_2t debug_mc_2t;

    cerr << "\nz_de_linearized: " << debug_mc.POpen(z_de_linearized, this->P) << '\n';
    cerr << "psi_2t: " << debug_mc_2t.POpen(psi_2t, this->P) << '\n';
    cerr << "psi_additive: " << psi_additive << '\n';
#endif
}



#endif
