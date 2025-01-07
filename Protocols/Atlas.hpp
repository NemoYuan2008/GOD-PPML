/*
 * Atlas.hpp
 *
 */

/* 
 * TODO: Some Optimizations that can be done:
 *
 * 1. Use lazy mod for prepare_dotprod_trunc and prepare_dotprod
 * 2. Pass-by-value for T
 * 3. In mul_trunc and dotprod_trunc, the k and f are fixed, maybe omit them both here and in the instruction, and add an instruction to set them
 */


#ifndef PROTOCOLS_ATLAS_HPP_
#define PROTOCOLS_ATLAS_HPP_

#include "Atlas.h"

template<class T>
Atlas<T>::~Atlas()
{
#ifdef VERBOSE
    if (not double_sharings.empty())
        cerr << double_sharings.size() << " double sharings left" << endl;
#endif
#ifdef DEBUG_MUL_CNT
    cerr << "\n~Atlas<T>::Atlas\n"
         << "T: " << typeid(T).name() << '\n'
         << "T::clear: " << typeid(typename T::clear).name() << '\n'
         << "mul_count: " << mul_count << '\n'
         << "multrunc_count: " << multrunc_count << '\n';
#endif
}

template<class T>
array<T, 2> Atlas<T>::get_double_sharing()
{
    if (double_sharings.empty())
    {
        SeededPRNG G;
        PRNG G2 = G;
        auto random = shamir.get_randoms(G, 0);
        auto random2 = shamir2.get_randoms(G2, 0);
        assert(random.size() == random2.size());
        assert(random.size() % P.num_players() == 0);
        for (size_t i = 0; i < random.size(); i++)
            double_sharings.push_back({{random2.at(i), random.at(i)}});
    }

    auto res = double_sharings.back();
    double_sharings.pop_back();
    return res;
}

template<class T>
void Atlas<T>::init_mul()
{
    oss.reset();
    oss2.reset();
    masks.clear();
    base_king = next_king;
}

template<class T>
void Atlas<T>::prepare_mul(const T& x, const T& y, int)
{
#ifdef DEBUG_MUL_CNT
    ++mul_count;
#endif
    prepare(x * y);
}

template<class T>
void Atlas<T>::prepare(const typename T::open_type& product)
{
    auto r = get_double_sharing();
    (product + r[0]).pack(oss2[next_king]);
    next_king = (next_king + 1) % P.num_players();
    masks.push_back(r[1]);
}

template<class T>
void Atlas<T>::exchange()
{
    P.send_receive_all(oss2, oss);
    oss.mine = oss2.mine;

    int t = ShamirMachine::s().threshold;
    if (reconstruction.empty())
        for (int i = 0; i < 2 * t + 1; i++)
            reconstruction.push_back(Shamir<T>::get_rec_factor(i, 2 * t + 1));
    resharing.reset_all(P);

    for (size_t j = P.get_player(-base_king); j < masks.size();
            j += P.num_players())
    {
        typename T::open_type e;
        for (int i = 0; i < 2 * t + 1; i++)
        {
            auto tmp = oss[i].template get<T>();
            e += tmp * reconstruction.at(i);
        }
        resharing.add_mine(e);
    }

    for (size_t i = 0; i < min(masks.size(), size_t(P.num_players())); i++)
    {
        int j = (base_king + i) % P.num_players();
        resharing.add_sender(j);
    }

    resharing.exchange();
}

template<class T>
T Atlas<T>::finalize_mul(int)
{
    T res = resharing.finalize(base_king) - masks.next();
    base_king = (base_king + 1) % P.num_players();
    return res;
}

template<class T>
void Atlas<T>::init_dotprod()
{
    init_mul();
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share += x * y;
}

template<class T>
void Atlas<T>::next_dotprod()
{
    prepare(dotprod_share);
    dotprod_share = 0;
}

template<class T>
T Atlas<T>::finalize_dotprod(int)
{
    return finalize_mul();
}

template<class T>
T Atlas<T>::get_random()
{
    return shamir.get_random();
}


template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type) {
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
void Atlas<T>::init_mul_trunc(int length)
{   
    init_mul();
    local_mc_2t.init_open(P, length);
}

template<class T>
void Atlas<T>::prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc)
{
#ifdef DEBUG_MUL_CNT
    ++multrunc_count;
#endif
#ifdef DEBUG_MUL_TRUNC
    cerr << "\nprepare_mul_trunc(): " << "k = " << k << ' ' << "f = " << f << '\n'
         << "x = " << x << ", y = " << y << '\n';
    
    typename T::MAC_Check debug_mc;
    cerr << "x_open = " << debug_mc.POpen(x, P) << ' ' 
         << "y_open = " << debug_mc.POpen(y, P) << '\n';
#endif

    prepare_with_solved_bits(x * y, k, f, proc);
}

/**
 * prepare_with_solved_bits()
 * 
 * This function is like prepare(),
 * but the random mask is from the solved bits, 
 * not from a double sharing.
 */
template<class T>
void Atlas<T>::prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc)
{
    typename T::open_type two_power_k_minus_two = T::power_of_two(1, k - 2); // TODO: we don't need k, we can use prime length

#ifdef DEBUG_MUL_TRUNC
    cerr << "\nprepare_with_solved_bits(): \n"
         << "product = " << product << '\n';

    // Open the product for debugging
    typename T::MAC_Check_2t debug_mc_2t;
    auto product_open = debug_mc_2t.POpen(product, P);
    cerr << "product_open = " << product_open << '\n';
#endif

    // get the individual bits [r_i]
    vector<T> r_bits(k);
    for (auto& r_i : r_bits) {
        proc.DataF.get_one(DATA_BIT, r_i);
    }

    // Compose [r_i] into [r]
    // r = sum_{i=0}^{k-1} r_i * 2^i
    T r = 0;
    for (int i = 0; i < k; ++i) {
        r += r_bits[i] << i;
    }

    T r_msb = r_bits.back();

    // Compute [r'] from [r_i]
    // r' = sum_{i=f}^{k-1} 2^{i-f} * r_i + sum_{i=k-f}^{k-1} 2^i * r_msb
    T r_prime = 0;
    for (int i = f; i < k; ++i) {
        r_prime += r_bits[i] << (i - f);
    }
    for (int i = k - f; i < k; ++i) {
        r_prime += r_msb << i;
    }

    // TODO: a zero-sharing is needed here for security
    auto c = product + r + two_power_k_minus_two;
    local_mc_2t.prepare_open(c);

#ifdef DEBUG_MUL_TRUNC
    // Open r, r_bits, r_msb, r_prime for debugging
    typename T::MAC_Check debug_mc;

    auto r_open = debug_mc.POpen(r, P);
    auto r_msb_open = debug_mc.POpen(r_msb, P);
    auto r_prime_open = debug_mc.POpen(r_prime, P);

    vector<typename T::open_type> r_bits_open;
    debug_mc.POpen(r_bits_open, r_bits, P);

    // Compose the bits
    T r_composed = 0;
    for (int i = 0; i < k; ++i) {
        r_composed += r_bits_open[i] << i;
    }

    // Print the values for debugging
    cerr << "r_open= " << r_open << '\n'
         << "r_composed = " << r_composed << '\n'
         << "r_bits_open = ";
    for (int i = 0; i < k; ++i) {
        cerr << r_bits_open[i] << ' ';
    }
    cerr << '\n'
         << "r_msb_open = " << r_msb_open << '\n'
         << "r_prime_open = " << r_prime_open << '\n';
#endif

    next_king = (next_king + 1) % P.num_players();

    masks.push_back(r_msb);
    masks.push_back(r_prime);
}

template<class T>
void Atlas<T>::exchange_mul_trunc()
{
    local_mc_2t.exchange(P);
}

template<class T>
T Atlas<T>::finalize_mul_trunc(int k, int f)
{
    typename T::clear two_power_k_minus_f = T::power_of_two(1, k - f);
    typename T::clear two_power_k_minus_f_minus_two = T::power_of_two(1, k - f - 2);

    typename T::clear c = local_mc_2t.finalize_open();
    typename T::clear c_msb = c >> (k - 1);
    typename T::clear c_trunc = c.truncate(f);

    T r_msb = masks.next();
    T r_prime = masks.next();

    typename T::clear e(1);
    e = (e - r_msb) * c_msb;


#ifdef DEBUG_MUL_TRUNC
    typename T::MAC_Check debug_mc;
    auto r_msb_open = debug_mc.POpen(r_msb, P);
    auto r_prime_open = debug_mc.POpen(r_prime, P);
    auto e_open = debug_mc.POpen(e, P);

    T res = c_trunc - r_prime + e * (two_power_k_minus_f - 1) - two_power_k_minus_f_minus_two;
    auto res_open = debug_mc.POpen(res, P);

    cerr << "\nfinalize_mul_trunc(): " << "k = " << k << ' ' << "f = " << f << '\n'
         << "two_power_k_minus_f = " << two_power_k_minus_f << '\n'
         << "two_power_k_minus_f_minus_two = " << two_power_k_minus_f_minus_two << '\n'
         << "c = " << c << '\n'
         << "c_trunc = " << c_trunc << '\n'
         << "r_msb_open = " << r_msb_open << '\n'
         << "r_prime_open = " << r_prime_open << '\n'
         << "e_open = " << e_open << '\n'
         << "res_open = " << res_open << '\n';
#endif

    return c_trunc - r_prime + e * (two_power_k_minus_f - 1) - two_power_k_minus_f_minus_two;
}

template<class T>
void Atlas<T>::init_dotprod_trunc()
{
    // TODO: Check the parameter to init_mul_trunc
    init_mul_trunc(1); // We only need one opening
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
#ifdef DEBUG_DOTPROD
    cerr << "\nprepare_dotprod()\n"
         << "x = " << x << ", y = " << y << '\n'
         << "dotprod_share (pre addition): " << dotprod_share << '\n';

    typename T::MAC_Check debug_mc;
    typename T::MAC_Check_2t debug_mc_2t;

    auto x_open = debug_mc.POpen(x, P);
    auto y_open = debug_mc.POpen(y, P);
    auto dotprod_share_open = debug_mc_2t.POpen(dotprod_share, P);

    cerr << "x_open = " << x_open << '\n'
         << "y_open = " << y_open << '\n'
         << "dotprod_share_open (pre addition) = " << dotprod_share_open << '\n';
#endif

    dotprod_share += x * y;
}

template<class T>
void Atlas<T>::next_dotprod_trunc(int k, int f, SubProcessor<T>& proc)
{
#ifdef DEBUG_DOTPROD
    // Open the product for debugging
    typename T::MAC_Check_2t debug_mc_2t;
    auto dotprod_open = debug_mc_2t.POpen(dotprod_share, P);
    cerr << "\nnext_dotprod_trunc()\n"
         << "dotprod_open:\n" << dotprod_open << "\n\n";
#endif

    prepare_with_solved_bits(dotprod_share, k, f, proc);
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::exchange_dotprod_trunc()
{
    exchange_mul_trunc();
}

template<class T>
T Atlas<T>::finalize_dotprod_trunc(int, int k, int f)
{
    return finalize_mul_trunc(k, f);
}


#endif /* PROTOCOLS_ATLAS_HPP_ */
