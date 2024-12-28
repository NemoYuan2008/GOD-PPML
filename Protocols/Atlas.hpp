/*
 * Atlas.hpp
 *
 */

#ifndef PROTOCOLS_ATLAS_HPP_
#define PROTOCOLS_ATLAS_HPP_

#include "Atlas.h"

template<class T>
Atlas<T>::~Atlas()
{
    // cerr << "~Atlas\n";
#ifdef VERBOSE
    if (not double_sharings.empty())
        cerr << double_sharings.size() << " double sharings left" << endl;
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
    prepare(x * y);
}

template<class T>
void Atlas<T>::prepare(const typename T::open_type& product)
{
    // Mask the product with a double sharing, then put the masked product in oss2
    // open_type is gpf_ in our context
    // r[0] is of degree 2t
    // r[1] is of degree t
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

# define VERBOSE_MUL_TRUNC

template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc) {
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
        infos.emplace_back(regs, i);


    // Perform the multiplicationss
    init_mul();
    for (const auto& info : infos)
    {
        for (int i = 0; i < size; i++)
        {
            // Get operands from registers
            T x = proc.get_S_ref(info.x_base + i);
            T y = proc.get_S_ref(info.y_base + i);
            
            // Prepare multiplication
            // prepare_mul(x, y);
            prepare_mul_trunc(x, y, info.k, info.f, proc);
        }
    }

    // Single exchange for all multiplications
    exchange();

    // Finalize all multiplications
    for (auto& info : infos)
    {
        for (int i = 0; i < size; i++)
        {
            // Get result and store in destination register
            proc.get_S_ref(info.dest_base + i) = finalize_mul();
        }
    }
}

template<class T>
void Atlas<T>::prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc)
{
    // Prepare the multiplication of x and y, and truncate the result to k - f bits
    prepare_mask_with_solved_bits(x * y, k, f, proc);
}

template<class T>
void Atlas<T>::prepare_mask_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc)
{
    // This function deserves a better name, but I can't think of one :(
    // This function is like prepare(), 
    // but the random mask is from the solved bits, not from a double sharing

    // TODO: the following two lines are computed every time
    typename T::open_type two_power_k_minus_two = T::power_of_two(1, k - 2);
    // typename T::open_type two_power_k_minus_f = T::power_of_two(1, k - f);
    // typename T::open_type two_power_k_minus_f_minus_two = T::power_of_two(1, k - f - 2);

    // get the individual bits [r_i] of the random mask r
    vector<T> r_bits(k);
    for (auto& r_i : r_bits) {
        proc.DataF.get_one(DATA_BIT, r_i);
    }

    // Compose the random bits into a random number [r]
    // r = sum_{i=0}^{k-1} r_i * 2^i
    T r = 0;
    for (int i = 0; i < k; ++i) {
        r += r_bits[i] << i;
    }

    T r_msb = r_bits.back();

    // Compute [r']
    // r' = sum_{i=f}^{k-1} 2^{i-f} * r_i + sum_{i=k-f}^{k-1} 2^i * r_msb
    T r_prime = 0;
    for (int i = f; i < k; ++i) {
        r_prime += r_bits[i] << (i - f);
    }
    for (int i = k - f; i < k; ++i) {
        r_prime += r_msb << i;
    }

    auto c = product + r + two_power_k_minus_two;
    c.pack(oss2[next_king]);
    next_king = (next_king + 1) % P.num_players();

    masks.push_back(r_prime);
}

#endif /* PROTOCOLS_ATLAS_HPP_ */
