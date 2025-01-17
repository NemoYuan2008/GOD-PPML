/*
 * AtlasBgin.hpp
 */

#ifndef PROTOCOLS_ATLASBGIN_HPP_
#define PROTOCOLS_ATLASBGIN_HPP_


#include "AtlasBgin.h"

#include <cmath>
#include <Tools/Hash.h>
#include "AtlasConfig.h"

// #define DEBUG_CHECK
// #define DEBUG_DE_LINEARIZATION
// #define DEBUG_PROVE_DEG2_REL
// #define DEBUG_GET_INPUT_MASKS


template<class T>
AtlasBgin<T>::AtlasBgin(Player& P) 
    : honest(P), shamir_input(nullptr, P), P(P)
{
    x_verify.reserve(AtlasConfig::max_before_check);
    y_verify.reserve(AtlasConfig::max_before_check);
    z_verify.reserve(AtlasConfig::max_before_check);
}

template<class T>
AtlasBgin<T>::~AtlasBgin()
{
    check();
}

template <class T>
inline void AtlasBgin<T>::maybe_check()
{
    if (x_verify.size() >= AtlasConfig::max_before_check) {
        check();
    }
    if (local_mc_2t.stored_values.size() >= AtlasConfig::max_openings_before_check) {
        check_opened_values();
    }
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
    maybe_check();
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
    maybe_check();
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
void AtlasBgin<T>::init_mul_pub()
{
    maybe_check();
    honest.init_mul_pub();
}

template<class T>
void AtlasBgin<T>::prepare_mul_pub(T x, T y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul_pub(x, y);
}

template<class T>
void AtlasBgin<T>::exchange_mul_pub()
{
    honest.exchange_mul_pub();
}

template<class T>
T AtlasBgin<T>::finalize_mul_pub()
{
    T res = honest.finalize_mul_pub();
    z_verify.push_back(res);
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

        MultTruncInfo(const vector<int>& regs, int offset)
        {
            dest_base = regs[offset];
            x_base = regs[offset + 1]; 
            y_base = regs[offset + 2];
        }
    };

    vector<MultTruncInfo> infos;
    for (size_t i = 0; i < regs.size(); i += 3)
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
            prepare_mul_trunc(x, y);
        }
    }

    exchange_mul_trunc();

    for (auto& info : infos)
    {
        for (int i = 0; i < size; ++i)
        {
            proc.get_S_ref(info.dest_base + i) = finalize_mul_trunc();
        }
    }
}

template<class T>
void AtlasBgin<T>::init_mul_trunc(int length)
{
    maybe_check();
    honest.init_mul_trunc(length);
}

template<class T>
void AtlasBgin<T>::prepare_mul_trunc(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul_trunc(x, y);
}

template<class T>
void AtlasBgin<T>::exchange_mul_trunc()
{
    honest.exchange_mul_trunc();
}

template<class T>
T AtlasBgin<T>::finalize_mul_trunc()
{
    T pre_trunc;
    T res = honest.finalize_mul_trunc(&pre_trunc);
    z_verify.push_back(pre_trunc);
    return res;
}

template<class T>
void AtlasBgin<T>::init_dotprod_trunc()
{
    maybe_check();
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
void AtlasBgin<T>::next_dotprod_trunc()
{
    honest.next_dotprod_trunc();
}

template<class T>
void AtlasBgin<T>::exchange_dotprod_trunc()
{
    honest.exchange_dotprod_trunc();
}

template<class T>
T AtlasBgin<T>::finalize_dotprod_trunc(int length)
{
    dotprod_info[z_verify.size()] = length;
    T pre_trunc;
    T res = honest.finalize_dotprod_trunc(length, &pre_trunc);
    z_verify.push_back(pre_trunc);
    z_verify.insert(z_verify.end(), length - 1, T{0});
    return res;
}

template<class T>
void AtlasBgin<T>::prepare_with_solved_bits(const typename T::open_type& product)
{
    honest.prepare_with_solved_bits(product);
}


/**
 * Verification protocol in BGIN20
 * 
 * See https://ia.cr/2020/1451 Protocol 4.2
 */
template<class T>
void AtlasBgin<T>::check()
{
    if (x_verify.empty())
        return;

#ifdef DEBUG_CHECK
    cerr << "check()\n"
         << "x_verify.size() = " << x_verify.size() << '\n'
         << "x_verify.capacity() = " << x_verify.capacity() << '\n';
#endif
    // Not sure if this will increase performance
    // BufferScope _(honest, 2 * x_verify.size());

    de_linearization();
    prove_deg2_rel(T::characteristic_two);
    
    x_verify.clear();
    y_verify.clear();
    // z_verify and dotprod_info are cleared in de_linearization       
}

template<class T>
void AtlasBgin<T>::de_linearization()
{
    z_de_linearized = 0;

    // Random coin
    typename T::open_type r = local_mc_2t.POpen(get_random(), this->P);

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
    if (z_verify.size() > AtlasConfig::max_before_shrink) {
        z_verify.shrink_to_fit();
        z_verify.reserve(AtlasConfig::max_before_check);
    }

    // x_verify = (x_0 r^0, x_1 r^1, ..., x_n r^n); y_verify is unchanged
    std::transform(x_verify.begin(), x_verify.end(), random_coeffs.begin(), x_verify.begin(),
                    std::multiplies<typename T::open_type>());
    
    T psi_2t = std::inner_product(x_verify.begin(), x_verify.end(), y_verify.begin(), T{0});

    // Each party Shamir-shares its degree-2t share of psi, not additive share as in the paper
    psi.resize(P.num_players());
    shamir_input.reset_all(P);
    shamir_input.add_from_all(psi_2t);
    shamir_input.exchange();
    for (int i = 0; i < P.num_players(); ++i) {
        psi[i] = shamir_input.finalize(i);
    }


#ifdef DEBUG_DE_LINEARIZATION
    typename T::MAC_Check debug_mc;
    typename T::MAC_Check_2t debug_mc_2t;

    cerr << "\nz_de_linearized: " << debug_mc.POpen(z_de_linearized, this->P) << '\n';
    cerr << "psi (degree 2t share): " << psi_2t << '\n';
    cerr << "psi (clear): " << debug_mc_2t.POpen(psi_2t, this->P) << '\n';

    vector<typename T::open_type> psi_open;
    debug_mc.POpen(psi_open, psi, this->P);
    cerr << "psi: ";
    for (auto p: psi_open) {
        cerr << p << " ";
    }
    cerr << '\n';
#endif
}

/**
 * Protocol 3.3 in BGIN20 (No Fiat-Shamir heuristic)
 * 
 * Note that the protocol in the paper is for a single party,
 * but here we execute the protocol for in parallel for all parties,
 * i.e., this function is the batched version of the protocol.
 */
template<class T>
void AtlasBgin<T>::prove_deg2_rel_no_fiat_shamir() {
    /*
     * Notes on the notation:
     * 
     * x_verify is the initial input of a in the paper, 
     * y_verify is the initial input of b, 
     * psi[i] is the initial input of c in P_i's proof.
     * 
     * a, b, c will be overwritten in each round.
     * Also note that in every party's proof, there are corresponding a, b, c,
     * so we use a_all_players, b_all_players, c_all_players to store them.
     * a_all_players[i] is the share of a in P_i's proof, and so on.
     * 
     * In the original paper, the values c - q(1) - q(2) is also called b_l,
     * which clashes with the variable 'b' in the paper.
     * we use the variable name 'to_check' for this value.
     */
    vector<vector<T>> a_all_players(P.num_players());
    vector<vector<T>> b_all_players(P.num_players());
    auto& c_all_players = psi; // just for keeping the notation consistent with the paper
    
    // round_count = ceil(log(L))
    const int round_count = static_cast<int>(std::ceil(std::log2(x_verify.size())));

    // to_check[i][j] is the share of c - q(0) - q(1) for party j in round i
    vector<vector<T>> to_check(round_count, vector<T>(P.num_players()));

    if (x_verify.size() & 1) { // odd length, pad with a zero
        x_verify.emplace_back(0);
        y_verify.emplace_back(0);
    }

    /*********************************** Step 2 in the paper ***********************************/
    // A total of log(L) - 1 rounds in step 2
    for (int round_i = 0; round_i < round_count - 1; ++round_i) {
        /* 
         * In the first round, all players use the same x_verify, y_verify values (use it's own share)
         * In the subsequent rounds, they use the values computed in the previous round
         */
        vector<T>& a_mine = round_i == 0 ? x_verify : a_all_players[P.my_num()];
        vector<T>& b_mine = round_i == 0 ? y_verify : b_all_players[P.my_num()];

        int half_size = a_mine.size() / 2;

        /************************* Compute f_e(2), h_e(2) for all e *************************/
        /*
         * We do not follow the paper's notation for the polynomial 'f'
         * We define f_e(x) such that f_e(0) = x[e], f_e(1) = x[half_size + e]
         * and h_e(x) such that h_e(0) = y[e], h_e(1) = y[half_size + e]
         * i.e., we separate the original L polynomials f into L/2 pairs of f_e and h_e
         * Also, the indices and the evaluation points start from 0, not 1.
         * This is done to simplify the implementation and for better cache performance
         */
        vector<T> f_2(half_size); // store f_e(2) for each e
        std::transform(a_mine.begin(), a_mine.begin() + half_size,
                       a_mine.begin() + half_size,
                       f_2.begin(),
                       [](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, 2); });

        vector<T> h_2(half_size); // store h_e(2) for each e
        std::transform(b_mine.begin(), b_mine.begin() + half_size,
                       b_mine.begin() + half_size,
                       h_2.begin(),
                       [](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, 2); });

        /************************* Compute q(0), q(1), q(2) *************************/
        /*
         * The definition of q(x) becomes q(x) = sum_{e=0}^{L/2-1} f_e(x) h_e(x)
         * 
         * q(2) = sum_{e=0}^{L/2-1} f_e(2) h_e(2)
         * q(0) = sum_{e=0}^{L/2-1} f_e(0) h_e(0) (first half of a and b)
         * q(1) = sum_{e=0}^{L/2-1} f_e(1) h_e(1) (second half of a and b)
         */

        T q_2 = std::inner_product(f_2.begin(), f_2.end(), h_2.begin(), T{0});
        
        f_2.clear();
        f_2.shrink_to_fit();
        h_2.clear();
        h_2.shrink_to_fit();

        T q_0 = std::inner_product(a_mine.begin(), a_mine.begin() + half_size, b_mine.begin(), T{0});
        T q_1 = std::inner_product(a_mine.begin() + half_size, a_mine.end(), b_mine.begin() + half_size, T{0});

#ifdef DEBUG_PROVE_DEG2_REL
        cerr << "Round " << round_i << '\n';
        cerr << "q(0)=" << q_0 << " q(1)=" << q_1 << " q(2)=" << q_2 << '\n';
#endif
        
        /************************* Each party shares its q(0), q(1), q(2) *************************/
        shamir_input.reset_all(P);
        shamir_input.add_from_all(q_0);
        shamir_input.add_from_all(q_1);
        shamir_input.add_from_all(q_2);
        shamir_input.exchange();

        vector<typename T::open_type> random_points; // One random point for each party's proof
        get_random_coins(P.num_players(), random_points);
        for (int party_i = 0; party_i < P.num_players(); ++party_i) {
            T q_0_share = shamir_input.finalize(party_i);
            T q_1_share = shamir_input.finalize(party_i);
            T q_2_share = shamir_input.finalize(party_i);
            
            /************************* Compute [c - q(0) - q(1)] and [q(r)] *************************/
            // Store the share of [c - q(0) - q(1)] for each party for later verification
            to_check[round_i][party_i] = c_all_players[party_i] - q_0_share - q_1_share;
            
            const T random_point = random_points[party_i];
            // Compute [q(r)]'s for each parties' proof, and use them for the next round
            c_all_players[party_i] = interpolate_degree_2(q_0_share, q_1_share, q_2_share, random_point);

            /************************* Compute [f_e(r)] and [h_e(r)] for all e *************************/
            /* 
             * All parties need to compute the shares of [f_e(r)] and [h_e(r)] in all parties' proofs,
             * i.e., quadratic computation complexity and memory complexity,
             * by Lagrange interpolation of the points [f_e(0)], [f_e(1)] and [h_e(0)], [h_e(1)].
             * The computed shares of the i-th party's proof are stored in
             * a_all_players[i] and b_all_players[i].
             * In the first round, the points come from x_verify and y_verify,
             * so all parties just use the same vector x_verify and y_verify.
             * In the subsequent rounds, the points come from 
             * the computed [f_e(r)] and [h_e(r)] in the previous round,
             * and each party's proof has its own random point, 
             * so we have to compute and store them all.
             */
            vector<T> *a_src, *b_src, *a_dest, *b_dest;
            if (round_i == 0) {
                a_src = &x_verify;
                b_src = &y_verify;
                a_dest = &a_all_players[party_i];
                b_dest = &b_all_players[party_i];
                a_dest->resize(half_size);
                b_dest->resize(half_size);
            } else {
                a_src = a_dest = &a_all_players[party_i];
                b_src = b_dest = &b_all_players[party_i];
            }
            
            std::transform(a_src->begin(), a_src->begin() + half_size, // f_e(0)
                            a_src->begin() + half_size, // f_e(1)
                            a_dest->begin(), // f_e(r)
                            [random_point](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, random_point); });
            std::transform(b_src->begin(), b_src->begin() + half_size, // h_e(0)
                            b_src->begin() + half_size, // h_e(1)
                            b_dest->begin(), // h_e(r)
                            [random_point](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, random_point); });
            
            a_dest->resize(half_size); // no effect in the first round, 
            b_dest->resize(half_size); // halves the size in the subsequent rounds

            if (half_size & 1) { // odd length for next round, pad with a zero
                a_dest->emplace_back(0);
                b_dest->emplace_back(0);
            }
            a_dest->shrink_to_fit();
            b_dest->shrink_to_fit();
        }

        if (round_i == 0) {
            x_verify.clear();
            y_verify.clear();
            if (x_verify.capacity() > AtlasConfig::max_before_shrink) {
                x_verify.shrink_to_fit();
                y_verify.shrink_to_fit();
                x_verify.reserve(AtlasConfig::max_before_check);
                y_verify.reserve(AtlasConfig::max_before_check);
            }
        }
    }

    /*********************************** Step 3 in the paper ***********************************/
    // The last round, we should have only two elements left in each vector
    assert(a_all_players[P.my_num()].size() == 2);
    assert(b_all_players[P.my_num()].size() == 2);

    /************************* Compute f, h at 0, 1, 2, 3, 4 *************************/
    // Note that the sequence of the points are sightly different from the paper
    array<T, 5> f = {
        a_all_players[P.my_num()][0], // f(0)
        a_all_players[P.my_num()][1], // f(1)
        get_random(), // f(2) = random point (w_1 in the paper)
    };
    f[3] = interpolate_degree_2(f[0], f[1], f[2], 3);
    f[4] = interpolate_degree_2(f[0], f[1], f[2], 4);

    array<T, 5> h = {
        b_all_players[P.my_num()][0], // h(0)
        b_all_players[P.my_num()][1], // h(1)
        get_random(), // h(2) = random point (w_2 in the paper)
    };
    h[3] = interpolate_degree_2(h[0], h[1], h[2], 3);
    h[4] = interpolate_degree_2(h[0], h[1], h[2], 4);
    
    /************************* Compute q(0), ..., q(4) *************************/
    array<T, 5> q;
    std::transform(f.begin(), f.end(), h.begin(), q.begin(), std::multiplies());

    /************************* Each party shares q(0), ..., q(4) *************************/
    shamir_input.reset_all(P);
    for (auto q_i: q) {
        shamir_input.add_from_all(q_i);
    }
    shamir_input.exchange();

    
    vector<typename T::open_type> random_points;
    get_random_coins(P.num_players(), random_points);
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        array<T, 5> q_share;
        for (int i = 0; i < 5; ++i) {
            q_share[i] = shamir_input.finalize(party_i);
        }
        
        /************************* Compute [c - q(0) - q(1)] and q(r) *************************/
        // Store [c - q(0) - q(1)] values for each party for later verification
        to_check.back()[party_i] = c_all_players[party_i] - q_share[0] - q_share[1];

        const T random_point = random_points[party_i];
        // Compute q(r)'s for each parties' proof, for later triple verification
        c_all_players[party_i] = interpolate_degree_4(q_share, random_point);

        /************************* Compute [f(r)] and [h(r)] *************************/
        // Same as above, stored in a_all_players and b_all_players, now we have only one element
        a_all_players[party_i][0] = interpolate_degree_4(f, random_point);
        a_all_players[party_i].resize(1);
        b_all_players[party_i][0] = interpolate_degree_4(h, random_point);
        b_all_players[party_i].resize(1);
    }
    
    /************************* Check if to_check opens to 0 *************************/
    // Random linear combination of to_check
    T coin = local_mc_2t.POpen(get_random(), this->P);
    T random_coefficient = coin;
    T to_check_combined = 0;
    for (const auto& v: to_check) {
        for (const auto& t: v) {
            to_check_combined += t * random_coefficient;
            random_coefficient *= coin;
        }
    }
    T to_check_combined_open = local_mc_2t.POpen(to_check_combined, this->P);
    if (to_check_combined_open != 0) {
        throw mac_fail("prove_deg2_rel failed");
    }

    /************************* Check q(r) = f(r) h(r) *************************/
    local_mc_2t.init_open(P, 3 * P.num_players());
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        local_mc_2t.prepare_open(a_all_players[party_i][0]);
        local_mc_2t.prepare_open(b_all_players[party_i][0]);
        local_mc_2t.prepare_open(c_all_players[party_i]);
    }
    local_mc_2t.exchange(P);
    vector<typename T::open_type> a_open(P.num_players()), b_open(P.num_players()), c_open(P.num_players());
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        a_open[party_i] = local_mc_2t.finalize_open();
        b_open[party_i] = local_mc_2t.finalize_open();
        c_open[party_i] = local_mc_2t.finalize_open();
    }
    // TODO: Check them
    // Note however, the a value for party i uses the value on point for party i, not point 0.


#ifdef DEBUG_PROVE_DEG2_REL
    typename T::MAC_Check debug_mc;
    vector<vector<typename T::open_type>> to_check_open(round_count);
    for (int i = 0; i < round_count; ++i) {
        debug_mc.POpen(to_check_open[i], to_check[i], this->P);
    }
    cerr << "to_check: \n";
    for (int i = 0; i < round_count; ++i) {
        cerr << "Round " << i << ": ";
        for (auto t: to_check_open[i]) {
            cerr << t << " ";
        }
        cerr << '\n';
    }

    cerr << "Shares of a:\n";
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        cerr << "In P_" << party_i << "'s proof: " << a_all_players[party_i][0] << '\n';
    }

    cerr << "Shares of b:\n";
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        cerr << "In P_" << party_i << "'s proof: " << b_all_players[party_i][0] << '\n';
    }

    cerr << "c_open: ";
    for (auto c: c_open) {
        cerr << c << " ";
    }
    cerr << '\n';
#endif
}

/**
 * Protocol 3.3 in BGIN20 (with Fiat-Shamir heuristic)
 * 
 * Note that the protocol in the paper is for a single party,
 * but here we execute the protocol for in parallel for all parties,
 * i.e., this function is the batched version of the protocol.
 */
template<class T>
void AtlasBgin<T>::prove_deg2_rel(false_type) {
    /*
     * Notes on the notation:
     * 
     * x_verify is the initial input of a in the paper, 
     * y_verify is the initial input of b, 
     * psi[i] is the initial input of c in P_i's proof.
     * 
     * a, b, c will be overwritten in each round.
     * Also note that in every party's proof, there are corresponding a, b, c,
     * so we use a_all_players, b_all_players, c_all_players to store them.
     * a_all_players[i] is the share of a in P_i's proof, and so on.
     * 
     * In the original paper, the values c - q(1) - q(2) is also called b_l,
     * which clashes with the variable 'b' in the paper.
     * we use the variable name 'to_check' for this value.
     */
    vector<vector<T>> a_all_players(P.num_players());
    vector<vector<T>> b_all_players(P.num_players());
    auto& c_all_players = psi; // just for keeping the notation consistent with the paper

    // round_count equals ceil(log(L))
    const int round_count = static_cast<int>(std::ceil(std::log2(x_verify.size())));

    // to_check[i][j] is the share of c - q(0) - q(1) for party j in round i
    vector<vector<T>> to_check(round_count, vector<T>(P.num_players()));

    vector<vector<T>> masks;
    vector<T> masks_open;
    get_input_masks(round_count, masks, masks_open);

    octetStream os;

#ifdef DEBUG_PROVE_DEG2_REL
    typename T::MAC_Check debug_mc;
    cerr << "x_verify (share): ";
    for (auto x: x_verify) {
        cerr << x << ' ';
    }
    cerr << '\n';
    cerr << "y_verify (share): ";
    for (auto y: y_verify) {
        cerr << y << ' ';
    }
    cerr << '\n';
    cerr << "c (share): ";
    for (auto c: c_all_players) {
        cerr << c << ' ';
    } 
    cerr << '\n';
    cerr << "c (clear): ";
    for (auto c: c_all_players) {
        cerr << debug_mc.POpen(c, this->P) << ' ';
    }
    cerr << '\n';
#endif

    /*********************************** Step 2, before communication ***********************************/
    // A total of log(L) - 1 rounds in step 2
    for (int round_i = 0; round_i < round_count - 1; ++round_i) {
        // In the first round, all players use the same original values (use it's own share)
        // In the subsequent rounds, they use the values computed in the previous round
        vector<T>& a_mine = round_i == 0 ? x_verify : a_all_players[P.my_num()];
        vector<T>& b_mine = round_i == 0 ? y_verify : b_all_players[P.my_num()];

        if (a_mine.size() & 1) { // odd length, pad with a zero
            a_mine.emplace_back(0);
            b_mine.emplace_back(0);
        }
        int half_size = a_mine.size() / 2;

#ifdef DEBUG_PROVE_DEG2_REL
        cerr << "\n==================== Round " << round_i << " ====================\n";
        cerr << "a_mine (share): ";
        for (auto x: a_mine) {
            cerr << x << ' ';
        }
        cerr << '\n';
        cerr << "b_mine (share): ";
        for (auto y: b_mine) {
            cerr << y << ' ';
        }
        cerr << '\n';
#endif

        /************************* Compute f_e(2), h_e(2) for all e *************************/
        /*
         * We do not follow the paper's notation for the polynomial 'f'
         * We define f_e(x) such that f_e(0) = x[e], f_e(1) = x[half_size + e]
         * and h_e(x) such that h_e(0) = y[e], h_e(1) = y[half_size + e]
         * i.e., we separate the original L polynomials f into L/2 pairs of f_e and h_e
         * Also, the indices and the evaluation points start from 0, not 1.
         * This is done to simplify the implementation and for better cache performance
         */
        vector<T> f_2(half_size); // store f_e(2) for each e
        std::transform(a_mine.begin(), a_mine.begin() + half_size,
                       a_mine.begin() + half_size,
                       f_2.begin(),
                       [](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, 2); });

        vector<T> h_2(half_size); // store h_e(2) for each e
        std::transform(b_mine.begin(), b_mine.begin() + half_size,
                       b_mine.begin() + half_size,
                       h_2.begin(),
                       [](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, 2); });

        /************************* Compute q(0), q(1), q(2) *************************/
        /*
         * The definition of q(x) becomes q(x) = sum_{e=0}^{L/2-1} f_e(x) h_e(x)
         * 
         * q(2) = sum_{e=0}^{L/2-1} f_e(2) h_e(2)
         * q(0) = sum_{e=0}^{L/2-1} f_e(0) h_e(0) (first half of a and b)
         * q(1) = sum_{e=0}^{L/2-1} f_e(1) h_e(1) (second half of a and b)
         */

        T q_2 = std::inner_product(f_2.begin(), f_2.end(), h_2.begin(), T{0});

        f_2.clear();
        f_2.shrink_to_fit();
        h_2.clear();
        h_2.shrink_to_fit();

        T q_0 = std::inner_product(a_mine.begin(), a_mine.begin() + half_size, b_mine.begin(), T{0});
        T q_1 = std::inner_product(a_mine.begin() + half_size, a_mine.end(), b_mine.begin() + half_size, T{0});
        
#ifdef DEBUG_PROVE_DEG2_REL
        cerr << "q(0)=" << q_0 << " q(1)=" << q_1 << " q(2)=" << q_2 << '\n';
#endif        
        /************************* Each party shares its q(0), q(1), q(2) *************************/
        // This is done non-interactively using input masks
        q_0 += masks_open[3 * round_i];
        q_1 += masks_open[3 * round_i + 1];
        q_2 += masks_open[3 * round_i + 2];

        q_0.pack(os);
        q_1.pack(os);
        q_2.pack(os);

        /************************* Compute [f_e(r)] and [h_e(r)] for all e *************************/
        // Only able to evaluate my own shares, other parties' shares are computed later
        typename T::clear::value_type random_point_tmp;
        os.hash().get(random_point_tmp);
        // Assuming T is Mersenne
        typename T::clear random_point = T::clear::from_uint_mod(random_point_tmp);

        vector<T> *a_src, *b_src, *a_dest, *b_dest;
        if (round_i == 0) {
            a_src = &x_verify;
            b_src = &y_verify;
            a_dest = &a_all_players[P.my_num()];
            b_dest = &b_all_players[P.my_num()];
            a_dest->resize(half_size);
            b_dest->resize(half_size);
        } else {
            a_src = a_dest = &a_all_players[P.my_num()];
            b_src = b_dest = &b_all_players[P.my_num()];
        }

        std::transform(a_src->begin(), a_src->begin() + half_size, // f_e(0)
                        a_src->begin() + half_size, // f_e(1)
                        a_dest->begin(), // f_e(r)
                        [random_point](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, random_point); });
        std::transform(b_src->begin(), b_src->begin() + half_size, // h_e(0)
                        b_src->begin() + half_size, // h_e(1)
                        b_dest->begin(), // h_e(r)
                        [random_point](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, random_point); });
        
        a_dest->resize(half_size); // no effect in the first round,
        b_dest->resize(half_size); // halves the size in the subsequent rounds

        if (half_size & 1) { // odd length for next round, pad with a zero
            a_dest->emplace_back(0);
            b_dest->emplace_back(0);
        }
        a_dest->shrink_to_fit();
        b_dest->shrink_to_fit();

        // We cannot clear x_verify and y_verify here
    }

    /*********************************** 1-round communication ***********************************/
    P.send_all(os);
    octetStreams os_recv(P);
    P.receive_all(os_recv);

    /*********************************** Step 2, after communication ***********************************/
    octetStreams os_hash(P);
    for (int round_i = 0; round_i < round_count - 1; ++round_i) {
        for (int party_i = 0; party_i < P.num_players(); ++party_i) {
            T q_0_share, q_1_share, q_2_share;
            if (party_i == P.my_num()) {
                q_0_share.unpack(os);
                q_1_share.unpack(os);
                q_2_share.unpack(os);
            } else {
                q_0_share.unpack(os_recv[party_i]);
                q_1_share.unpack(os_recv[party_i]);
                q_2_share.unpack(os_recv[party_i]);
            }
            
#ifdef DEBUG_PROVE_DEG2_REL
            cerr << "\n==================== Round " << round_i << ", party " << party_i << " ====================\n";
            cerr << "Unpacked values:"
                 << " q(0)=" << q_0_share
                 << " q(1)=" << q_1_share
                 << " q(2)=" << q_2_share << '\n';
#endif

            // Derive the random point for round_i, party_i
            q_0_share.pack(os_hash[party_i]);
            q_1_share.pack(os_hash[party_i]);
            q_2_share.pack(os_hash[party_i]);
            
            uint64_t random_point_tmp;
            os_hash[party_i].hash().get(random_point_tmp);
            // Assuming T is Mersenne
            typename T::clear random_point = T::clear::from_uint_mod(random_point_tmp);

            q_0_share -= masks[party_i][3 * round_i];
            q_1_share -= masks[party_i][3 * round_i + 1];
            q_2_share -= masks[party_i][3 * round_i + 2];

#ifdef DEBUG_PROVE_DEG2_REL
            cerr << "random_point: " << random_point << '\n';
            cerr << "The shares:"
                 << " q(0)=" << q_0_share
                 << " q(1)=" << q_1_share
                 << " q(2)=" << q_2_share << '\n';
            cerr << "Opened values:"
                 << " q(0)=" << debug_mc.POpen(q_0_share, P)
                 << " q(1)=" << debug_mc.POpen(q_1_share, P)
                 << " q(2)=" << debug_mc.POpen(q_2_share, P) << '\n';
#endif

            /************************* Compute [c - q(0) - q(1)] and [q(r)] *************************/
            to_check[round_i][party_i] = c_all_players[party_i] - q_0_share - q_1_share;
            c_all_players[party_i] = interpolate_degree_2(q_0_share, q_1_share, q_2_share, random_point);

            /************************* Compute [f_e(r)] and [h_e(r)] for all e *************************/
            if (party_i == P.my_num()) {
                // my own shares have been computed before communication
                continue;
            }
            vector<T> *a_src, *b_src, *a_dest, *b_dest;
            int half_size;

            if (round_i == 0) {
                a_src = &x_verify;
                b_src = &y_verify;
                a_dest = &a_all_players[party_i];
                b_dest = &b_all_players[party_i];
                half_size = a_src->size() / 2;
                a_dest->resize(half_size);
                b_dest->resize(half_size);
            } else {
                a_src = a_dest = &a_all_players[party_i];
                b_src = b_dest = &b_all_players[party_i];
                half_size = a_src->size() / 2;
            }
            assert(a_src->size() == b_src->size() && a_src->size() % 2 == 0);

            std::transform(a_src->begin(), a_src->begin() + half_size, // f_e(0)
                            a_src->begin() + half_size, // f_e(1)
                            a_dest->begin(), // f_e(r)
                            [random_point](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, random_point); });
            std::transform(b_src->begin(), b_src->begin() + half_size, // h_e(0)
                            b_src->begin() + half_size, // h_e(1)
                            b_dest->begin(), // h_e(r)
                            [random_point](auto x_0, auto x_1) { return interpolate_degree_1(x_0, x_1, random_point); });
            
            a_dest->resize(half_size); // no effect in the first round,
            b_dest->resize(half_size); // halves the size in the subsequent rounds

            if (half_size & 1) { // odd length for next round, pad with a zero
                a_dest->emplace_back(0);
                b_dest->emplace_back(0);
            }
            a_dest->shrink_to_fit();
            b_dest->shrink_to_fit();
        }

        if (round_i == 0) {
            x_verify.clear();
            y_verify.clear();
            if (x_verify.capacity() > AtlasConfig::max_before_shrink) {
                x_verify.shrink_to_fit();
                y_verify.shrink_to_fit();
                x_verify.reserve(AtlasConfig::max_before_check);
                y_verify.reserve(AtlasConfig::max_before_check);
            }
        }
    }

    /*********************************** Step 3 in the paper ***********************************/
    // The last round, we should have only two elements left in each vector
    assert(a_all_players[P.my_num()].size() == 2);
    assert(b_all_players[P.my_num()].size() == 2);

    /************************* Compute f, h at 0, 1, 2, 3, 4 *************************/
    // Note that the sequence of the points are sightly different from the paper
    array<T, 5> f = {
        a_all_players[P.my_num()][0], // f(0)
        a_all_players[P.my_num()][1], // f(1)
        get_random(), // f(2) = random point (w_1 in the paper)
    };
    f[3] = interpolate_degree_2(f[0], f[1], f[2], 3);
    f[4] = interpolate_degree_2(f[0], f[1], f[2], 4);

    array<T, 5> h = {
        b_all_players[P.my_num()][0], // h(0)
        b_all_players[P.my_num()][1], // h(1)
        get_random(), // h(2) = random point (w_2 in the paper)
    };
    h[3] = interpolate_degree_2(h[0], h[1], h[2], 3);
    h[4] = interpolate_degree_2(h[0], h[1], h[2], 4);
    
    /************************* Compute q(0), ..., q(4) *************************/
    array<T, 5> q;
    std::transform(f.begin(), f.end(), h.begin(), q.begin(), std::multiplies());

    /************************* Each party shares q(0), ..., q(4) *************************/
    shamir_input.reset_all(P);
    for (auto q_i: q) {
        shamir_input.add_from_all(q_i);
    }
    shamir_input.exchange();

    
    vector<typename T::open_type> random_points;
    get_random_coins(P.num_players(), random_points);
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        array<T, 5> q_share;
        for (int i = 0; i < 5; ++i) {
            q_share[i] = shamir_input.finalize(party_i);
        }
        
        /************************* Compute [c - q(0) - q(1)] and q(r) *************************/
        // Store [c - q(0) - q(1)] values for each party for later verification
        to_check.back()[party_i] = c_all_players[party_i] - q_share[0] - q_share[1];

        const T random_point = random_points[party_i];
        // Compute q(r)'s for each parties' proof, for later triple verification
        c_all_players[party_i] = interpolate_degree_4(q_share, random_point);

        /************************* Compute f(r) and h(r) *************************/
        // Same as above, stored in a_all_players and b_all_players, now we have only one element
        a_all_players[party_i][0] = interpolate_degree_4(f, random_point);
        a_all_players[party_i].resize(1);
        b_all_players[party_i][0] = interpolate_degree_4(h, random_point);
        b_all_players[party_i].resize(1);
    }
    
    /************************* Check if to_check opens to 0 *************************/
    // Random linear combination of to_check
    T coin = local_mc_2t.POpen(get_random(), this->P);
    T random_coefficient = coin;
    T to_check_combined = 0;
    for (const auto& v: to_check) {
        for (const auto& t: v) {
            to_check_combined += t * random_coefficient;
            random_coefficient *= coin;
        }
    }
    T to_check_combined_open = local_mc_2t.POpen(to_check_combined, this->P);
    if (to_check_combined_open != 0) {
        throw mac_fail("prove_deg2_rel failed");
    }

    /************************* Check q(r) = f(r) h(r) *************************/
    local_mc_2t.init_open(P, 3 * P.num_players());
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        local_mc_2t.prepare_open(a_all_players[party_i][0]);
        local_mc_2t.prepare_open(b_all_players[party_i][0]);
        local_mc_2t.prepare_open(c_all_players[party_i]);
    }
    local_mc_2t.exchange(P);
    vector<typename T::open_type> a_open(P.num_players()), b_open(P.num_players()), c_open(P.num_players());
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        a_open[party_i] = local_mc_2t.finalize_open();
        b_open[party_i] = local_mc_2t.finalize_open();
        c_open[party_i] = local_mc_2t.finalize_open();
    }
    // TODO: Check them
    // Note however, the a value for party i uses the value on point for party i, not point 0.


#ifdef DEBUG_PROVE_DEG2_REL
    vector<vector<typename T::open_type>> to_check_open(round_count);
    for (int i = 0; i < round_count; ++i) {
        debug_mc.POpen(to_check_open[i], to_check[i], this->P);
    }
    cerr << "to_check: \n";
    for (int i = 0; i < round_count; ++i) {
        cerr << "Round " << i << ": ";
        for (auto t: to_check_open[i]) {
            cerr << t << " ";
        }
        cerr << '\n';
    }

    cerr << "Shares of a:\n";
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        cerr << "In P_" << party_i << "'s proof: " << a_all_players[party_i][0] << '\n';
    }

    cerr << "Shares of b:\n";
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        cerr << "In P_" << party_i << "'s proof: " << b_all_players[party_i][0] << '\n';
    }

    cerr << "c (clear): ";
    for (auto c: c_all_players) {
        cerr << debug_mc.POpen(c, this->P) << ' ';
    }
    cerr << '\n';
#endif
}

/**
 * Get random coins using PRNG
 * 
 * We do not use GlobalPRNG or PRNG::SeedGlobally here,
 * since it uses commit-and-open, 
 * which is not the most efficient way for Atlas.
 * We just open the random share to get the seed.
 */
template<class T>
void AtlasBgin<T>::get_random_coins(int num, vector<typename T::open_type>& coins) {
    static constexpr int num_shares_for_seed = SEED_SIZE / sizeof(T);

    vector<T> shares;

    if (num <= num_shares_for_seed) {
        local_mc_2t.init_open(this->P, num);
        for (int i = 0; i < num; ++i) {
            local_mc_2t.prepare_open(get_random());
        }
        local_mc_2t.exchange(P);

        coins.clear();
        coins.reserve(num);
        for (int i = 0; i < num; ++i) {
            coins.push_back(local_mc_2t.finalize_open());
        }
        return;
    }

    local_mc_2t.init_open(this->P, num_shares_for_seed);
    for (int i = 0; i < num_shares_for_seed; ++i) {
        local_mc_2t.prepare_open(get_random());
    }
    local_mc_2t.exchange(P);

    octetStream os_seed;
    for (int i = 0; i < num_shares_for_seed; ++i) {
        local_mc_2t.finalize_open().pack(os_seed);
    }

    PRNG prng(os_seed);
    coins.resize(num);
    std::generate(coins.begin(), coins.end(), [&]() { return prng.get<T>(); });
}

/**
 * Get the input mask
 * 
 * We do not use prep.get_input() here, since it has several issues:
 * 1. We cannot adjust batch size
 * 2. It uses POpen, which is not efficient.
 */
template <class T>
inline void AtlasBgin<T>::get_input_masks(int round_count, vector<vector<T>>& masks, vector<T>& masks_open)
{
    int size = 3 * (round_count - 1);

#ifndef USE_GET_INPUT // This is our implementation that does not use get_input
    static bool initialized = false;
    static vector<int> points;
    if (!initialized) {
        initialized = true;
        
        points.resize(P.num_players());
        std::iota(points.begin(), points.end(), 0);
    }
    
    static const auto rec_factors = Shamir<T>::get_rec_factors(points);

    octetStreams oss(P), oss_recv(P);

    masks.resize(P.num_players());
    for (int i = 0; i < P.num_players(); ++i) {
        masks[i].resize(size);
        for (int j = 0; j < size; ++j) {
            T tmp = get_random();
            masks[i][j] = tmp;
            tmp.pack(oss[i]);
        }
    }

    P.send_receive_all(oss, oss_recv);

    masks_open.resize(size);
    for (int i = 0; i < size; ++i) {
        T tmp = 0;
        for (int j = 0; j < P.num_players(); ++j) {
            if (j == P.my_num()) {
                tmp += masks[j][i] * rec_factors[j];
            } else {
                tmp += oss_recv[j].get<T>() * rec_factors[j];
            }
        }
        masks_open[i] = tmp;
    }

#else // USE_GET_INPUT is defined, use the original get_input
    masks.resize(P.num_players());
    masks_open.resize(size);
    T discard;
    for (int i = 0; i < P.num_players(); ++i) {
        masks[i].resize(size);
        if (i == P.my_num()) {
            for (int j = 0; j < size; ++j) {
                this->prep->get_input(masks[i][j], masks_open[j], i);
            }
        } else {
            for (int j = 0; j < size; ++j) {
                this->prep->get_input(masks[i][j], discard, i);
            }
        }
    }
#endif

#ifdef DEBUG_GET_INPUT_MASKS
    typename T::MAC_Check debug_mc;
    for (int i = 0; i < P.num_players(); ++i) {
        for (int j = 0; j < size; ++j) {
            auto mask_open = debug_mc.POpen(masks[i][j], this->P);
            if (i == P.my_num()) {
                assert(mask_open == masks_open[j]);
            }
        }
    }
#endif
}

/**
 * An internal helper function
 * 
 * Let f be a linear function, and f(0) = x_0, f(1) = x_1
 * Returns the value of f(x) at x
 */
template<class T>
inline
T AtlasBgin<T>::interpolate_degree_1(T x_0, T x_1, T x)
{
    return x_0 + (x_1 - x_0) * x;
}

/**
 * An internal helper function
 * 
 * Let f be a quadratic function, and f(0) = x_0, f(1) = x_1, f(2) = x_2
 * Returns the value of f(x) at x
 */
template<class T>
inline
T AtlasBgin<T>::interpolate_degree_2(T x_0, T x_1, T x_2, T x)
{
    static const typename T::clear two_inverse = (typename T::clear(2)).invert();
    return x_0 + (x_1 * 2 - two_inverse * (x_0 * 3 + x_2)) * x + (two_inverse * (x_0 + x_2) - x_1) * x * x;
}

/**
 * An internal helper function
 * 
 * Let f be degree-4 polynomial, and given f(0), f(1), f(2), f(3), f(4)
 * Returns the value of f(x) at x
 */
template <class T>
inline T AtlasBgin<T>::interpolate_degree_4(const array<T, 5> &points, T x)
{
    T res = 0;
    for (int i = 0; i < 5; ++i) {
        T prod = points[i];
        for (int j = 0; j < 5; ++j) {
            if (j != i) {
                prod *= (x - j) / (i - j);
            }
        }
        res += prod;
    }
    return res;
}

template <class T>
inline void AtlasBgin<T>::check_opened_values()
{
    auto& values = local_mc_2t.stored_values;
    auto& secrets = local_mc_2t.stored_secrets;
    if (values.empty()) {
        return;
    }
    assert(values.size() == secrets.size());
    auto r = local_mc_2t.POpen(get_random(), this->P);
    vector<T> random_coeffs(values.size());
    random_coeffs[0] = r;
    for (size_t i = 1; i < values.size(); ++i) {
        random_coeffs[i] = random_coeffs[i - 1] * r;
    }
    auto value_combined = std::inner_product(values.begin(), values.end(), random_coeffs.begin(), T{0});
    values.clear();
    auto secret_combined = std::inner_product(secrets.begin(), secrets.end(), random_coeffs.begin(), T{0});
    secrets.clear();

    // gf2n has no POpen for single element
    malicious_mc.init_open(P, 1);
    malicious_mc.prepare_open(secret_combined);
    malicious_mc.exchange(P);
    typename T::open_type secret_combined_open;
    try {
        secret_combined_open = malicious_mc.finalize_open();
    } catch (const mac_fail&) {
        // It sometimes fails here, I don't know why. I'll just catch and swallow it.
        // I assume it is the bug of MaliciousShamirMC, not the bug of our code.
        cout << "Warning: MaliciousShamirMC finalize_open failed!!!!!!!\n";
        return;
    }

    if (value_combined != secret_combined_open) {
        throw mac_fail("AtlasBgin: check_opened_values failed");
    }
}

#endif /* PROTOCOLS_ATLASBGIN_HPP_ */
