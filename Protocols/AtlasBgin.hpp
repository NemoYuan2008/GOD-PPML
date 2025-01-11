/*
 * AtlasBgin.hpp
 */

#ifndef PROTOCOLS_ATLASBGIN_HPP_
#define PROTOCOLS_ATLASBGIN_HPP_

#include <cmath>

#include "AtlasBgin.h"

#define DEBUG_CHECK
#define DEBUG_DE_LINEARIZATION
#define DEBUG_PROVE_DEG2_REL

template<class T>
AtlasBgin<T>::AtlasBgin(Player& P) 
    : honest(P), shamir_input(nullptr, P), P(P)
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

    // Not sure if this will increase performance
    // BufferScope _(honest, 2 * x_verify.size());

    de_linearization();
    prove_deg2_rel();
    
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
 * Protocol 3.3 in BGIN20
 * 
 * Note that the protocol in the paper is for a single party,
 * but here we execute the protocol for in parallel for all parties,
 * i.e., this function is the batched version of the protocol.
 */
template<class T>
void AtlasBgin<T>::prove_deg2_rel() {
    /**
     * Notes on the notation:
     * 
     * x_verify corresponds to a in the paper, 
     * y_verify corresponds to b, 
     * psi[i] corresponds to c in P_i's proof.
     * 
     * In the original paper, the values c - q(1) - q(2) is also called b_l,
     * which clashes with the variable 'b' in the paper.
     * we use the variable name 'to_check' for this value.
     */
    
    const int computed_round_count = static_cast<int>(std::ceil(std::log2(x_verify.size())));
    int round_count = 0; // For debugging purposes. TODO: remove

    // to_check[i][j] corresponds to the j-th round's value for P_i
    vector<vector<T>> to_check(P.num_players()); 
    std::for_each(to_check.begin(), to_check.end(), 
                  [computed_round_count](auto& v) { v.reserve(computed_round_count + 2); });

    /*********************************** Step 2 in the paper ***********************************/
    while (x_verify.size() > 2) {
        ++round_count;

        if (x_verify.size() & 1) { // odd length, pad with a zero
            x_verify.emplace_back(0);
            y_verify.emplace_back(0);
        }
        int half_size = x_verify.size() / 2;

        /************************* Compute f_e(2), h_e(2) for all e *************************/
        // We do not follow the paper's notation for the polynomial 'f'
        // We define f_e(x) such that f_e(0) = x[e], f_e(1) = x[half_size + e]
        // and h_e(x) such that h_e(0) = y[e], h_e(1) = y[half_size + e]
        // i.e., we separate the original L polynomials f into L/2 pairs of f_e and h_e
        // Also, the indices and the evaluation points start from 0, not 1.
        // This is done to simplify the implementation and for better cache performance

        vector<T> f_2(half_size); // store f_e(2) for each e
        std::transform(x_verify.begin(), x_verify.begin() + half_size,
                       x_verify.begin() + half_size,
                       f_2.begin(),
                       [](auto a, auto b) { return interpolate_degree_1(a, b, 2); });

        vector<T> h_2(half_size); // store h_e(2) for each e
        std::transform(y_verify.begin(), y_verify.begin() + half_size,
                       y_verify.begin() + half_size,
                       h_2.begin(),
                       [](auto a, auto b) { return interpolate_degree_1(a, b, 2); });

        /************************* Compute q(0), q(1), q(2) *************************/
        // The definition of q(x) becomes q(x) = sum_{e=0}^{L/2-1} f_e(x) h_e(x)
        T q_2 = std::inner_product( // q(2) = sum_{e=0}^{L/2-1} f_e(2) h_e(2)
            f_2.begin(), f_2.end(), h_2.begin(), T{0}); // Compute q(2) first since h_2 maybe in cache
        T q_0 = std::inner_product( // q(0) = sum_{e=0}^{L/2-1} f_e(0) h_e(0) (first half)
            x_verify.begin(), x_verify.begin() + half_size, y_verify.begin(), T{0});
        T q_1 = std::inner_product( // q(1) = sum_{e=0}^{L/2-1} f_e(1) h_e(1) (second half)
            x_verify.begin() + half_size, x_verify.end(), y_verify.begin() + half_size, T{0});
        
        /************************* Each party shares q(0), q(1), q(2) *************************/
        shamir_input.reset_all(P);
        shamir_input.add_from_all(q_0);
        shamir_input.add_from_all(q_1);
        shamir_input.add_from_all(q_2);
        shamir_input.exchange();

        /************************* Compute c - q(0) - q(1) and q(r) *************************/
        // TODO: random_points should be random, not fixed
        vector<typename T::open_type> random_points{432, 1234, 5463}; // One random point for each party's proof
        for (int party_i = 0; party_i < P.num_players(); ++party_i) {
            T q_0_share = shamir_input.finalize(party_i);
            T q_1_share = shamir_input.finalize(party_i);
            T q_2_share = shamir_input.finalize(party_i);
            
            // Store the c - q(1) - q(2) values for each party for later verification
            to_check[party_i].push_back(psi[party_i] - q_0_share - q_1_share);
            
            // Compute q(r)'s for each parties' proof, and use them for the next round
            psi[party_i] = interpolate_degree_2(q_0_share, q_1_share, q_2_share, random_points[party_i]);
        }

        /************************* Compute f_e(r) and h_e(r) for all e *************************/
        // Evaluate f_e and h_e at the random point, and store them in x_verify and y_verify
        // Note that each party only needs to evaluate f_e and h_e for its own random point,
        // it does not need to evaluate f_e and h_e for other parties' random points
        const auto random_point = random_points[P.my_num()];

        std::transform(x_verify.begin(), x_verify.begin() + half_size, // f_e(0) = x_verify[i]
                       x_verify.begin() + half_size, // f_e(1) = x_verify[i + half_size]
                       x_verify.begin(), // store f_e(random_point)
                       [random_point](auto a, auto b) { return interpolate_degree_1(a, b, random_point); });
        x_verify.resize(half_size);
        
        std::transform(y_verify.begin(), y_verify.begin() + half_size, // h_e(0) = y_verify[i]
                       y_verify.begin() + half_size, // h_e(1) = y_verify[i + half_size]
                       y_verify.begin(), // store h_e(random_point)
                       [random_point](auto a, auto b) { return interpolate_degree_1(a, b, random_point); });
        y_verify.resize(half_size);
    }

    /*********************************** Step 3 in the paper ***********************************/
    // The last round, where we have only two elements left
#ifdef DEBUG_PROVE_DEG2_REL
    typename T::MAC_Check debug_mc;
    cerr << "x[0] = " << debug_mc.POpen(x_verify[0], this->P) << '\n'
         << "x[1] = " << debug_mc.POpen(x_verify[1], this->P) << '\n'
         << "y[0] = " << debug_mc.POpen(y_verify[0], this->P) << '\n'
         << "y[1] = " << debug_mc.POpen(y_verify[1], this->P) << '\n';
    
    cerr << "The shares:\n"
         << "x[0] = " << x_verify[0] << '\n'
         << "x[1] = " << x_verify[1] << '\n'
         << "y[0] = " << y_verify[0] << '\n'
         << "y[1] = " << y_verify[1] << '\n';
    
    vector<typename T::open_type> psi_open;
    debug_mc.POpen(psi_open, psi, this->P);
    cerr << "psi: ";
    for (auto p: psi_open) {
        cerr << p << " ";
    }
    cerr << '\n';
#endif

    /************************* Compute f, h at 0, 1, 2, 3, 4 *************************/
    // Note that the order of the points are sightly different from the paper
    array<T, 5> f = {
        x_verify[0], // f(0)
        x_verify[1], // f(1)
        get_random(), // f(2) = random point (w_1 in the paper)
    };
    f[3] = interpolate_degree_2(f[0], f[1], f[2], 3);
    f[4] = interpolate_degree_2(f[0], f[1], f[2], 4);

    array<T, 5> h = {
        y_verify[0], // h(0)
        y_verify[1], // h(1)
        get_random(), // h(2) = random point (w_2 in the paper)
    };
    h[3] = interpolate_degree_2(h[0], h[1], h[2], 3);
    h[4] = interpolate_degree_2(h[0], h[1], h[2], 4);
    
    /************************* Compute q(0), ..., q(4) *************************/
    array<T, 5> q;
    std::transform(f.begin(), f.end(), h.begin(), q.begin(), std::multiplies<T>());

    /************************* Each party shares q(0), ..., q(4) *************************/
    shamir_input.reset_all(P);
    for (auto q_i: q) {
        shamir_input.add_from_all(q_i);
    }
    shamir_input.exchange();

    /************************* Compute c - q(0) - q(1) and q(r) *************************/
    // TODO: random
    vector<typename T::open_type> random_points{431, 345, 789}; // One random point for each party's proof
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        array<T, 5> q_share;
        for (int i = 0; i < 5; ++i) {
            q_share[i] = shamir_input.finalize(party_i);
        }
        
        // Store the c - q(0) - q(1) values for each party for later verification
        to_check[party_i].push_back(psi[party_i] - q_share[0] - q_share[1]);

        // Compute q(r)'s for each parties' proof, for later triple verification
        psi[party_i] = interpolate_degree_4(q_share, random_points[party_i]);
    }
    
    /************************* Compute f(r) and h(r) *************************/
    // This is tricky. 
    // Although there is one pair of f(r) and h(r) in each party's proof,
    // i.e., there should be n pairs of f(r) and h(r) in total,
    // we only need to compute f(r) and h(r) for the random point of the current party.
    // This is because all the f(r) computed by all the parties 
    // actually forms a degree-t Shamir sharing,
    // where the share held by party i is f(r) for the random point of party i.
    // The same applies to h(r).
    // Hence, for the check, we only need to reconstruct f(r), h(r), q(r), 
    // and check the final multiplication triple.
    // WTF, this is so confusing.
    
    // f_r and h_r computed by party i should satisfy f_r * h_r = q_r[i] (q_r is actually psi)
    // TODO
    T random_point = random_points[P.my_num()];
    T f_r = interpolate_degree_4(f, random_point);
    T h_r = interpolate_degree_4(h, random_point);
    cerr << "f_r: " << f_r << '\n';
    cerr << "h_r: " << h_r << '\n';

    /************************* Check if to_check opens to 0 *************************/
    T coin = local_mc.POpen(get_random(), this->P);
    T random_coefficient = coin;
    T to_check_combined = 0;
    for (const auto& v: to_check) {
        for (const auto& t: v) {
            to_check_combined += t * random_coefficient;
            random_coefficient *= coin;
        }
    }
    T to_check_combined_open = local_mc.POpen(to_check_combined, this->P);
    if (to_check_combined_open != 0) {
        throw mac_fail("prove_deg2_rel failed");
    }
    

#ifdef DEBUG_PROVE_DEG2_REL
    cerr << "Round count: " << round_count << '\n';
    cerr << "Computed round count: " << computed_round_count << '\n';

    // typename T::MAC_Check debug_mc;
    vector<vector<typename T::open_type>> to_check_open(P.num_players());
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        debug_mc.POpen(to_check_open[party_i], to_check[party_i], this->P);
    }
    cerr << "to_check: \n";
    for (int party_i = 0; party_i < P.num_players(); ++party_i) {
        cerr << "P_" << party_i << ": ";
        for (auto t: to_check_open[party_i]) {
            cerr << t << " ";
        }
        cerr << '\n';
    }

    // vector<typename T::open_type> psi_open;
    debug_mc.POpen(psi_open, psi, this->P);
    cerr << "psi: ";
    for (auto p: psi_open) {
        cerr << p << " ";
    }
    cerr << '\n';

    cerr << "f_r: " << debug_mc.POpen(f_r, this->P) << '\n';
    cerr << "h_r: " << debug_mc.POpen(h_r, this->P) << '\n';
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

#endif /* PROTOCOLS_ATLASBGIN_HPP_ */
