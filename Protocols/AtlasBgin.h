/*
 * AtlasBgin.h
 */

#ifndef PROTOCOLS_ATLASBGIN_H_
#define PROTOCOLS_ATLASBGIN_H_

#include "Atlas.h"

#include <unordered_map>
#include "Tools/random.h"

/**
 * Maliciously secure ATLAS protocol using BGIN verification
 */
template<class T>
class AtlasBgin : public ProtocolBase<T>
{
private:
    Atlas<T> honest;
    Preprocessing<T>* prep = nullptr;

    typename T::MAC_Check local_mc;
    typename T::MAC_Check_2t local_mc_2t;

    ShamirInput<T> shamir_input;
    vector<T> x_verify;
    vector<T> y_verify;
    vector<T> z_verify;
    T z_de_linearized;
    vector<T> psi;

    // The dot product results are stored flattened in *_verify,
    // so we need to know where each dot product begins and ends,
    // this is stored as (index in *_verify) -> length
    std::unordered_map<int, int> dotprod_info; 

public:
    static constexpr false_type use_fiat_shamir; 
    // static constexpr true_type use_fiat_shamir; 

    static const bool uses_triples = false;

    Player& P;

    AtlasBgin(Player& P);
    ~AtlasBgin();

    AtlasBgin branch()
    {
        return P;
    }

    int get_n_relevant_players()
    {
        return honest.get_n_relevant_players();
    }

    void init(Preprocessing<T>& prep, typename T::MAC_Check& MC);

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);

    T get_random();
    
    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type);

    void init_mul_trunc(int length);
    void prepare_mul_trunc(const T& x, const T& y, int k, int f);
    void exchange_mul_trunc();
    T finalize_mul_trunc(int k, int f);

    void init_dotprod_trunc();
    void prepare_dotprod_trunc(const T& x, const T& y);
    void next_dotprod_trunc(int k, int f);
    void exchange_dotprod_trunc();
    T finalize_dotprod_trunc(int length, int k, int f);

    void prepare_with_solved_bits(const typename T::open_type& product, int k, int f);

    // BGIN20 verification 
    void check();
    void de_linearization();
    void prove_deg2_rel(false_type); // No Fiat-Shamir heuristic
    void prove_deg2_rel(true_type); // With Fiat-Shamir heuristic

    // Helper function for BGIN20 verification
    // void seed_prng_globally(PRNG& G);
    void get_random_coins(int num, vector<typename T::open_type>& coins);
    void get_input_masks(int round_count, vector<vector<T>>& masks, vector<T>& masks_open);

    inline static T interpolate_degree_1(T x_0, T x_1, T x);
    inline static T interpolate_degree_2(T x_0, T x_1, T x_2, T x);
    inline static T interpolate_degree_4(const array<T, 5>& points, T x);
};

#endif
