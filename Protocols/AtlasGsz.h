/*
 * AtlasGsz.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_H_
#define PROTOCOLS_ATLASGSZ_H_

#include <unordered_map>

#include "Atlas.h"

/**
 * Maliciously secure ATLAS protocol
 * 
 * t-wise independence only
 * Use GSZ20 for verification
 */
template<class T>
class AtlasGsz : public ProtocolBase<T>
{
private:
    Atlas<T> honest;

    typename T::MAC_Check local_mc;
    typename T::MAC_Check_2t local_mc_2t;

    vector<T> x_verify;
    vector<T> y_verify;
    vector<T> z_verify;
    T z_de_linearized;

    // (index in x_verify) -> length, used in de-linearization
    std::unordered_map<int, int> dotprod_info; 

public:
    static const bool uses_triples = false;

    Player& P;

    AtlasGsz(Player& P);

    ~AtlasGsz();

    AtlasGsz branch()
    {
        return P;
    }

    int get_n_relevant_players()
    {
        return honest.get_n_relevant_players();
    }

    T get_random();

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type);

    void init_mul_trunc(int length);
    void prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc);
    void exchange_mul_trunc();
    T finalize_mul_trunc(int k, int f);

    void init_dotprod_trunc();
    void prepare_dotprod_trunc(const T& x, const T& y);
    void next_dotprod_trunc(int k, int f, SubProcessor<T>& proc);
    void exchange_dotprod_trunc();
    T finalize_dotprod_trunc(int length, int k, int f);

    void prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc);

    // GSZ20 verification
    void check();
    void de_linearization();
    void dimension_reduction();
    void randomization();
};

#endif /* PROTOCOLS_ATLASGSZ_H_ */
