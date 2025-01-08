/*
 * AtlasGsz.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_H_
#define PROTOCOLS_ATLASGSZ_H_

#include "Atlas.h"

/**
 * ATLAS-GSZ protocol 
 * Use GSZ20 for verification
 */
template<class T>
class AtlasGsz : public Atlas<T>
{
    typedef Atlas<T> super;

public:
    static const bool uses_triples = false;

    AtlasGsz(Player& P) : super(P)
    {
    }

    AtlasGsz branch()
    {
        return this->P;
    }

    // Core multiplication operations
    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void prepare(const typename T::open_type& product);
    void exchange();
    T finalize_mul(int n = -1);

    // Dot product operations
    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    // Truncated multiplication operations
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type);

    void init_mul_trunc(int length);
    void prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc);
    void exchange_mul_trunc();
    T finalize_mul_trunc(int k, int f);

    // Truncated dot product operations
    void init_dotprod_trunc();
    void prepare_dotprod_trunc(const T& x, const T& y);
    void next_dotprod_trunc(int k, int f, SubProcessor<T>& proc);
    void exchange_dotprod_trunc();
    T finalize_dotprod_trunc(int length, int k, int f);

    void prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc);
};

#endif /* PROTOCOLS_ATLASGSZ_H_ */
