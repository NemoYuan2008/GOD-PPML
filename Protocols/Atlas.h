/*
 * Atla.h
 *
 */

#ifndef PROTOCOLS_ATLAS_H_
#define PROTOCOLS_ATLAS_H_

#include "Replicated.h"

#include "Tools/Bundle.h"

// #define DEBUG_MUL_CNT
#define DEBUG_MUL_TRUNC

/**
 * ATLAS protocol (simple version).
 * Uses double sharings to reduce degree of Shamir secret sharing.
 */
template<class T>
class Atlas : public ProtocolBase<T>
{
    Shamir<T> shamir, shamir2;

    Bundle<octetStream> oss, oss2;
    PointerVector<T> masks;

    vector<array<T, 2>> double_sharings;

    vector<typename T::open_type> reconstruction;

    int next_king, base_king;

    ShamirInput<T> resharing;

    typename T::open_type dotprod_share;

    array<T, 2> get_double_sharing();

    // ADDED: USE THIS LOCAL MAC CHECK!!!! see the comments in Atlas::init_mul_trunc
    typename T::MAC_Check local_mc; // default initialization is fine

#ifdef DEBUG_MUL_CNT
    int mul_count = 0;
    int multrunc_count = 0;
#endif

public:
    static const bool uses_triples = false;

    Player& P;

    Atlas(Player& P) :
            shamir(P), shamir2(P, 2 * ShamirMachine::s().threshold), oss(P),
            oss2(P), next_king(0), base_king(0), resharing(0, P), P(P)
    {
        cerr << "\nAtlas constructor\n"
             << "T: " << typeid(T).name() << '\n'
             << "T::clear: " << typeid(typename T::clear).name() << '\n';
    }

    ~Atlas();

    Atlas branch()
    {
        return P;
    }

    int get_n_relevant_players()
    {
        return shamir.get_n_relevant_players();
    }

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void prepare(const typename T::open_type& product);
    void exchange();
    T finalize_mul(int n = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    T get_random();

    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type);

    void init_mul_trunc(int length, SubProcessor<T>& proc);
    void prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc);
    void exchange_mul_trunc(SubProcessor<T>& proc);
    T finalize_mul_trunc(int k, int f, SubProcessor<T>& proc);

    void prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc);
};

#endif /* PROTOCOLS_ATLAS_H_ */
