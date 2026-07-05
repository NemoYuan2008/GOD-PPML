/*
 * AtlasGsz.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_H_
#define PROTOCOLS_ATLASGSZ_H_

#include <unordered_map>

#include "Atlas.h"
#include "MaliciousShamirMC.h"

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

    CheckedIndirectShamirMC_2t<T> local_mc_2t;
    MaliciousShamirMC<T> malicious_mc;

    vector<T> x_verify;
    vector<T> y_verify;
    vector<T> z_verify;
    T z_de_linearized;

    // The dot product results are stored flattened in *_verify,
    // so we need to know where each dot product begins and ends,
    // this is stored as (index in *_verify) -> length
    unordered_map<int, int> dotprod_info; 

    struct PartialMultTranscriptRecord
    {
        size_t offset;
        int length;
        typename Atlas<T>::PartialMultTranscript transcript;
        bool has_king_evidence;
        typename Atlas<T>::KingPartialMultEvidence king_evidence;
    };

    vector<PartialMultTranscriptRecord> partial_mult_transcripts;

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


    void init(Preprocessing<T>& prep, typename T::MAC_Check& MC);

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);
    void set_fixed_king(int king);

    T get_random();

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    void init_mul_pub();
    void prepare_mul_pub(T x, T y);
    void exchange_mul_pub();
    T finalize_mul_pub();

    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, true_type);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, false_type);

    void init_mul_trunc(int length);
    void prepare_mul_trunc(const T& x, const T& y);
    void exchange_mul_trunc();
    T finalize_mul_trunc();

    void init_dotprod_trunc();
    void prepare_dotprod_trunc(const T& x, const T& y);
    void next_dotprod_trunc();
    void exchange_dotprod_trunc();
    T finalize_dotprod_trunc(int length);

    void prepare_with_solved_bits(const typename T::open_type& product);

    void maybe_check();

    // GSZ20 verification
    void check();
    void de_linearization();
    void dimension_reduction();
    void randomization();

    // Check the values opened in local_mc_2t
    void check_opened_values();
};

#endif /* PROTOCOLS_ATLASGSZ_H_ */
