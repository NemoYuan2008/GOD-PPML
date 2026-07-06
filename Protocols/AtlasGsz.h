/*
 * AtlasGsz.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_H_
#define PROTOCOLS_ATLASGSZ_H_

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

    struct PartialMultTranscriptRecord
    {
        size_t offset;
        int length;
        typename Atlas<T>::PartialMultTranscript transcript;
        bool has_king_evidence;
        typename Atlas<T>::KingPartialMultEvidence king_evidence;
    };

    vector<PartialMultTranscriptRecord> partial_mult_transcripts;

    enum class UltimateFailureKind
    {
        none,
        inconsistent_alpha,
        inconsistent_beta,
        inconsistent_gamma,
        incorrect_multiplication,
    };

    struct PublishedDegreeTSharing
    {
        vector<typename T::open_type> shares;
        bool consistent = false;
        typename T::open_type value{};
    };

    struct PublishedDegree2TVector
    {
        vector<typename T::open_type> shares;
        typename T::open_type value{};
    };

    struct UltimateFailureContext
    {
        bool valid = false;
        int king = -1;
        UltimateFailureKind failure_kind = UltimateFailureKind::none;

        PublishedDegreeTSharing alpha_t;
        PublishedDegreeTSharing beta_t;
        PublishedDegreeTSharing delta_t;
        PublishedDegree2TVector delta_2t;
        PublishedDegree2TVector eta_2t;
        PublishedDegreeTSharing eta_t;
        PublishedDegreeTSharing gamma_t;

        bool has_published_king_evidence = false;
        typename Atlas<T>::KingPartialMultEvidence published_king_evidence;
        vector<int> received_eta_2t_mismatch_players;
        vector<int> distributed_eta_t_mismatch_players;
    };

    UltimateFailureContext ultimate_failure_context;
    bool have_ultimate_failure_context = false;

    typename Atlas<T>::PartialMultTranscript current_virtual_transcript;
    bool have_current_virtual_transcript = false;

    typename Atlas<T>::KingPartialMultEvidence current_virtual_king_evidence;
    bool have_current_virtual_king_evidence = false;

    void validate_partial_mult_transcript_coverage() const;
    void validate_current_virtual_transcript() const;
    typename T::open_type sample_agreed_challenge();
    vector<vector<typename T::open_type>>
        broadcast_local_shares(const vector<T>& local_shares);
    PublishedDegreeTSharing classify_degree_t_sharing(
            const vector<typename T::open_type>& shares);
    PublishedDegree2TVector collect_degree_2t_vector(
            const vector<typename T::open_type>& shares);

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
