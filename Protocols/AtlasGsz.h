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

    enum class UltimateFailureAction
    {
        none,
        analyze_alpha,
        analyze_beta,
        check_double_rand,
        identify_corrupted_party,
        king_party_disagreement,
    };

    enum class KingEvidenceMismatchKind
    {
        none,
        received_eta_2t,
        distributed_eta_t,
    };

    enum class UltimateFailureDecisionSource
    {
        none,
        local_transcript_equation,
        invalid_king_evidence,
    };

    struct UltimateFailureDecision
    {
        bool valid = false;
        UltimateFailureAction action = UltimateFailureAction::none;
        UltimateFailureDecisionSource source =
                UltimateFailureDecisionSource::none;
        int party = -1;
        int king = -1;
        int counterparty = -1;
        KingEvidenceMismatchKind mismatch_kind =
                KingEvidenceMismatchKind::none;
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

    enum class CheckDoubleRandAction
    {
        none,
        identify_corrupted_party,
        dealer_recipient_disagreement,
    };

    enum class CheckDoubleRandMismatchKind
    {
        none,
        invalid_dealer_double_sharing,
        r_t_share_mismatch,
        r_2t_share_mismatch,
    };

    struct CheckDoubleRandDecision
    {
        bool valid = false;
        CheckDoubleRandAction action = CheckDoubleRandAction::none;
        CheckDoubleRandMismatchKind mismatch_kind =
                CheckDoubleRandMismatchKind::none;
        int dealer = -1;
        int recipient = -1;
        int party = -1;
    };

    struct CheckDoubleRandContext
    {
        bool valid = false;

        vector<typename Atlas<T>::OwnDealerDoubleSharingEvidence>
            dealer_claims;
        vector<vector<typename Atlas<T>::DealerDoubleSharingContribution>>
            recipient_views;

        vector<PublishedDegreeTSharing> dealer_r_t;
        vector<PublishedDegree2TVector> dealer_r_2t;

        CheckDoubleRandDecision decision;
    };

    enum class FaultLocalizationAction
    {
        none,
        needs_analyze_sharing,
        identify_corrupted_party,
        identify_disputed_pair,
    };

    enum class FaultLocalizationSource
    {
        none,
        inconsistent_alpha,
        inconsistent_beta,
        local_transcript_equation,
        invalid_king_evidence,
        king_party_disagreement,
        invalid_double_sharing_dealer,
        double_sharing_dealer_recipient_disagreement,
    };

    enum class SharingToAnalyze
    {
        none,
        alpha,
        beta,
    };

    struct FaultLocalizationOutcome
    {
        bool valid = false;
        FaultLocalizationAction action = FaultLocalizationAction::none;
        FaultLocalizationSource source = FaultLocalizationSource::none;

        SharingToAnalyze sharing_to_analyze = SharingToAnalyze::none;

        int corrupted_party = -1;

        int disputed_party_a = -1;
        int disputed_party_b = -1;
        int primary_party = -1;
        int counterparty = -1;
    };

    struct DisputeControlState
    {
        bool initialized = false;
        vector<bool> corr;
        vector<vector<bool>> disp;
    };

    enum class FaultLocalizationApplicationAction
    {
        none,
        pending_analyze_sharing,
        recorded_corrupted_party,
        recorded_disputed_pair,
    };

    struct FaultLocalizationApplication
    {
        bool valid = false;
        FaultLocalizationApplicationAction action =
                FaultLocalizationApplicationAction::none;

        bool state_updated = false;

        int corrupted_party = -1;

        int disputed_party_a = -1;
        int disputed_party_b = -1;
        int primary_party = -1;
        int counterparty = -1;

        vector<int> newly_corrupted_parties;
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
        typename Atlas<T>::DoubleSharingDecomposition
            local_delta_decomposition;
        bool has_check_double_rand_context = false;
        CheckDoubleRandContext check_double_rand_context;

        bool has_published_king_evidence = false;
        typename Atlas<T>::KingPartialMultEvidence published_king_evidence;
        PublishedDegree2TVector king_received_eta_2t;
        PublishedDegreeTSharing king_distributed_eta_t;
        vector<int> received_eta_2t_mismatch_players;
        vector<int> distributed_eta_t_mismatch_players;

        UltimateFailureDecision decision;
        FaultLocalizationOutcome fault_localization;
        FaultLocalizationApplication fault_application;
    };

    DisputeControlState dispute_control_state;

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
    UltimateFailureDecision diagnose_ultimate_failure(
            const UltimateFailureContext& context) const;
    CheckDoubleRandContext run_check_double_rand_diagnosis(
            const typename Atlas<T>::DoubleSharingDecomposition&
                decomposition);
    FaultLocalizationOutcome derive_fault_localization_outcome(
            const UltimateFailureContext& context) const;
    void ensure_dispute_control_state_initialized();
    void validate_dispute_control_state() const;
    int corruption_threshold() const;
    bool has_dispute_control_state() const;
    vector<int> active_parties() const;
    bool is_active_party(int party) const;
    int num_active_parties() const;
    bool is_corrupted_party(int party) const;
    bool is_disputed_pair(int a, int b) const;
    vector<int> disputed_parties_of(int party) const;
    int count_disputes(int party) const;
    int count_active_disputes(int party) const;
    bool can_communicate_directly(int sender, int receiver) const;
    bool share_from_dealer_is_suppressed(
            int dealer,
            int recipient) const;
    int select_active_king() const;
    vector<int> select_T_for_king(int king) const;
    int relay_for_disputed_pair(int a, int b) const;
    bool has_relay_for_disputed_pair(int a, int b) const;
    void record_corrupted_party(
            int party,
            FaultLocalizationApplication& application);
    void record_disputed_pair(
            int a,
            int b,
            FaultLocalizationApplication& application);
    FaultLocalizationApplication apply_fault_localization_outcome(
            const FaultLocalizationOutcome& outcome);
    typename Atlas<T>::DoubleSharingDecomposition
        zero_double_sharing_decomposition() const;
    typename Atlas<T>::DealerDoubleSharingContribution
        sum_double_sharing_decomposition(
                const typename Atlas<T>::DoubleSharingDecomposition&
                    decomposition) const;
    void validate_double_sharing_decomposition(
            const typename Atlas<T>::DoubleSharingDecomposition&
                decomposition,
            const T& r_t,
            const T& r_2t) const;
    void add_scaled_double_sharing_decomposition(
            typename Atlas<T>::DoubleSharingDecomposition& accumulator,
            const typename Atlas<T>::DoubleSharingDecomposition& source,
            const typename T::open_type& coefficient) const;
    typename Atlas<T>::DoubleSharingDecomposition
        subtract_double_sharing_decomposition(
                const typename Atlas<T>::DoubleSharingDecomposition& left,
                const typename Atlas<T>::DoubleSharingDecomposition& right)
                    const;
    typename Atlas<T>::DoubleSharingDecomposition
        interpolate_double_sharing_decompositions(
                const typename Atlas<T>::DoubleSharingDecomposition& point_0,
                const typename Atlas<T>::DoubleSharingDecomposition& point_1,
                const typename Atlas<T>::DoubleSharingDecomposition& point_2,
                const typename T::open_type& L0,
                const typename T::open_type& L1,
                const typename T::open_type& L2) const;

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
