/*
 * Atlas.h
 *
 */

#ifndef PROTOCOLS_ATLAS_H_
#define PROTOCOLS_ATLAS_H_

#include "Replicated.h"

#include "Tools/Bundle.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>


/**
 * ATLAS protocol (simple version).
 * Uses double sharings to reduce degree of Shamir secret sharing.
 */
template<class T>
class Atlas : public ProtocolBase<T>
{
public:
    typedef typename T::open_type share_value_type;

    struct FixedKingInterpolationContext
    {
        const int num_players;
        const int threshold;
        const int king;
        const vector<int> support;
        const vector<bool> support_membership;
        const vector<int> construction_points;
        const vector<share_value_type> construction_coefficients;
        const vector<vector<share_value_type>> support_evaluation_factors;
        const vector<share_value_type> support_reconstruction_factors;
        const vector<share_value_type> received_reconstruction_factors;

        FixedKingInterpolationContext(int num_players, int threshold,
                int king, vector<int> support,
                vector<bool> support_membership,
                vector<int> construction_points,
                vector<share_value_type> construction_coefficients,
                vector<vector<share_value_type>>
                        support_evaluation_factors,
                vector<share_value_type> support_reconstruction_factors,
                vector<share_value_type> received_reconstruction_factors) :
                num_players(num_players), threshold(threshold), king(king),
                support(std::move(support)),
                support_membership(std::move(support_membership)),
                construction_points(std::move(construction_points)),
                construction_coefficients(
                        std::move(construction_coefficients)),
                support_evaluation_factors(
                        std::move(support_evaluation_factors)),
                support_reconstruction_factors(
                        std::move(support_reconstruction_factors)),
                received_reconstruction_factors(
                        std::move(received_reconstruction_factors))
        {
        }
    };

    struct FixedKingInterpolationAuditSnapshot
    {
        uint64_t contexts_constructed = 0;
        uint64_t context_reuses = 0;
        uint64_t support_validation_calls = 0;
        uint64_t sharing_construction_calls = 0;
        uint64_t sharing_construction_nanoseconds = 0;
        uint64_t evidence_validation_calls = 0;
        uint64_t evidence_validation_nanoseconds = 0;
    };

    struct DealerDoubleSharingContribution
    {
        T r_t;
        T r_2t;
    };

    struct OwnDealerDoubleSharingEvidence
    {
        vector<share_value_type> r_t_shares;
        vector<share_value_type> r_2t_shares;
    };

    struct DoubleSharingDecomposition
    {
        // Recipient-side and dealer-side views used by GSZ20 Check-DoubleRand.
        vector<DealerDoubleSharingContribution> dealer_components;
        OwnDealerDoubleSharingEvidence own_dealer_evidence;
        DealerDoubleSharingContribution validated_residual;
    };

    struct DoubleSharingProducerProvenance
    {
        typename Shamir<T>::RandomsProvenance degree_t;
        typename Shamir<T>::RandomsProvenance degree_2t;
    };

    struct DoubleSharingProducerReference
    {
        // Private-process transfer token, never a public protocol identity.
        shared_ptr<const DoubleSharingProducerProvenance>
            producer_provenance;
        size_t producer_output_ordinal = 0;
    };

    struct DoubleSharingProvenanceTestSummary
    {
        size_t input_generation_groups = 0;
        size_t output_derivations = 0;
        size_t sources_per_group = 0;
    };

    struct PartialMultTranscript
    {
        T r_t;
        T r_2t;
        T e_2t;
        T e_t;
        int king;
        vector<int> special_sharing_support;
        DoubleSharingDecomposition r_decomposition;
    };

    struct KingPartialMultEvidence
    {
        vector<share_value_type> received_e_2t;
        vector<share_value_type> distributed_e_t;
        int king;
    };

private:
    Shamir<T> shamir, shamir2;

    Bundle<octetStream> oss, oss2;
    PointerVector<T> masks;

    struct DoubleSharingMaterial
    {
        T r_t;
        T r_2t;
        DoubleSharingDecomposition decomposition;
        DoubleSharingProducerReference producer_reference;
    };

    struct PendingPartialMultOperation
    {
        PartialMultTranscript transcript;
        DoubleSharingProducerReference producer_reference;
    };

    vector<DoubleSharingMaterial> double_sharings;

    vector<typename T::open_type> reconstruction;
    vector<typename T::open_type> reconstruction_t;

    const bool fixed_king_interpolation_audit_enabled_;
    shared_ptr<const FixedKingInterpolationContext>
            fixed_king_interpolation_context_;
    mutable FixedKingInterpolationAuditSnapshot
            fixed_king_interpolation_audit_;

    class FixedKingInterpolationAuditTimer
    {
        bool enabled;
        uint64_t& elapsed_nanoseconds;
        std::chrono::steady_clock::time_point started;

    public:
        FixedKingInterpolationAuditTimer(bool enabled,
                uint64_t& elapsed_nanoseconds) :
                enabled(enabled), elapsed_nanoseconds(elapsed_nanoseconds)
        {
            if (enabled)
                started = std::chrono::steady_clock::now();
        }

        ~FixedKingInterpolationAuditTimer()
        {
            if (enabled)
                elapsed_nanoseconds += uint64_t(
                        std::chrono::duration_cast<
                                std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now() - started)
                                .count());
        }
    };

    int next_king, base_king;
    bool fixed_king_enabled = false;
    int fixed_king = 0;
    vector<int> fixed_king_special_sharing_support;
    vector<T> fixed_king_special_e_t_shares;

    ShamirInput<T> resharing;

    typename T::open_type dotprod_share;

    Preprocessing<T>* prep = nullptr;

    vector<PendingPartialMultOperation> pending_partial_mult_operations;
    size_t next_partial_mult_transcript = 0;
    PendingPartialMultOperation last_completed_partial_mult_operation;
    bool have_last_partial_mult_transcript = false;

    vector<KingPartialMultEvidence> pending_king_partial_mult_evidence;
    KingPartialMultEvidence last_king_partial_mult_evidence;
    bool have_last_king_partial_mult_evidence = false;

    DoubleSharingMaterial get_double_sharing();
    DoubleSharingDecomposition zero_double_sharing_decomposition() const;
    DealerDoubleSharingContribution sum_double_sharing_decomposition(
            const DoubleSharingDecomposition& decomposition) const;
    void validate_double_sharing_decomposition(
            const DoubleSharingDecomposition& decomposition,
            const T& r_t,
            const T& r_2t) const;
    void validate_randoms_provenance(
            const typename Shamir<T>::RandomsProvenance& provenance,
            const vector<T>& outputs,
            const vector<vector<T>>& dealer_contributions) const;
    void validate_paired_double_sharing_provenance(
            const DoubleSharingProducerProvenance& provenance) const;
    void validate_double_sharing_material_provenance(
            const DoubleSharingMaterial& material) const;
    void initialize_reconstruction_factors();
    shared_ptr<const FixedKingInterpolationContext>
            build_fixed_king_interpolation_context(
                    int king, const vector<int>& support) const;
    vector<int> canonical_fixed_king_special_sharing_support(
            int king) const;
    void validate_fixed_king_special_sharing_support(
            int king, const vector<int>& support) const;
    bool fixed_king_special_sharing_support_contains(int party) const;
    vector<share_value_type> make_fixed_king_special_sharing(
            const share_value_type& secret,
            const vector<int>& support) const;
    share_value_type reconstruct_received_e_2t(
            const vector<share_value_type>& sharing) const;
    share_value_type reconstruct_distributed_e_t(
            const vector<share_value_type>& sharing,
            const vector<int>& support) const;
    void validate_fixed_king_special_sharing_evidence(
            const PartialMultTranscript& transcript,
            const KingPartialMultEvidence& evidence) const;
    void build_public_opening_king_evidence(
            size_t transcript_index,
            const share_value_type& opened_value);


protected:
    typename T::MAC_Check_2t local_mc_2t; // default initialization


public:
    static const bool uses_triples = false;

    Player& P;

    Atlas(Player& P, bool fixed_king_interpolation_audit_enabled = false) :
            shamir(P), shamir2(P, 2 * ShamirMachine::s().threshold), oss(P),
            oss2(P),
            fixed_king_interpolation_audit_enabled_(
                    fixed_king_interpolation_audit_enabled),
            next_king(0), base_king(0), resharing(0, P), P(P)
    {
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

    void init(Preprocessing<T>& prep, typename T::MAC_Check& MC);

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void prepare(const typename T::open_type& product);
    void exchange();
    T finalize_mul(int n = -1);
    void set_fixed_king(int king);
    void set_fixed_king_special_sharing_support(
            const vector<int>& support);
    const FixedKingInterpolationContext*
            fixed_king_interpolation_context_if_matches(
                    int king, const vector<int>& support) const;
    FixedKingInterpolationAuditSnapshot
            fixed_king_interpolation_audit_snapshot() const;
    const PartialMultTranscript& get_last_partial_mult_transcript() const;
    const DoubleSharingProducerReference&
        get_last_double_sharing_producer_reference() const;
    bool has_last_king_partial_mult_evidence() const;
    const KingPartialMultEvidence& get_last_king_partial_mult_evidence() const;
    DoubleSharingProvenanceTestSummary
        run_double_sharing_provenance_test();

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int = 0);

    T get_random();

    // Functions for multiplication with public output
    void init_mul_pub();
    void prepare_mul_pub(T x, T y); // It's our method, so we can change the signature, use pass-by-value
    void exchange_mul_pub();
    T finalize_mul_pub();

    // Functions for multiply-then-truncate
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, true_type);
    void mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, false_type);

    void init_mul_trunc(int length);
    void prepare_mul_trunc(const T& x, const T& y);
    void exchange_mul_trunc();
    T finalize_mul_trunc(T* pre_trunc = nullptr);

    // Functions for dot-product-then-truncate
    void init_dotprod_trunc();
    void prepare_dotprod_trunc(const T& x, const T& y);
    void next_dotprod_trunc();
    void exchange_dotprod_trunc();
    T finalize_dotprod_trunc(int length, T* pre_trunc = nullptr);

    void prepare_with_solved_bits(const typename T::open_type& product);
};

#endif /* PROTOCOLS_ATLAS_H_ */
