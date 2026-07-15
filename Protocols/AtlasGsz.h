/*
 * AtlasGsz.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_H_
#define PROTOCOLS_ATLASGSZ_H_

#include "Atlas.h"
#include "MaliciousShamirMC.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>

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
    struct PreserveBaseFieldFTagChunkWidth
    {
    };

    class SentCommunicationAccumulator
    {
        Player& player;
        size_t& primary;
        size_t* secondary;
        size_t communication_before;

    public:
        SentCommunicationAccumulator(Player& player, size_t& primary,
                size_t* secondary = 0) :
                player(player), primary(primary), secondary(secondary),
                communication_before(player.total_comm().sent)
        {
        }

        ~SentCommunicationAccumulator()
        {
            const size_t communication =
                    player.total_comm().sent - communication_before;
            primary += communication;
            if (secondary != 0)
                *secondary += communication;
        }
    };

    class RuntimeAuditTimer
    {
        bool enabled;
        uint64_t& elapsed_nanoseconds;
        std::chrono::steady_clock::time_point started;

    public:
        RuntimeAuditTimer(bool enabled, uint64_t& elapsed_nanoseconds) :
                enabled(enabled), elapsed_nanoseconds(elapsed_nanoseconds)
        {
            if (enabled)
                started = std::chrono::steady_clock::now();
        }

        ~RuntimeAuditTimer()
        {
            finish();
        }

        void finish()
        {
            if (enabled)
            {
                elapsed_nanoseconds += uint64_t(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now() - started)
                                .count());
                enabled = false;
            }
        }
    };

    struct RuntimeAuditState
    {
        bool ordinary_online_started = false;
        std::chrono::steady_clock::time_point ordinary_online_start;

        uint64_t ordinary_online_before_close_nanoseconds = 0;
        uint64_t merge_candidates_nanoseconds = 0;
        uint64_t build_merged_candidate_nanoseconds = 0;
        uint64_t width_agreement_nanoseconds = 0;
        uint64_t authenticate_frozen_nanoseconds = 0;
        uint64_t source_batch_registration_nanoseconds = 0;
        uint64_t verify_sharing_nanoseconds = 0;
        uint64_t key_establishment_and_check_nanoseconds = 0;
        uint64_t base_sharing_nanoseconds = 0;
        uint64_t ordinary_ftag_nanoseconds = 0;
        uint64_t base_ftag_nanoseconds = 0;
        uint64_t check_tag_nanoseconds = 0;
        uint64_t handle_and_derivation_conversion_nanoseconds = 0;
        uint64_t create_checkpoint_nanoseconds = 0;
        uint64_t promote_checkpoint_nanoseconds = 0;
        uint64_t memory_estimation_nanoseconds = 0;
        uint64_t cleanup_nanoseconds = 0;
        uint64_t capture_concrete_e_t_validation_nanoseconds = 0;
        uint64_t candidate_finalization_nanoseconds = 0;
        uint64_t frozen_batch_construction_nanoseconds = 0;
        uint64_t integrated_close_nanoseconds = 0;

        uint64_t authenticated_handle_exists_calls = 0;
        uint64_t authenticated_handle_linear_comparisons = 0;
        uint64_t producer_output_derivation_entries_scanned = 0;
        uint64_t live_out_derivations_copied = 0;
        uint64_t live_out_terms_copied = 0;
        uint64_t live_out_bytes_copied = 0;
        uint64_t checkpoint_derivations_copied = 0;
        uint64_t checkpoint_terms_copied = 0;
        uint64_t checkpoint_bytes_copied = 0;
        uint64_t memory_estimation_calls = 0;
        uint64_t memory_estimation_elements_traversed = 0;
        uint64_t capture_concrete_e_t_validation_calls = 0;
        uint64_t concrete_e_t_validation_calls = 0;
        uint64_t tentative_candidate_validation_calls = 0;
        uint64_t exact_batch_correspondence_validation_calls = 0;
        uint64_t candidate_finalization_calls = 0;
        uint64_t frozen_batch_construction_calls = 0;
        uint64_t integrated_close_calls = 0;
        size_t memory_estimation_depth = 0;
    };

    const uint64_t base_field_ftag_chunk_width_;
    const bool runtime_audit_enabled_;
    const bool memory_audit_enabled_;
    mutable RuntimeAuditState runtime_audit_state;
    Atlas<T> honest;

    CheckedIndirectShamirMC_2t<T> local_mc_2t;
    MaliciousShamirMC<T> malicious_mc;

    vector<T> x_verify;
    vector<T> y_verify;
    vector<T> z_verify;
    T z_de_linearized;

    enum class OrdinaryDoubleRandOperationKind
    {
        noneligible,
        scalar_multiplication,
        dot_product,
    };

    struct PartialMultTranscriptRecord
    {
        size_t offset;
        int length;
        OrdinaryDoubleRandOperationKind operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        uint64_t verification_batch_serial = 0;
        typename Atlas<T>::PartialMultTranscript transcript;
        typename Atlas<T>::DoubleSharingProducerReference producer_reference;
        bool has_king_evidence;
        typename Atlas<T>::KingPartialMultEvidence king_evidence;
    };

    vector<PartialMultTranscriptRecord> partial_mult_transcripts;

    struct TentativeConcreteEtSource
    {
        int king = -1;
        vector<int> special_sharing_support;
        T local_share;
    };

    struct TentativeSourceGroupReference
    {
        size_t producer_record_ordinal = 0;
        size_t input_generation_group_ordinal = 0;

        bool operator==(const TentativeSourceGroupReference& other) const
        {
            return producer_record_ordinal == other.producer_record_ordinal
                    && input_generation_group_ordinal
                            == other.input_generation_group_ordinal;
        }
    };

    struct TentativeSourceReference
    {
        size_t producer_record_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        int dealer = -1;

        bool operator==(const TentativeSourceReference& other) const
        {
            return producer_record_ordinal == other.producer_record_ordinal
                    && input_generation_group_ordinal
                            == other.input_generation_group_ordinal
                    && dealer == other.dealer;
        }
    };

    struct TentativeDealerSource
    {
        TentativeSourceReference reference;
        size_t tentative_source_ordinal = 0;
        T local_share;
    };

    struct TentativeDealerSourceSequence
    {
        int dealer = -1;
        vector<TentativeDealerSource> sources;
    };

    struct TentativeLinearDerivationTerm
    {
        TentativeSourceReference source;
        typename T::open_type coefficient{};
    };

    struct TentativeLinearDerivation
    {
        vector<TentativeLinearDerivationTerm> terms;
    };

    struct TentativeConsumedOutputEvidence
    {
        size_t capture_order_ordinal = 0;
        size_t producer_record_ordinal = 0;
        size_t producer_output_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        OrdinaryDoubleRandOperationKind operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        T actual_r_t;
        T actual_r_2t;
        typename Atlas<T>::DoubleSharingDecomposition decomposition;
        TentativeLinearDerivation degree_t_derivation;
        TentativeConcreteEtSource concrete_e_t_source;
        size_t partial_mult_transcript_record_ordinal = 0;
    };

    struct TentativeDoubleRandCaptureCandidate
    {
        // These immutable records are candidate-local evidence. Their local
        // ordinals are assigned by completed-operation encounter order.
        vector<shared_ptr<const typename Atlas<T>::
                DoubleSharingProducerProvenance>> producer_records;
        vector<TentativeSourceGroupReference> source_groups;
        vector<TentativeDealerSourceSequence> dealer_sources;
        vector<TentativeConsumedOutputEvidence> consumed_outputs;
        size_t source_count = 0;
    };

    struct TentativeCapturedConsumption
    {
        size_t capture_order_ordinal = 0;
        size_t producer_record_ordinal = 0;
        typename Atlas<T>::DoubleSharingProducerReference producer_reference;
        OrdinaryDoubleRandOperationKind operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        T actual_r_t;
        T actual_r_2t;
        typename Atlas<T>::DoubleSharingDecomposition decomposition;
        TentativeConcreteEtSource concrete_e_t_source;
        size_t partial_mult_transcript_record_ordinal = 0;
    };

    struct TentativeDoubleRandCaptureState
    {
        bool active = false;
        vector<shared_ptr<const typename Atlas<T>::
                DoubleSharingProducerProvenance>> producer_records;
        vector<TentativeCapturedConsumption> consumptions;
        unique_ptr<TentativeDoubleRandCaptureCandidate> finalized_candidate;

        // Candidate-local direct indices. They exist only while capture is
        // active and avoid another operation-count factor in producer and
        // exact-output lookup.
        unordered_map<const void*, size_t> producer_record_ordinals;
        vector<unordered_map<size_t, bool>> consumed_outputs_by_producer;
    };

    TentativeDoubleRandCaptureState tentative_double_rand_capture_state;

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

    enum class AnalyzeSharingRequestTarget
    {
        none,
        alpha,
        beta,
    };

    struct AnalyzeSharingRequest
    {
        bool valid = false;
        AnalyzeSharingRequestTarget target =
                AnalyzeSharingRequestTarget::none;

        SharingToAnalyze sharing_to_analyze =
                SharingToAnalyze::none;

        PublishedDegreeTSharing published_sharing;
        vector<typename T::open_type> published_shares;

        FaultLocalizationSource source = FaultLocalizationSource::none;

        bool has_registered_snapshot = false;
        uint64_t registered_snapshot_id = 0;

        bool has_authentication_plan = false;
        vector<uint64_t> authentication_plan_record_ids;

        bool has_authentication_material = false;
        vector<uint64_t> authentication_material_record_ids;
    };

    enum class PendingAnalyzeSharingSource
    {
        none,
        ultimate_failure,
        authentication_rejection,
    };

    enum class PendingAnalyzeSharingTarget
    {
        none,
        published_alpha,
        published_beta,
        registered_checkpoint_output_sharing,
    };

    struct PendingAnalyzeSharingRequest
    {
        bool valid = false;
        uint64_t id = 0;

        PendingAnalyzeSharingSource source =
                PendingAnalyzeSharingSource::none;
        PendingAnalyzeSharingTarget target =
                PendingAnalyzeSharingTarget::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;
        uint64_t sharing_id = 0;

        uint64_t registered_snapshot_id = 0;
        vector<uint64_t> authentication_plan_record_ids;
        vector<uint64_t> authentication_material_record_ids;

        vector<int> rejected_holder_ids;
    };

    struct PendingAnalyzeSharingState
    {
        bool initialized = false;
        uint64_t next_request_id = 1;
        vector<PendingAnalyzeSharingRequest> requests;
    };

    enum class UltimateFailureAnalyzeEnqueueAction
    {
        none,
        no_current_failure,
        no_analyze_required,
        missing_analyze_request,
        already_enqueued,
        enqueued_request,
        inconsistent_state,
    };

    struct UltimateFailureAnalyzeEnqueueResult
    {
        bool valid = false;
        UltimateFailureAnalyzeEnqueueAction action =
                UltimateFailureAnalyzeEnqueueAction::none;

        bool state_updated = false;

        SharingToAnalyze sharing_to_analyze = SharingToAnalyze::none;
        FaultLocalizationSource source = FaultLocalizationSource::none;
        PendingAnalyzeSharingTarget target =
                PendingAnalyzeSharingTarget::none;

        uint64_t pending_request_id = 0;
        uint64_t registered_snapshot_id = 0;
        vector<uint64_t> authentication_plan_record_ids;
        vector<uint64_t> authentication_material_record_ids;
    };

    enum class RegisteredSharingDegree
    {
        none,
        degree_t,
        degree_2t,
    };

    enum class RegisteredSharingKind
    {
        none,
        checkpoint_input,
        checkpoint_output,
        segment_intermediate,
        analyze_request_snapshot,
    };

    enum class VerifiableSharingStatus
    {
        none,
        registered,
        authentication_pending,
        authenticated,
        analysis_pending,
    };

    struct RegisteredVerifiableSharing
    {
        bool valid = false;
        uint64_t id = 0;

        RegisteredSharingDegree degree = RegisteredSharingDegree::none;
        RegisteredSharingKind kind = RegisteredSharingKind::none;
        VerifiableSharingStatus status = VerifiableSharingStatus::none;

        T local_share;

        bool has_published_snapshot = false;
        vector<typename T::open_type> published_shares;

        uint64_t segment_id = 0;
        uint64_t checkpoint_id = 0;
    };

    struct CheckpointRecord
    {
        bool valid = false;
        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        vector<uint64_t> sharing_ids;

        bool sealed = false;
        bool authentication_requested = false;
        bool authenticated = false;
    };

    struct VerifiableSharingRegistry
    {
        bool initialized = false;

        uint64_t next_sharing_id = 1;
        uint64_t next_checkpoint_id = 1;
        uint64_t current_segment_id = 0;

        vector<RegisteredVerifiableSharing> sharings;
        vector<CheckpointRecord> checkpoints;
    };

    struct SegmentLifecycleState
    {
        bool initialized = false;

        uint64_t current_segment_id = 0;
        uint64_t last_completed_segment_id = 0;

        bool segment_open = false;
        bool checkpoint_open = false;

        uint64_t current_input_checkpoint_id = 0;
        uint64_t current_output_checkpoint_id = 0;

        vector<uint64_t> current_segment_input_sharings;
        vector<uint64_t> current_segment_output_sharings;
    };

    // Authoritative optimistic-path authentication state.  This is kept
    // separate from the legacy metadata-only authentication plan below: the
    // object authenticated here is a dealer-generated source batch, never a
    // derived checkpoint output.
    enum class OptimisticAuthenticationStatus
    {
        ready,
        RecoveryNotImplemented,
    };

    enum class DealerBatchAuthenticationState
    {
        pending,
        authenticated,
        rejected,
    };

    enum class OptimisticAuthenticationFailureClass
    {
        none,
        invocation_validation,
        verify_sharing,
        base_sharing,
        key_distribution,
        key_check,
        tag_generation,
        tag_check,
    };

    struct AuthenticatedSourceHandle
    {
        uint64_t batch_id = 0;
        int dealer = -1;
        uint64_t source_ordinal = 0;

        bool operator==(const AuthenticatedSourceHandle& other) const
        {
            return batch_id == other.batch_id
                    && dealer == other.dealer
                    && source_ordinal == other.source_ordinal;
        }
    };

    struct TentativeDoubleRandSourceHandleMapping
    {
        size_t producer_record_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        int dealer = -1;
        AuthenticatedSourceHandle handle;
    };

    struct TentativeDoubleRandDealerBatchSummary
    {
        int dealer = -1;
        uint64_t batch_id = 0;
        size_t source_count = 0;
    };

    struct DealerBatchFailureEvidence
    {
        typename T::open_type challenge{};
        vector<typename T::open_type> published_shares;
    };

    struct DealerSourceBatchRecord
    {
        DealerSourceBatchRecord() = default;
        DealerSourceBatchRecord(DealerSourceBatchRecord&&) noexcept = default;
        DealerSourceBatchRecord& operator=(
                DealerSourceBatchRecord&&) noexcept = default;
        DealerSourceBatchRecord(const DealerSourceBatchRecord&) = delete;
        DealerSourceBatchRecord& operator=(
                const DealerSourceBatchRecord&) = delete;

        uint64_t batch_id = 0;
        int dealer = -1;
        vector<uint64_t> source_ordinals;

        // This process owns only its local shares of the dealer's ordered
        // degree-t source sharings.
        vector<T> local_source_shares;

        DealerBatchAuthenticationState authentication_state =
                DealerBatchAuthenticationState::pending;
        OptimisticAuthenticationFailureClass failure_class =
                OptimisticAuthenticationFailureClass::none;
        bool verify_sharing_completed = false;
        bool verify_sharing_passed = false;
        bool base_sharing_check_completed = false;
        bool base_sharing_check_passed = false;

        // Retained only when the public compressed sharing is inconsistent.
        unique_ptr<DealerBatchFailureEvidence>
                verify_sharing_failure_evidence;
        unique_ptr<DealerBatchFailureEvidence>
                base_sharing_failure_evidence;
        size_t ftag_chunk_count = 0;
        vector<AuthenticatedSourceHandle> authenticated_handles;
    };

    struct BaseFieldFTagSourceChunk
    {
        size_t chunk_ordinal = 0;
        size_t original_source_offset = 0;
        size_t original_source_count = 0;
        vector<T> components;
    };

    struct LongTermMuKeyRecord
    {
        uint64_t key_id = 0;
        uint64_t epoch = 0;
        int verifier = -1;
        int holder = -1;

        // Only the verifier process sets owns_clear_mu.  A non-holder process
        // has at most its local share of the twisted key sharing; the holder
        // receives neither representation.
        bool owns_clear_mu = false;
        vector<typename T::open_type> clear_mu;
        bool has_local_twisted_share = false;
        vector<typename T::open_type> local_twisted_share;
        bool checked = false;
    };

    struct BatchNuMaterialRecord
    {
        uint64_t batch_id = 0;
        size_t chunk_ordinal = 0;
        bool check_mask = false;
        uint64_t key_epoch = 0;
        int verifier = -1;
        int holder = -1;

        // nu is present only on the verifier process.
        bool owns_nu = false;
        typename T::open_type nu{};
    };

    struct HolderTagRecord
    {
        uint64_t batch_id = 0;
        size_t chunk_ordinal = 0;
        bool check_mask = false;
        uint64_t key_epoch = 0;
        int verifier = -1;
        int holder = -1;

        // The reconstructed tag is present only on the holder process.
        bool owns_tag = false;
        typename T::open_type tag{};
    };

    struct LinearDerivationTerm
    {
        AuthenticatedSourceHandle handle;
        typename T::open_type coefficient{};
    };

    struct LinearDerivation
    {
        vector<LinearDerivationTerm> terms;
    };

    struct TentativeDoubleRandConvertedRtDerivation
    {
        size_t capture_order_ordinal = 0;
        size_t producer_record_ordinal = 0;
        size_t producer_output_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        OrdinaryDoubleRandOperationKind operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        LinearDerivation derivation;
    };

    struct TentativeDoubleRandConvertedZtDerivation
    {
        size_t capture_order_ordinal = 0;
        size_t producer_record_ordinal = 0;
        size_t producer_output_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        OrdinaryDoubleRandOperationKind operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        LinearDerivation derivation;
    };

    struct TentativeAuthenticatedEtSource
    {
        size_t capture_order_ordinal = 0;
        size_t producer_record_ordinal = 0;
        size_t producer_output_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        OrdinaryDoubleRandOperationKind operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        int king = -1;
        vector<int> special_sharing_support;
        AuthenticatedSourceHandle handle;
    };

    struct TentativeDoubleRandAuthenticationReceipt
    {
        bool authenticated = false;
        uint64_t authentication_invocation_id = 0;
        vector<TentativeDoubleRandDealerBatchSummary> dealer_batches;
        vector<TentativeDoubleRandSourceHandleMapping> source_handles;
        vector<TentativeDoubleRandConvertedRtDerivation>
                converted_r_t_derivations;
        vector<TentativeAuthenticatedEtSource> authenticated_e_t_sources;
        vector<TentativeDoubleRandConvertedZtDerivation>
                converted_z_t_derivations;
    };

    struct TentativeDoubleRandProspectiveSourceMapping
    {
        size_t producer_record_ordinal = 0;
        size_t input_generation_group_ordinal = 0;
        int dealer = -1;
        uint64_t source_ordinal = 0;
    };

    struct FrozenOrdinaryBatch
    {
        unique_ptr<TentativeDoubleRandCaptureCandidate> candidate;
        vector<DealerSourceBatchRecord> prospective_batches;
        vector<TentativeDoubleRandProspectiveSourceMapping>
                prospective_mappings;
        vector<vector<size_t>> converted_term_mapping_indices;
        vector<size_t> e_t_source_ordinals;
        TentativeDoubleRandAuthenticationReceipt receipt;

        uint64_t verification_batch_serial = 0;
        size_t dealer_count = 0;
        size_t operation_count = 0;
        size_t mapping_count = 0;
        size_t combined_king_source_count = 0;
        size_t x_verify_coordinate_count = 0;
        size_t partial_transcript_count = 0;
    };

    struct OptimisticCheckpointRecord
    {
        uint64_t checkpoint_id = 0;
        vector<LinearDerivation> output_derivations;
        bool sealed = false;
        bool promoted = false;
    };

    struct GlobalAuthenticationInvocationMember
    {
        uint64_t batch_id = 0;
        int dealer = -1;
        size_t ftag_chunk_count = 0;
    };

    struct GlobalAuthenticationInvocationRecord
    {
        uint64_t invocation_id = 0;
        uint64_t key_epoch = 0;
        uint64_t checkpoint_id = 0;
        vector<GlobalAuthenticationInvocationMember> members;
        size_t max_ftag_chunk_count = 0;

        bool challenge_sampled = false;
        typename T::open_type challenge{};
        bool completed = false;
        bool passed = false;
        OptimisticAuthenticationFailureClass failure_class =
                OptimisticAuthenticationFailureClass::none;
        int failed_verifier = -1;
        int failed_holder = -1;

        // This presentation is retained only by the failing verifier
        // process. It is never broadcast as public failure evidence.
        bool owns_failure_presentation = false;
        vector<typename T::open_type> failure_sigma;
        typename T::open_type failure_tag{};
    };

    // Stack-local preparation state. It is not an authoritative planning or
    // scheduler layer, and it is discarded after this invocation returns.
    struct GlobalAuthenticationWorkingMember
    {
        uint64_t batch_id = 0;
        size_t dealer_batch_index = 0;
        vector<BaseFieldFTagSourceChunk> source_chunks;
        vector<T> base_sharing;
        size_t ordinary_nu_begin = 0;
        size_t ordinary_tag_begin = 0;
        size_t base_nu_begin = 0;
        size_t base_tag_begin = 0;
    };

    struct GlobalAuthenticationWorkingSet
    {
        vector<GlobalAuthenticationWorkingMember> members;
    };

    enum class GlobalAuthenticationTestFault
    {
        none,
        ordinary_source_presentation,
        base_sharing_presentation,
        aggregate_holder_tag,
        missing_chunk,
        duplicate_chunk,
        key_epoch_mismatch,
    };

    struct OptimisticAuthenticationState
    {
        uint64_t key_epoch = 1;
        uint64_t next_key_id = 1;
        uint64_t next_batch_id = 1;
        uint64_t next_checkpoint_id = 1;
        uint64_t next_global_invocation_id = 1;

        bool keys_established = false;
        bool keys_checked = false;
        bool base_field_ftag_chunk_width_agreed = false;
        size_t base_field_ftag_chunk_width_agreement_communication = 0;
        size_t key_establishment_runs = 0;
        size_t check_key_runs = 0;
        size_t key_establishment_communication = 0;
        size_t check_key_masking_equation_checks = 0;
        size_t verify_sharing_invocations = 0;
        size_t verify_sharing_communication = 0;
        size_t base_sharing_checks = 0;
        size_t base_sharing_communication = 0;
        size_t tag_generation_communication = 0;
        size_t ordinary_tag_generation_communication = 0;
        size_t base_tag_generation_communication = 0;
        size_t tag_checking_communication = 0;
        size_t total_ftag_chunks = 0;
        size_t global_check_tag_challenges = 0;
        bool test_hook_ran = false;

        OptimisticAuthenticationStatus status =
                OptimisticAuthenticationStatus::ready;
        OptimisticAuthenticationFailureClass failure_class =
                OptimisticAuthenticationFailureClass::none;
        uint64_t failed_batch_id = 0;
        int failed_verifier = -1;
        int failed_holder = -1;

        vector<LongTermMuKeyRecord> keys;
        vector<DealerSourceBatchRecord> dealer_batches;
        vector<BatchNuMaterialRecord> nu_material;
        vector<HolderTagRecord> holder_tags;
        vector<OptimisticCheckpointRecord> checkpoints;
        vector<GlobalAuthenticationInvocationRecord> global_invocations;
    };

    enum class OrdinaryBatchLifecycle
    {
        idle,
        capturing_ordinary,
        checking_gs20,
        authenticating_sources,
        failed,
    };

    enum class VerificationBatchFlushReason
    {
        none,
        threshold,
        eligibility_boundary,
        explicit_test_residual,
        destructor,
    };

    struct OrdinaryBatchOperationShape
    {
        OrdinaryDoubleRandOperationKind kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        size_t length = 0;
    };

    struct IntegratedBatchReport
    {
        bool valid = false;
        uint64_t logical_segment_id = 0;
        uint64_t checkpoint_id = 0;
        uint64_t verification_batch_serial = 0;
        VerificationBatchFlushReason flush_reason =
                VerificationBatchFlushReason::none;
        size_t internal_gs20_checks = 0;
        size_t collected_verification_batches = 0;
        size_t ordinary_scalar_operations = 0;
        size_t ordinary_dot_operations = 0;
        size_t x_verify_coordinates = 0;
        size_t partial_transcripts = 0;
        vector<OrdinaryBatchOperationShape> operation_shapes;
        vector<size_t> per_dealer_source_counts;
        vector<size_t> per_dealer_ftag_chunk_counts;
        size_t double_rand_producer_records = 0;
        size_t double_rand_source_groups = 0;
        vector<size_t> outputs_per_double_rand_source_group;
        size_t peak_segment_collector_bytes = 0;
        size_t committed_handles = 0;
        size_t r_t_derivations = 0;
        size_t direct_e_t_handles = 0;
        size_t z_t_derivations = 0;
        size_t r_t_local_evaluations = 0;
        size_t e_t_local_evaluations = 0;
        size_t z_t_local_evaluations = 0;
        size_t verify_sharing_invocations = 0;
        size_t check_key_setup_runs = 0;
        size_t check_key_runs = 0;
        size_t checked_base_sharings = 0;
        size_t ordinary_tag_nu_relations = 0;
        size_t base_tag_nu_relations = 0;
        size_t global_check_tag_challenges = 0;
        size_t gs20_de_linearization_challenges = 0;
        size_t gs20_dimension_reduction_challenges = 0;
        size_t gs20_randomization_logical_challenges = 0;
        size_t gs20_randomization_raw_samples = 0;
        size_t gs20_communication = 0;
        size_t verify_sharing_communication = 0;
        size_t key_check_communication = 0;
        size_t base_sharing_communication = 0;
        size_t ordinary_tag_communication = 0;
        size_t base_tag_communication = 0;
        size_t check_tag_communication = 0;
        size_t total_authentication_communication = 0;
        size_t total_integrated_communication = 0;
        size_t authentication_invocations_started = 0;
        size_t authentication_invocations_completed = 0;
        size_t authentication_invocations_accepted = 0;
        size_t post_cleanup_x_verify = 0;
        size_t post_cleanup_y_verify = 0;
        size_t post_cleanup_z_verify = 0;
        size_t post_cleanup_partial_transcripts = 0;
        size_t post_cleanup_virtual_transcripts = 0;
        size_t post_cleanup_virtual_king_evidence = 0;
        size_t post_cleanup_capture_active = 0;
        size_t post_cleanup_capture_finalized = 0;
        size_t post_cleanup_capture_producers = 0;
        size_t post_cleanup_capture_consumptions = 0;
        size_t post_cleanup_capture_producer_indices = 0;
        size_t post_cleanup_capture_output_indices = 0;
        size_t post_cleanup_frozen_batches = 0;
        size_t post_cleanup_receipt_dealer_batches = 0;
        size_t post_cleanup_receipt_source_handles = 0;
        size_t post_cleanup_receipt_r_t = 0;
        size_t post_cleanup_receipt_e_t = 0;
        size_t post_cleanup_receipt_z_t = 0;
        size_t post_cleanup_dealer_batches = 0;
        size_t post_cleanup_nu_material = 0;
        size_t post_cleanup_holder_tags = 0;
        size_t post_cleanup_global_invocations = 0;
        size_t retained_dealer_batches = 0;
        size_t retained_nu_material = 0;
        size_t retained_holder_tags = 0;
        size_t retained_global_invocations = 0;
        size_t persistent_reusable_keys = 0;
        uint64_t persistent_key_epoch = 0;
        bool checkpoint_sealed = false;
        bool checkpoint_promoted = false;
    };

    struct IntegratedOrdinaryBatchState
    {
        OrdinaryBatchLifecycle lifecycle = OrdinaryBatchLifecycle::idle;
        uint64_t next_verification_batch_serial = 1;
        uint64_t current_verification_batch_serial = 0;
        bool wrapper_operation_active = false;
        OrdinaryDoubleRandOperationKind wrapper_operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        size_t wrapper_operation_coordinate_start = 0;
        size_t wrapper_pending_results = 0;
        size_t preprocessing_initialization_wrappers_replaced = 0;
        size_t preprocessing_mul_public_records = 0;
        bool preprocessing_mul_public_test_reported = false;
        bool inject_unsupported_gs20_failure = false;
        VerificationBatchFlushReason pending_flush_reason =
                VerificationBatchFlushReason::none;
        unique_ptr<FrozenOrdinaryBatch> frozen_batch;
        TentativeDoubleRandAuthenticationReceipt adapter_receipt;

        size_t ordinary_scalar_operations = 0;
        size_t ordinary_dot_operations = 0;
        size_t ordinary_operations = 0;
        size_t x_verify_coordinates = 0;
        size_t partial_transcripts = 0;
        size_t threshold_batches = 0;
        size_t eligibility_boundary_batches = 0;
        size_t explicit_residual_batches = 0;
        size_t destructor_batches = 0;
        size_t direct_check_batches = 0;
        size_t gs20_checks = 0;
        // A started invocation is counted immediately before entering the
        // source authenticator. Completed and accepted remain separate.
        size_t authentication_invocations = 0;
        size_t authentication_invocations_completed = 0;
        size_t authentication_invocations_accepted = 0;
        size_t gs20_de_linearization_challenges = 0;
        size_t gs20_dimension_reduction_challenges = 0;
        size_t gs20_randomization_logical_challenges = 0;
        size_t gs20_randomization_raw_samples = 0;
        size_t gs20_communication = 0;
        size_t total_authentication_communication = 0;
        size_t total_integrated_communication = 0;
        size_t committed_handles = 0;
        size_t r_t_derivations = 0;
        size_t direct_e_t_handles = 0;
        size_t z_t_derivations = 0;
        size_t ordinary_tag_nu_relations = 0;
        size_t base_tag_nu_relations = 0;
        size_t logical_segments_started = 0;
        size_t logical_segments_closed = 0;
        size_t logical_segments_promoted = 0;
        size_t double_rand_producer_records = 0;
        size_t double_rand_source_groups = 0;
        vector<size_t> outputs_per_double_rand_source_group;
        size_t peak_segment_collector_bytes = 0;
        IntegratedBatchReport latest_batch;
    };

    enum class OrdinaryOnlineSegmentLifecycle
    {
        idle,
        collecting,
        closing,
        promoted,
        failed,
    };

    struct OrdinaryOnlineSegmentCollector
    {
        OrdinaryOnlineSegmentLifecycle lifecycle =
                OrdinaryOnlineSegmentLifecycle::idle;
        uint64_t next_logical_segment_id = 1;
        uint64_t logical_segment_id = 0;
        uint64_t checkpoint_id = 0;
        vector<unique_ptr<FrozenOrdinaryBatch>> verified_batches;
        IntegratedBatchReport report;
        size_t peak_owned_bytes = 0;
    };

    enum class AuthenticationPlanStatus
    {
        none,
        planned,
        requested,
        authenticated,
    };

    enum class AuthenticationRecordKind
    {
        none,
        checkpoint_output_share,
        analyze_request_snapshot,
    };

    struct AuthenticationPlanRecord
    {
        bool valid = false;
        uint64_t id = 0;

        uint64_t sharing_id = 0;
        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        int verifier = -1;
        int holder = -1;

        AuthenticationRecordKind kind =
                AuthenticationRecordKind::none;
        AuthenticationPlanStatus status =
                AuthenticationPlanStatus::none;
    };

    struct AuthenticationPlanState
    {
        bool initialized = false;
        uint64_t next_auth_record_id = 1;
        vector<AuthenticationPlanRecord> records;
    };

    enum class AuthenticationMaterialStatus
    {
        none,
        placeholder,
        verifier_key_assigned,
        holder_tag_assigned,
        complete,
    };

    struct AuthenticationMaterialRecord
    {
        bool valid = false;
        uint64_t id = 0;

        uint64_t auth_record_id = 0;
        uint64_t sharing_id = 0;
        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        int verifier = -1;
        int holder = -1;

        AuthenticationRecordKind kind =
                AuthenticationRecordKind::none;

        AuthenticationMaterialStatus status =
                AuthenticationMaterialStatus::none;

        bool has_verifier_key = false;
        typename T::open_type verifier_key_mu{};
        typename T::open_type verifier_key_nu{};

        bool has_holder_tag = false;
        typename T::open_type holder_tag{};
    };

    struct AuthenticationMaterialState
    {
        bool initialized = false;
        uint64_t next_material_id = 1;
        vector<AuthenticationMaterialRecord> records;
    };

    enum class AuthenticationEquationStatus
    {
        none,
        not_ready,
        holder_share_unavailable,
        pass,
        fail,
    };

    struct AuthenticationEquationResult
    {
        bool valid = false;

        AuthenticationEquationStatus status =
                AuthenticationEquationStatus::none;

        uint64_t material_id = 0;
        uint64_t auth_record_id = 0;
        uint64_t sharing_id = 0;

        int verifier = -1;
        int holder = -1;

        bool has_holder_share = false;
        typename T::open_type holder_share{};

        bool has_expected_tag = false;
        typename T::open_type expected_tag{};

        bool has_actual_tag = false;
        typename T::open_type actual_tag{};
    };

    enum class AuthenticationVerifierVoteStatus
    {
        none,
        not_ready,
        holder_share_unavailable,
        accept,
        reject,
    };

    enum class AuthenticationHolderDecisionStatus
    {
        none,
        not_ready,
        holder_share_unavailable,
        insufficient_votes,
        accepted,
        rejected,
    };

    struct AuthenticationVerifierVote
    {
        bool valid = false;

        AuthenticationVerifierVoteStatus status =
                AuthenticationVerifierVoteStatus::none;

        uint64_t material_id = 0;
        uint64_t auth_record_id = 0;
        uint64_t sharing_id = 0;
        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        int verifier = -1;
        int holder = -1;

        AuthenticationRecordKind kind =
                AuthenticationRecordKind::none;

        AuthenticationEquationStatus equation_status =
                AuthenticationEquationStatus::none;

        bool contributes_to_decision = false;
    };

    struct AuthenticationHolderDecision
    {
        bool valid = false;

        AuthenticationHolderDecisionStatus status =
                AuthenticationHolderDecisionStatus::none;

        uint64_t sharing_id = 0;
        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        int holder = -1;

        AuthenticationRecordKind kind =
                AuthenticationRecordKind::none;

        int decision_threshold = 0;
        int total_votes = 0;
        int accept_votes = 0;
        int reject_votes = 0;
        int not_ready_votes = 0;
        int unavailable_votes = 0;
        int contributing_votes = 0;

        vector<uint64_t> material_ids;
    };

    enum class AuthenticationSharingDecisionStatus
    {
        none,
        not_ready,
        holder_share_unavailable,
        insufficient_votes,
        accepted,
        rejected,
    };

    enum class AuthenticationCheckpointDecisionStatus
    {
        none,
        not_ready,
        holder_share_unavailable,
        insufficient_votes,
        accepted,
        rejected,
    };

    struct AuthenticationSharingDecision
    {
        bool valid = false;

        AuthenticationSharingDecisionStatus status =
                AuthenticationSharingDecisionStatus::none;

        uint64_t sharing_id = 0;
        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        AuthenticationRecordKind kind =
                AuthenticationRecordKind::none;

        int expected_holders = 0;
        int total_holder_decisions = 0;
        int accepted_holders = 0;
        int rejected_holders = 0;
        int not_ready_holders = 0;
        int unavailable_holders = 0;
        int insufficient_holders = 0;

        vector<int> holder_ids;
        vector<int> rejected_holder_ids;
    };

    struct AuthenticationCheckpointDecision
    {
        bool valid = false;

        AuthenticationCheckpointDecisionStatus status =
                AuthenticationCheckpointDecisionStatus::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        int expected_sharings = 0;
        int total_sharing_decisions = 0;
        int accepted_sharings = 0;
        int rejected_sharings = 0;
        int not_ready_sharings = 0;
        int unavailable_sharings = 0;
        int insufficient_sharings = 0;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<int> rejected_holder_ids;
    };

    enum class AuthenticationDecisionOutcomeAction
    {
        none,
        wait_for_material,
        holder_share_unavailable,
        insufficient_votes,
        accept_checkpoint,
        reject_checkpoint,
    };

    struct AuthenticationDecisionOutcome
    {
        bool valid = false;

        AuthenticationDecisionOutcomeAction action =
                AuthenticationDecisionOutcomeAction::none;

        AuthenticationCheckpointDecisionStatus checkpoint_status =
                AuthenticationCheckpointDecisionStatus::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        int expected_sharings = 0;
        int accepted_sharings = 0;
        int rejected_sharings = 0;
        int not_ready_sharings = 0;
        int unavailable_sharings = 0;
        int insufficient_sharings = 0;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<int> rejected_holder_ids;

        bool would_accept_checkpoint = false;
        bool would_reject_checkpoint = false;
        bool needs_more_authentication_material = false;
        bool has_unavailable_holder_share = false;
        bool has_insufficient_votes = false;
    };

    enum class AuthenticationOutcomeHookAction
    {
        none,
        no_action,
        would_wait_for_material,
        would_request_holder_share_recovery,
        would_report_insufficient_votes,
        would_accept_checkpoint,
        would_reject_checkpoint,
    };

    struct AuthenticationOutcomeHookResult
    {
        bool valid = false;

        AuthenticationOutcomeHookAction action =
                AuthenticationOutcomeHookAction::none;

        AuthenticationDecisionOutcomeAction outcome_action =
                AuthenticationDecisionOutcomeAction::none;

        AuthenticationCheckpointDecisionStatus checkpoint_status =
                AuthenticationCheckpointDecisionStatus::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<int> rejected_holder_ids;

        bool performed_action = false;
        bool would_wait = false;
        bool would_accept = false;
        bool would_reject = false;
        bool would_need_recovery = false;
        bool would_report_insufficient = false;
    };

    enum class AuthenticationPromotionAction
    {
        none,
        already_authenticated,
        promoted_checkpoint,
        not_accepted,
    };

    struct AuthenticationPromotionResult
    {
        bool valid = false;

        AuthenticationPromotionAction action =
                AuthenticationPromotionAction::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        bool state_updated = false;

        vector<uint64_t> promoted_sharing_ids;
        vector<uint64_t> authentication_record_ids;
    };

    enum class SegmentCompletionReadinessAction
    {
        none,
        no_open_segment,
        missing_output_checkpoint,
        checkpoint_still_open,
        checkpoint_not_sealed,
        authentication_not_requested,
        authentication_records_missing,
        authentication_incomplete,
        checkpoint_not_authenticated,
        ready,
        already_completed,
    };

    struct SegmentCompletionReadinessResult
    {
        bool valid = false;

        SegmentCompletionReadinessAction action =
                SegmentCompletionReadinessAction::none;

        uint64_t segment_id = 0;
        uint64_t checkpoint_id = 0;

        bool ready = false;
        bool state_updated = false;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> authentication_record_ids;
    };

    enum class AuthenticationAnalyzePlanAction
    {
        none,
        no_action,
        would_analyze_rejected_sharings,
        wait_for_material,
        holder_share_unavailable,
        insufficient_votes,
    };

    struct AuthenticationAnalyzeSharingPlanEntry
    {
        bool valid = false;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;
        uint64_t sharing_id = 0;

        AuthenticationRecordKind kind =
                AuthenticationRecordKind::none;

        AuthenticationSharingDecisionStatus sharing_status =
                AuthenticationSharingDecisionStatus::none;

        vector<int> rejected_holder_ids;

        bool would_analyze_sharing = false;
        bool performed_action = false;
    };

    struct AuthenticationAnalyzeSharingPlan
    {
        bool valid = false;

        AuthenticationAnalyzePlanAction action =
                AuthenticationAnalyzePlanAction::none;

        AuthenticationOutcomeHookAction hook_action =
                AuthenticationOutcomeHookAction::none;

        AuthenticationDecisionOutcomeAction outcome_action =
                AuthenticationDecisionOutcomeAction::none;

        AuthenticationCheckpointDecisionStatus checkpoint_status =
                AuthenticationCheckpointDecisionStatus::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<int> rejected_holder_ids;

        vector<AuthenticationAnalyzeSharingPlanEntry> entries;

        bool would_create_analyze_requests = false;
        bool performed_action = false;
    };

    enum class AuthenticationAnalyzeEnqueueAction
    {
        none,
        no_action,
        not_rejected,
        no_analyze_candidates,
        enqueued_requests,
        already_enqueued,
    };

    struct AuthenticationAnalyzeEnqueueResult
    {
        bool valid = false;

        AuthenticationAnalyzeEnqueueAction action =
                AuthenticationAnalyzeEnqueueAction::none;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;

        bool state_updated = false;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> pending_request_ids;
    };

    enum class PendingAnalyzeSharingInspectionAction
    {
        none,
        no_pending_request,
        planned_authentication_rejection,
        planned_ultimate_failure,
        inconsistent_state,
    };

    struct PendingAnalyzeSharingDispatchPlan
    {
        bool valid = false;

        PendingAnalyzeSharingInspectionAction action =
                PendingAnalyzeSharingInspectionAction::none;

        bool request_found = false;
        bool request_structurally_valid = false;

        uint64_t pending_request_id = 0;

        PendingAnalyzeSharingSource source =
                PendingAnalyzeSharingSource::none;
        PendingAnalyzeSharingTarget target =
                PendingAnalyzeSharingTarget::none;

        bool is_authentication_rejection_request = false;
        bool is_ultimate_failure_request = false;

        bool state_updated = false;
        bool performed_action = false;

        bool future_requires_analyze_sharing = false;
        bool future_requires_localization = false;
        bool future_requires_dispute_control_update = false;
        bool future_requires_segment_recovery_or_retry = false;

        bool planned_analyze_checkpoint_output_sharing = false;
        bool planned_analyze_published_snapshot = false;
        bool planned_localize_corrupted_party_or_disputed_pair = false;
        bool planned_feed_dispute_control_update = false;
        bool planned_feed_segment_recovery = false;

        bool target_is_published_alpha = false;
        bool target_is_published_beta = false;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;
        uint64_t sharing_id = 0;
        uint64_t registered_checkpoint_output_sharing_id = 0;

        uint64_t registered_snapshot_id = 0;
        uint64_t ultimate_failure_snapshot_id = 0;

        bool has_current_ultimate_failure_context = false;
        bool ultimate_failure_context_matches_request = false;
        UltimateFailureKind ultimate_failure_kind =
                UltimateFailureKind::none;
        UltimateFailureAction ultimate_failure_action =
                UltimateFailureAction::none;
        FaultLocalizationSource fault_source =
                FaultLocalizationSource::none;
        SharingToAnalyze sharing_to_analyze = SharingToAnalyze::none;

        AuthenticationSharingDecisionStatus authentication_sharing_status =
                AuthenticationSharingDecisionStatus::none;
        AuthenticationCheckpointDecisionStatus
            authentication_checkpoint_status =
                AuthenticationCheckpointDecisionStatus::none;
        AuthenticationDecisionOutcomeAction authentication_outcome_action =
                AuthenticationDecisionOutcomeAction::none;
        AuthenticationAnalyzePlanAction authentication_analyze_plan_action =
                AuthenticationAnalyzePlanAction::none;

        int expected_holders = 0;
        int total_holder_decisions = 0;
        int rejected_holders = 0;

        int expected_sharings = 0;
        int rejected_sharings = 0;
        int not_ready_sharings = 0;
        int unavailable_sharings = 0;
        int insufficient_sharings = 0;

        vector<uint64_t> checkpoint_sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<int> rejected_holder_ids;

        vector<uint64_t> authentication_plan_record_ids;
        vector<uint64_t> authentication_material_record_ids;
        vector<int> authentication_verifier_ids;
        vector<int> authentication_holder_ids;
        vector<AuthenticationPlanStatus> authentication_plan_statuses;
        vector<AuthenticationMaterialStatus>
            authentication_material_statuses;
    };

    enum class PendingAnalyzeSharingExecutionReadinessAction
    {
        none,
        no_pending_request,
        inconsistent_state,
        ready_authentication_rejection,
        ready_ultimate_failure,
    };

    struct PendingAnalyzeSharingExecutionReadinessPlan
    {
        bool valid = false;

        PendingAnalyzeSharingExecutionReadinessAction action =
                PendingAnalyzeSharingExecutionReadinessAction::none;

        bool request_found = false;
        bool request_structurally_valid = false;

        bool state_updated = false;
        bool performed_action = false;

        uint64_t pending_request_id = 0;

        PendingAnalyzeSharingSource source =
                PendingAnalyzeSharingSource::none;
        PendingAnalyzeSharingTarget target =
                PendingAnalyzeSharingTarget::none;

        bool is_authentication_rejection_request = false;
        bool is_ultimate_failure_request = false;

        bool future_requires_analyze_sharing = false;
        bool future_requires_localization = false;
        bool future_requires_dispute_control_update = false;
        bool future_requires_segment_recovery_or_retry = false;

        bool planned_analyze_checkpoint_output_sharing = false;
        bool planned_analyze_published_snapshot = false;
        bool planned_localize_corrupted_party_or_disputed_pair = false;
        bool planned_feed_dispute_control_update = false;
        bool planned_feed_segment_recovery = false;

        bool would_analyze_checkpoint_output_sharing = false;
        bool would_analyze_published_snapshot = false;
        bool would_feed_localization = false;
        bool would_feed_dispute_control_update = false;
        bool would_feed_segment_recovery_or_retry = false;

        bool metadata_complete = false;
        bool execution_inputs_metadata_complete = false;

        bool target_is_published_alpha = false;
        bool target_is_published_beta = false;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;
        uint64_t sharing_id = 0;
        uint64_t registered_checkpoint_output_sharing_id = 0;

        vector<int> rejected_holder_ids;

        bool checkpoint_record_exists = false;
        bool registered_checkpoint_output_sharing_exists = false;
        bool checkpoint_output_sharing_belongs_to_checkpoint = false;
        bool authentication_decision_metadata_available = false;

        uint64_t registered_snapshot_id = 0;
        uint64_t ultimate_failure_snapshot_id = 0;

        bool registered_published_snapshot_exists = false;
        bool authentication_plan_metadata_available = false;
        bool authentication_material_metadata_available = false;
        bool authentication_metadata_internally_consistent = false;

        vector<uint64_t> authentication_plan_record_ids;
        vector<uint64_t> authentication_material_record_ids;
        vector<int> authentication_verifier_ids;
        vector<int> authentication_holder_ids;
    };

    enum class PendingAnalyzeSharingExecutionAttemptRunAction
    {
        none,
        no_pending_request,
        inconsistent_state,
        ready_authentication_rejection,
        ready_ultimate_failure,
    };

    struct PendingAnalyzeSharingExecutionAttemptRunPlan
    {
        bool valid = false;

        PendingAnalyzeSharingExecutionAttemptRunAction action =
                PendingAnalyzeSharingExecutionAttemptRunAction::none;

        bool request_found = false;
        bool request_structurally_valid = false;

        bool metadata_complete = false;
        bool execution_inputs_metadata_complete = false;

        bool state_updated = false;
        bool performed_action = false;

        uint64_t pending_request_id = 0;

        PendingAnalyzeSharingSource source =
                PendingAnalyzeSharingSource::none;
        PendingAnalyzeSharingTarget target =
                PendingAnalyzeSharingTarget::none;

        bool is_authentication_rejection_request = false;
        bool is_ultimate_failure_request = false;

        uint64_t checkpoint_id = 0;
        uint64_t segment_id = 0;
        uint64_t sharing_id = 0;
        uint64_t registered_checkpoint_output_sharing_id = 0;

        uint64_t registered_snapshot_id = 0;
        uint64_t ultimate_failure_snapshot_id = 0;

        vector<int> rejected_holder_ids;

        vector<uint64_t> authentication_plan_record_ids;
        vector<uint64_t> authentication_material_record_ids;
        vector<int> authentication_verifier_ids;
        vector<int> authentication_holder_ids;

        bool future_requires_analyze_sharing = false;
        bool future_requires_localization = false;
        bool future_requires_dispute_control_update = false;
        bool future_requires_segment_recovery_or_retry = false;

        bool planned_analyze_checkpoint_output_sharing = false;
        bool planned_analyze_published_snapshot = false;
        bool planned_localize_corrupted_party_or_disputed_pair = false;
        bool planned_feed_dispute_control_update = false;
        bool planned_feed_segment_recovery = false;

        bool would_analyze_checkpoint_output_sharing = false;
        bool would_analyze_published_snapshot = false;
        bool would_feed_localization = false;
        bool would_feed_dispute_control_update = false;
        bool would_feed_segment_recovery_or_retry = false;

        bool would_execute_analyze_sharing = false;
        bool would_use_checkpoint_output_sharing = false;
        bool would_use_published_snapshot = false;
        bool would_feed_run_localization = false;
        bool would_feed_run_dispute_control_update = false;
        bool would_feed_run_segment_recovery_or_retry = false;
    };

    enum class SegmentRecoveryDecisionAction
    {
        none,
        no_open_segment,
        wait_for_checkpoint,
        wait_for_authentication_request,
        wait_for_authentication_material,
        holder_share_unavailable,
        insufficient_votes,
        would_promote_checkpoint,
        would_complete_authenticated_segment,
        would_enqueue_analyze_requests,
        already_completed,
        inconsistent_state,
    };

    struct SegmentRecoveryDecisionResult
    {
        bool valid = false;

        SegmentRecoveryDecisionAction action =
                SegmentRecoveryDecisionAction::none;

        uint64_t segment_id = 0;
        uint64_t checkpoint_id = 0;

        bool state_updated = false;
        bool checkpoint_authenticated = false;
        bool checkpoint_promotion_ready = false;
        bool segment_completion_ready = false;
        bool analyze_enqueue_ready = false;

        AuthenticationDecisionOutcomeAction authentication_outcome_action =
                AuthenticationDecisionOutcomeAction::none;
        AuthenticationOutcomeHookAction authentication_hook_action =
                AuthenticationOutcomeHookAction::none;
        SegmentCompletionReadinessAction segment_readiness_action =
                SegmentCompletionReadinessAction::none;
        AuthenticationAnalyzePlanAction analyze_plan_action =
                AuthenticationAnalyzePlanAction::none;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<uint64_t> pending_request_ids;
    };

    enum class SegmentRecoveryApplicationAction
    {
        none,
        no_action,
        promoted_checkpoint,
        completed_authenticated_segment,
        enqueued_analyze_requests,
        already_completed,
        waiting,
        inconsistent_state,
    };

    struct SegmentRecoveryApplicationResult
    {
        bool valid = false;

        SegmentRecoveryApplicationAction action =
                SegmentRecoveryApplicationAction::none;

        uint64_t segment_id = 0;
        uint64_t checkpoint_id = 0;

        bool state_updated = false;

        SegmentRecoveryDecisionAction decision_action =
                SegmentRecoveryDecisionAction::none;
        AuthenticationPromotionAction promotion_action =
                AuthenticationPromotionAction::none;
        SegmentCompletionReadinessAction completion_action =
                SegmentCompletionReadinessAction::none;
        AuthenticationAnalyzeEnqueueAction enqueue_action =
                AuthenticationAnalyzeEnqueueAction::none;

        vector<uint64_t> sharing_ids;
        vector<uint64_t> rejected_sharing_ids;
        vector<uint64_t> pending_request_ids;
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

    enum class DisputeControlUpdatePlanAction
    {
        none,
        no_action,
        needs_analyze_sharing,
        would_record_corrupted_party,
        would_record_disputed_pair,
        already_recorded,
        inconsistent_state,
    };

    struct DisputeControlUpdatePlan
    {
        bool valid = false;
        DisputeControlUpdatePlanAction action =
                DisputeControlUpdatePlanAction::none;

        FaultLocalizationAction fault_action =
                FaultLocalizationAction::none;
        FaultLocalizationSource source = FaultLocalizationSource::none;
        SharingToAnalyze sharing_to_analyze = SharingToAnalyze::none;

        bool state_updated = false;

        int corrupted_party = -1;

        int disputed_party_a = -1;
        int disputed_party_b = -1;
        int primary_party = -1;
        int counterparty = -1;

        vector<int> newly_corrupted_parties;
        vector<pair<int, int>> newly_disputed_pairs;
    };

    enum class DisputeControlUpdateApplicationAction
    {
        none,
        no_action,
        pending_analyze_sharing,
        recorded_corrupted_party,
        recorded_disputed_pair,
        already_recorded,
        inconsistent_state,
    };

    struct DisputeControlUpdateApplicationResult
    {
        bool valid = false;
        DisputeControlUpdateApplicationAction action =
                DisputeControlUpdateApplicationAction::none;

        DisputeControlUpdatePlanAction plan_action =
                DisputeControlUpdatePlanAction::none;
        FaultLocalizationAction fault_action =
                FaultLocalizationAction::none;
        FaultLocalizationSource source = FaultLocalizationSource::none;
        SharingToAnalyze sharing_to_analyze = SharingToAnalyze::none;

        bool state_updated = false;

        int corrupted_party = -1;

        int disputed_party_a = -1;
        int disputed_party_b = -1;
        int primary_party = -1;
        int counterparty = -1;

        vector<int> newly_corrupted_parties;
        vector<pair<int, int>> newly_disputed_pairs;
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
        bool has_analyze_sharing_request = false;
        AnalyzeSharingRequest analyze_sharing_request;
        bool has_analyze_enqueue_result = false;
        UltimateFailureAnalyzeEnqueueResult analyze_enqueue_result;
    };

    DisputeControlState dispute_control_state;
    VerifiableSharingRegistry verifiable_registry;
    SegmentLifecycleState segment_lifecycle;
    AuthenticationPlanState authentication_plan_state;
    AuthenticationMaterialState authentication_material_state;
    PendingAnalyzeSharingState pending_analyze_sharing_state;

    OptimisticAuthenticationState optimistic_authentication_state;
    IntegratedOrdinaryBatchState integrated_ordinary_batch_state;
    OrdinaryOnlineSegmentCollector ordinary_online_segment_collector;
    bool producer_provenance_test_hook_ran = false;
    bool consumed_provenance_transfer_test_hook_ran = false;
    bool special_e_t_test_enabled = false;
    bool special_e_t_test_hook_ran = false;
    size_t special_e_t_test_completed_records = 0;
    bool tentative_double_rand_capture_test_enabled = false;
    bool tentative_double_rand_capture_test_checked_first_output = false;
    bool tentative_double_rand_capture_test_hook_ran = false;
    string tentative_double_rand_adapter_test_mode;
    string honest_batch_integration_test_mode;
    bool honest_batch_integration_test_hook_ran = false;
    SeededPRNG optimistic_authentication_prng;
    ShamirInput<T> optimistic_authentication_input;

    UltimateFailureContext ultimate_failure_context;
    bool have_ultimate_failure_context = false;

    typename Atlas<T>::PartialMultTranscript current_virtual_transcript;
    bool have_current_virtual_transcript = false;

    typename Atlas<T>::KingPartialMultEvidence current_virtual_king_evidence;
    bool have_current_virtual_king_evidence = false;

    AtlasGsz(Player& P, uint64_t base_field_ftag_chunk_width,
            PreserveBaseFieldFTagChunkWidth);

    static uint64_t parse_base_field_ftag_chunk_width();
    size_t base_field_ftag_chunk_width() const;
    size_t base_field_ftag_chunk_count(size_t original_source_count) const;
    static size_t checked_size_product(
            size_t left, size_t right, const char* description);
    static size_t checked_size_sum(
            size_t left, size_t right, const char* description);
    bool agree_base_field_ftag_chunk_width();

    bool begin_tentative_double_rand_capture();
    bool capture_completed_ordinary_double_rand(
            const PartialMultTranscriptRecord& record,
            size_t record_ordinal,
            OrdinaryDoubleRandOperationKind operation_kind);
    bool validate_tentative_concrete_e_t_source(
            const TentativeConcreteEtSource& source,
            size_t record_ordinal,
            OrdinaryDoubleRandOperationKind operation_kind) const;
    bool finalize_tentative_double_rand_capture();
    const TentativeDoubleRandCaptureCandidate*
        inspect_tentative_double_rand_capture() const;
    void discard_tentative_double_rand_capture();
    bool validate_tentative_paired_producer_record(
            const typename Atlas<T>::DoubleSharingProducerProvenance&
                producer) const;
    bool validate_tentative_double_rand_candidate(
            const TentativeDoubleRandCaptureCandidate& candidate) const;
    bool validate_exact_ordinary_batch_correspondence(
            const TentativeDoubleRandCaptureCandidate& candidate) const;
    unique_ptr<FrozenOrdinaryBatch> build_frozen_ordinary_candidate(
            unique_ptr<TentativeDoubleRandCaptureCandidate> candidate,
            uint64_t verification_batch_serial,
            size_t x_verify_coordinate_count,
            size_t partial_transcript_count);
    unique_ptr<FrozenOrdinaryBatch>
        freeze_finalized_tentative_double_rand_candidate();
    unique_ptr<FrozenOrdinaryBatch>
        merge_verified_ordinary_segment_candidates();
    void maybe_complete_tentative_double_rand_capture_test();
    bool no_authentication_or_checkpoint_artifacts() const;
    void run_special_e_t_malformed_support_test();
    void maybe_run_special_e_t_test(
            const PartialMultTranscriptRecord& record,
            OrdinaryDoubleRandOperationKind operation_kind,
            const T& result);

    void validate_partial_mult_transcript_coverage() const;
    void validate_current_virtual_transcript() const;
    typename T::open_type sample_agreed_challenge();
    typename T::open_type sample_nonzero_agreed_challenge();
    vector<vector<typename T::open_type>>
        broadcast_local_shares(const vector<T>& local_shares);
    vector<typename T::open_type> make_twisted_sharing(
            const typename T::open_type& value,
            int degree,
            int holder);
    typename T::open_type reconstruct_twisted_at_holder(
            const vector<typename T::open_type>& shares,
            int holder) const;
    bool twisted_sharing_is_degree_at_most(
            const vector<typename T::open_type>& shares,
            int holder,
            int degree) const;
    LongTermMuKeyRecord* find_long_term_mu_key(int verifier, int holder);
    const LongTermMuKeyRecord* find_long_term_mu_key(
            int verifier, int holder) const;
    BatchNuMaterialRecord* find_batch_nu_material(
            uint64_t batch_id,
            size_t chunk_ordinal,
            bool check_mask,
            uint64_t key_epoch,
            int verifier,
            int holder);
    const BatchNuMaterialRecord* find_batch_nu_material(
            uint64_t batch_id,
            size_t chunk_ordinal,
            bool check_mask,
            uint64_t key_epoch,
            int verifier,
            int holder) const;
    HolderTagRecord* find_holder_tag(
            uint64_t batch_id,
            size_t chunk_ordinal,
            bool check_mask,
            uint64_t key_epoch,
            int verifier,
            int holder);
    const HolderTagRecord* find_holder_tag(
            uint64_t batch_id,
            size_t chunk_ordinal,
            bool check_mask,
            uint64_t key_epoch,
            int verifier,
            int holder) const;
    DealerSourceBatchRecord* find_dealer_source_batch(uint64_t batch_id);
    const DealerSourceBatchRecord* find_dealer_source_batch(
            uint64_t batch_id) const;
    OptimisticCheckpointRecord* find_optimistic_checkpoint(
            uint64_t checkpoint_id);
    const OptimisticCheckpointRecord* find_optimistic_checkpoint(
            uint64_t checkpoint_id) const;
    bool establish_optimistic_authentication_keys();
    bool check_optimistic_authentication_keys();
    vector<T> deal_optimistic_source_values(
            int dealer,
            const vector<typename T::open_type>& dealer_values,
            size_t count);
    uint64_t register_dealer_source_batch(
            int dealer,
            const vector<T>& local_source_shares);
    void register_tentative_double_rand_batches_atomically(
            vector<DealerSourceBatchRecord>& prospective_batches,
            uint64_t next_batch_id_after);
    bool masked_degree_t_consistency_check(
            const vector<T>& local_shares,
            bool inject_bad_published_share,
            typename T::open_type& challenge,
            vector<typename T::open_type>& published_shares);
    bool verify_dealer_source_batch(
            DealerSourceBatchRecord& batch,
            bool inject_bad_published_share);
    bool prepare_and_verify_base_sharing(
            DealerSourceBatchRecord& batch,
            vector<T>& base_sharing,
            bool inject_bad_published_share);
    vector<BaseFieldFTagSourceChunk> source_chunks_for_batch(
            const DealerSourceBatchRecord& batch) const;
    bool compute_and_deliver_batch_tags(
            DealerSourceBatchRecord& batch,
            const vector<BaseFieldFTagSourceChunk>& source_chunks,
            bool check_mask,
            size_t& nu_begin,
            size_t& tag_begin);
    bool prepare_global_authentication(
            GlobalAuthenticationInvocationRecord& invocation,
            const vector<uint64_t>& requested_batch_ids,
            GlobalAuthenticationWorkingSet& working,
            int inject_bad_verify_sharing_dealer,
            int inject_bad_base_sharing_dealer,
            GlobalAuthenticationTestFault test_fault);
    bool validate_global_authentication_material(
            const GlobalAuthenticationInvocationRecord& invocation,
            const GlobalAuthenticationWorkingSet& working) const;
    bool check_global_authentication(
            GlobalAuthenticationInvocationRecord& invocation,
            const GlobalAuthenticationWorkingSet& working,
            GlobalAuthenticationTestFault test_fault);
    bool commit_global_authentication(
            GlobalAuthenticationInvocationRecord& invocation,
            const GlobalAuthenticationWorkingSet& working);
    bool authenticate_checkpoint_source_batches(
            uint64_t checkpoint_id,
            const vector<uint64_t>& requested_batch_ids,
            GlobalAuthenticationTestFault test_fault =
                    GlobalAuthenticationTestFault::none,
            int inject_bad_verify_sharing_dealer = -1,
            int inject_bad_base_sharing_dealer = -1);
    bool authenticate_source_batches(
            const vector<uint64_t>& requested_batch_ids,
            GlobalAuthenticationTestFault test_fault =
                    GlobalAuthenticationTestFault::none,
            int inject_bad_verify_sharing_dealer = -1,
            int inject_bad_base_sharing_dealer = -1);
    TentativeDoubleRandAuthenticationReceipt
        authenticate_frozen_tentative_double_rand_candidate(
                FrozenOrdinaryBatch& frozen,
                GlobalAuthenticationTestFault test_fault =
                        GlobalAuthenticationTestFault::none,
                int inject_bad_verify_sharing_dealer = -1);
    TentativeDoubleRandAuthenticationReceipt
        adapt_finalized_tentative_double_rand_candidate(
                GlobalAuthenticationTestFault test_fault =
                        GlobalAuthenticationTestFault::none,
                int inject_bad_verify_sharing_dealer = -1);
    void run_tentative_double_rand_adapter_test_hook(const string& mode);
    size_t effective_max_before_check() const;
    bool automatic_ordinary_integration_enabled() const;
    bool communication_audit_enabled() const;
    static bool audit_environment_flag_enabled(const char* name);
    bool runtime_audit_enabled() const;
    bool memory_audit_enabled() const;
    void print_runtime_audit_summary() const;
    void ensure_wrapper_entry_allowed(const char* operation);
    bool replace_empty_preprocessing_initialization_wrapper();
    void enter_verification_operation(
            OrdinaryDoubleRandOperationKind operation_kind);
    void finish_verification_operation(
            OrdinaryDoubleRandOperationKind operation_kind,
            size_t coordinate_count);
    bool verification_batch_is_eligible_ordinary() const;
    void request_check(VerificationBatchFlushReason reason);
    void begin_ordinary_online_segment();
    void collect_verified_ordinary_batch(
            unique_ptr<FrozenOrdinaryBatch> frozen,
            const IntegratedBatchReport& report);
    void close_ordinary_online_segment();
    size_t estimate_frozen_ordinary_batch_owned_bytes(
            const FrozenOrdinaryBatch& frozen) const;
    size_t estimate_ordinary_segment_collector_owned_bytes() const;
    void cleanup_successful_integrated_batch(
            size_t dealer_batch_start,
            size_t nu_material_start,
            size_t holder_tag_start,
            size_t global_invocation_start,
            IntegratedBatchReport& report);
    void print_integrated_batch_report(
            const IntegratedBatchReport& report) const;
    void print_communication_audit_batch(
            const IntegratedBatchReport& report) const;
    void print_communication_audit_summary() const;
    void maybe_flush_honest_batch_integration_residual();
    bool authenticate_dealer_source_batch(
            uint64_t batch_id,
            bool inject_bad_presentation = false,
            bool inject_bad_verify_sharing = false,
            bool inject_bad_base_sharing = false);
    void fail_global_authentication(
            GlobalAuthenticationInvocationRecord* invocation,
            DealerSourceBatchRecord* batch,
            OptimisticAuthenticationFailureClass failure_class,
            int verifier = -1,
            int holder = -1);
    uint64_t create_optimistic_checkpoint(
            const vector<LinearDerivation>& output_derivations);
    bool promote_optimistic_checkpoint(uint64_t checkpoint_id);
    bool authenticated_handle_exists(
            const AuthenticatedSourceHandle& handle) const;
    bool run_optimistic_authentication_test_hook(const string& mode);
    void maybe_run_consumed_provenance_transfer_test(
            const PartialMultTranscriptRecord& record);
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
    AnalyzeSharingRequest build_analyze_sharing_request(
            const UltimateFailureContext& context);
    void validate_analyze_sharing_request(
            const AnalyzeSharingRequest& request) const;
    void ensure_pending_analyze_sharing_state_initialized();
    void validate_pending_analyze_sharing_state() const;
    PendingAnalyzeSharingRequest*
        find_pending_analyze_sharing_request(uint64_t id);
    const PendingAnalyzeSharingRequest*
        find_pending_analyze_sharing_request(uint64_t id) const;
    bool
        pending_analyze_sharing_request_exists_for_authentication_rejection(
                uint64_t checkpoint_id,
                uint64_t sharing_id) const;
    bool
        pending_analyze_sharing_request_exists_for_ultimate_failure(
                PendingAnalyzeSharingTarget target) const;
    uint64_t
        create_pending_analyze_sharing_request_for_authentication_rejection(
                const AuthenticationAnalyzeSharingPlanEntry& entry);
    uint64_t
        create_pending_analyze_sharing_request_for_ultimate_failure(
                const AnalyzeSharingRequest& request);
    UltimateFailureAnalyzeEnqueueResult
        enqueue_current_ultimate_failure_analyze_request_once();
    void validate_ultimate_failure_analyze_enqueue_result(
            const UltimateFailureAnalyzeEnqueueResult& result) const;
    PendingAnalyzeSharingDispatchPlan
        inspect_pending_analyze_sharing_request_by_index(
                size_t index) const;
    PendingAnalyzeSharingDispatchPlan
        inspect_pending_analyze_sharing_request(uint64_t id) const;
    PendingAnalyzeSharingDispatchPlan
        inspect_next_pending_analyze_sharing_request() const;
    void validate_pending_analyze_sharing_dispatch_plan(
            const PendingAnalyzeSharingDispatchPlan& plan) const;
    PendingAnalyzeSharingExecutionReadinessPlan
        inspect_pending_analyze_sharing_execution_plan_for_request(
                uint64_t pending_request_id) const;
    PendingAnalyzeSharingExecutionReadinessPlan
        inspect_next_pending_analyze_sharing_execution_plan() const;
    void validate_pending_analyze_sharing_execution_plan(
            const PendingAnalyzeSharingExecutionReadinessPlan& plan)
            const;
    PendingAnalyzeSharingExecutionAttemptRunPlan
        inspect_pending_analyze_sharing_execution_attempt_run_plan(
                uint64_t pending_request_id) const;
    PendingAnalyzeSharingExecutionAttemptRunPlan
        inspect_next_pending_analyze_sharing_execution_attempt_run_plan()
            const;
    void validate_pending_analyze_sharing_execution_attempt_run_plan(
            const PendingAnalyzeSharingExecutionAttemptRunPlan& plan)
            const;
    void ensure_verifiable_registry_initialized();
    uint64_t register_verifiable_sharing(
            const T& local_share,
            RegisteredSharingDegree degree,
            RegisteredSharingKind kind);
    uint64_t register_published_degree_t_snapshot(
            const PublishedDegreeTSharing& published,
            RegisteredSharingKind kind);
    RegisteredVerifiableSharing* find_registered_sharing(uint64_t id);
    const RegisteredVerifiableSharing*
        find_registered_sharing(uint64_t id) const;
    uint64_t create_checkpoint_record(
            const vector<uint64_t>& sharing_ids);
    void mark_checkpoint_sealed(uint64_t checkpoint_id);
    void mark_checkpoint_authentication_requested(uint64_t checkpoint_id);
    void mark_checkpoint_authenticated(uint64_t checkpoint_id);
    void validate_verifiable_registry() const;
    void ensure_segment_lifecycle_initialized();
    void validate_segment_lifecycle() const;
    uint64_t begin_segment();
    uint64_t current_segment_id() const;
    uint64_t register_segment_input_sharing(const T& local_share);
    uint64_t register_segment_output_sharing(const T& local_share);
    uint64_t create_input_checkpoint_for_current_segment();
    uint64_t create_output_checkpoint_for_current_segment();
    void seal_current_output_checkpoint();
    void mark_current_output_checkpoint_authentication_requested();
    void mark_current_output_checkpoint_authenticated();
    void complete_current_segment_successfully();
    SegmentCompletionReadinessResult
        inspect_current_segment_completion_readiness() const;
    SegmentCompletionReadinessResult
        inspect_segment_completion_readiness(
                uint64_t segment_id,
                uint64_t checkpoint_id) const;
    SegmentCompletionReadinessResult
        complete_current_segment_if_checkpoint_authenticated();
    void abandon_current_segment_after_failure();
    void ensure_authentication_plan_initialized();
    void validate_authentication_plan() const;
    uint64_t create_authentication_plan_record(
            uint64_t sharing_id,
            uint64_t checkpoint_id,
            int verifier,
            int holder,
            AuthenticationRecordKind kind);
    vector<uint64_t> create_checkpoint_authentication_plan(
            uint64_t checkpoint_id);
    AuthenticationPlanRecord*
        find_authentication_plan_record(uint64_t id);
    const AuthenticationPlanRecord*
        find_authentication_plan_record(uint64_t id) const;
    vector<uint64_t> authentication_records_for_checkpoint(
            uint64_t checkpoint_id) const;
    vector<uint64_t> authentication_records_for_sharing(
            uint64_t sharing_id) const;
    void mark_authentication_record_requested(uint64_t id);
    void mark_authentication_record_authenticated(uint64_t id);
    bool checkpoint_authentication_plan_complete(
            uint64_t checkpoint_id) const;
    vector<uint64_t> create_analyze_snapshot_authentication_plan(
            uint64_t registered_snapshot_id);
    void ensure_authentication_material_initialized();
    void validate_authentication_material() const;
    uint64_t create_authentication_material_placeholder(
            uint64_t auth_record_id);
    AuthenticationMaterialRecord*
        find_authentication_material_record(uint64_t id);
    const AuthenticationMaterialRecord*
        find_authentication_material_record(uint64_t id) const;
    AuthenticationMaterialRecord*
        find_authentication_material_for_auth_record(
                uint64_t auth_record_id);
    const AuthenticationMaterialRecord*
        find_authentication_material_for_auth_record(
                uint64_t auth_record_id) const;
    vector<uint64_t> authentication_material_for_checkpoint(
            uint64_t checkpoint_id) const;
    vector<uint64_t> authentication_material_for_sharing(
            uint64_t sharing_id) const;
    void assign_authentication_verifier_key_placeholder(
            uint64_t material_id,
            const typename T::open_type& mu,
            const typename T::open_type& nu);
    void assign_authentication_holder_tag_placeholder(
            uint64_t material_id,
            const typename T::open_type& tag);
    bool authentication_material_complete(uint64_t material_id) const;
    void create_material_placeholders_for_auth_records(
            const vector<uint64_t>& auth_record_ids);
    bool holder_share_available_for_material(
            const AuthenticationMaterialRecord& material) const;
    typename T::open_type holder_share_for_material(
            const AuthenticationMaterialRecord& material) const;
    AuthenticationEquationResult check_authentication_equation(
            uint64_t material_id) const;
    vector<AuthenticationEquationResult>
        check_authentication_equations_for_checkpoint(
                uint64_t checkpoint_id) const;
    vector<AuthenticationEquationResult>
        check_authentication_equations_for_sharing(
                uint64_t sharing_id) const;
    bool authentication_equation_passes(uint64_t material_id) const;
    bool all_available_authentication_equations_pass(
            const vector<uint64_t>& material_ids) const;
    AuthenticationVerifierVote authentication_vote_from_material(
            uint64_t material_id) const;
    vector<AuthenticationVerifierVote>
        authentication_votes_for_sharing(uint64_t sharing_id) const;
    vector<AuthenticationVerifierVote>
        authentication_votes_for_checkpoint(uint64_t checkpoint_id) const;
    AuthenticationHolderDecision authentication_holder_decision_for_sharing(
            uint64_t sharing_id,
            int holder) const;
    vector<AuthenticationHolderDecision>
        authentication_holder_decisions_for_sharing(
                uint64_t sharing_id) const;
    vector<AuthenticationHolderDecision>
        authentication_holder_decisions_for_checkpoint(
                uint64_t checkpoint_id) const;
    AuthenticationSharingDecision authentication_sharing_decision(
            uint64_t sharing_id) const;
    vector<AuthenticationSharingDecision>
        authentication_sharing_decisions_for_checkpoint(
                uint64_t checkpoint_id) const;
    AuthenticationCheckpointDecision authentication_checkpoint_decision(
            uint64_t checkpoint_id) const;
    AuthenticationCheckpointDecision
        current_output_checkpoint_authentication_decision() const;
    AuthenticationDecisionOutcome
        authentication_decision_outcome_from_checkpoint_decision(
                const AuthenticationCheckpointDecision& decision) const;
    AuthenticationDecisionOutcome
        authentication_decision_outcome_for_checkpoint(
                uint64_t checkpoint_id) const;
    AuthenticationDecisionOutcome
        current_output_checkpoint_authentication_outcome() const;
    AuthenticationOutcomeHookResult inspect_authentication_outcome_hook(
            const AuthenticationDecisionOutcome& outcome) const;
    AuthenticationOutcomeHookResult
        inspect_authentication_outcome_hook_for_checkpoint(
                uint64_t checkpoint_id) const;
    AuthenticationOutcomeHookResult
        inspect_current_output_checkpoint_authentication_hook() const;
    AuthenticationPromotionResult
        promote_accepted_authentication_outcome(
                const AuthenticationDecisionOutcome& outcome);
    AuthenticationPromotionResult
        promote_accepted_authentication_outcome_for_checkpoint(
                uint64_t checkpoint_id);
    AuthenticationPromotionResult
        promote_current_output_checkpoint_authentication_outcome();
    AuthenticationAnalyzeSharingPlanEntry
        authentication_analyze_plan_entry_for_rejected_sharing(
                uint64_t sharing_id) const;
    AuthenticationAnalyzeSharingPlan
        authentication_analyze_plan_from_hook_result(
                const AuthenticationOutcomeHookResult& hook_result) const;
    AuthenticationAnalyzeSharingPlan
        authentication_analyze_plan_for_checkpoint(
                uint64_t checkpoint_id) const;
    AuthenticationAnalyzeSharingPlan
        current_output_checkpoint_authentication_analyze_plan() const;
    AuthenticationAnalyzeEnqueueResult enqueue_authentication_analyze_plan(
            const AuthenticationAnalyzeSharingPlan& plan);
    AuthenticationAnalyzeEnqueueResult
        enqueue_authentication_analyze_requests_from_hook_result(
                const AuthenticationOutcomeHookResult& hook);
    AuthenticationAnalyzeEnqueueResult
        enqueue_authentication_analyze_requests_for_checkpoint(
                uint64_t checkpoint_id);
    AuthenticationAnalyzeEnqueueResult
        enqueue_current_output_checkpoint_authentication_analyze_requests();
    SegmentRecoveryDecisionResult
        inspect_current_segment_recovery_decision() const;
    SegmentRecoveryDecisionResult inspect_segment_recovery_decision(
            uint64_t segment_id,
            uint64_t checkpoint_id) const;
    SegmentRecoveryApplicationResult
        apply_current_segment_recovery_decision_once();
    SegmentRecoveryApplicationResult apply_segment_recovery_decision_once(
            const SegmentRecoveryDecisionResult& decision);
    void validate_authentication_vote(
            const AuthenticationVerifierVote& vote) const;
    void validate_authentication_holder_decision(
            const AuthenticationHolderDecision& decision) const;
    void validate_authentication_sharing_decision(
            const AuthenticationSharingDecision& decision) const;
    void validate_authentication_checkpoint_decision(
            const AuthenticationCheckpointDecision& decision) const;
    void validate_authentication_decision_outcome(
            const AuthenticationDecisionOutcome& outcome) const;
    void validate_authentication_outcome_hook_result(
            const AuthenticationOutcomeHookResult& result) const;
    void validate_authentication_promotion_result(
            const AuthenticationPromotionResult& result) const;
    void validate_segment_completion_readiness_result(
            const SegmentCompletionReadinessResult& result) const;
    void validate_authentication_analyze_plan_entry(
            const AuthenticationAnalyzeSharingPlanEntry& entry) const;
    void validate_authentication_analyze_sharing_plan(
            const AuthenticationAnalyzeSharingPlan& plan) const;
    void validate_authentication_analyze_enqueue_result(
            const AuthenticationAnalyzeEnqueueResult& result) const;
    void validate_segment_recovery_decision_result(
            const SegmentRecoveryDecisionResult& result) const;
    void validate_segment_recovery_application_result(
            const SegmentRecoveryApplicationResult& result) const;
    void ensure_dispute_control_state_initialized();
    void validate_dispute_control_state() const;
    DisputeControlUpdatePlan inspect_dispute_control_update_plan(
            const FaultLocalizationOutcome& outcome) const;
    DisputeControlUpdatePlan inspect_current_dispute_control_update_plan()
            const;
    void validate_dispute_control_update_plan(
            const DisputeControlUpdatePlan& plan) const;
    DisputeControlUpdateApplicationResult
        apply_dispute_control_update_once(
                const FaultLocalizationOutcome& outcome);
    DisputeControlUpdateApplicationResult
        apply_current_dispute_control_update_once();
    void validate_dispute_control_update_application_result(
            const DisputeControlUpdateApplicationResult& result) const;
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
        return AtlasGsz(P, base_field_ftag_chunk_width_,
                PreserveBaseFieldFTagChunkWidth{});
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
