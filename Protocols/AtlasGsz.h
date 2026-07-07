/*
 * AtlasGsz.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_H_
#define PROTOCOLS_ATLASGSZ_H_

#include "Atlas.h"
#include "MaliciousShamirMC.h"

#include <cstdint>

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
        bool has_analyze_sharing_request = false;
        AnalyzeSharingRequest analyze_sharing_request;
    };

    DisputeControlState dispute_control_state;
    VerifiableSharingRegistry verifiable_registry;
    SegmentLifecycleState segment_lifecycle;
    AuthenticationPlanState authentication_plan_state;
    AuthenticationMaterialState authentication_material_state;

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
    AnalyzeSharingRequest build_analyze_sharing_request(
            const UltimateFailureContext& context);
    void validate_analyze_sharing_request(
            const AnalyzeSharingRequest& request) const;
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
    void validate_authentication_analyze_plan_entry(
            const AuthenticationAnalyzeSharingPlanEntry& entry) const;
    void validate_authentication_analyze_sharing_plan(
            const AuthenticationAnalyzeSharingPlan& plan) const;
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
