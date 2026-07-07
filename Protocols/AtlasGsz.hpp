/*
 * AtlasGsz.hpp
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_HPP_
#define PROTOCOLS_ATLASGSZ_HPP_

#include "AtlasGsz.h"

#include <algorithm>
#include <numeric>
#include "BufferScope.h"
#include "AtlasConfig.h"


template<class T>
AtlasGsz<T>::AtlasGsz(Player& P) : honest(P), P(P)
{
    honest.set_fixed_king(0);
    x_verify.reserve(AtlasConfig::max_before_check);
    y_verify.reserve(AtlasConfig::max_before_check);
    z_verify.reserve(AtlasConfig::max_before_check);
    partial_mult_transcripts.reserve(AtlasConfig::max_before_check);
}

template<class T>
AtlasGsz<T>::~AtlasGsz()
{
    check();
    check_opened_values();
}

template <class T>
inline void AtlasGsz<T>::maybe_check()
{
    if (x_verify.size() >= AtlasConfig::max_before_check) {
        check();
        x_verify.reserve(AtlasConfig::max_before_check);
        y_verify.reserve(AtlasConfig::max_before_check);
    }
    if (local_mc_2t.stored_values.size() >= AtlasConfig::max_openings_before_check) {
        check_opened_values();
    }
}

template<class T>
void AtlasGsz<T>::validate_partial_mult_transcript_coverage() const
{
#ifndef NDEBUG
    assert(x_verify.size() == y_verify.size());
    assert(x_verify.size() == z_verify.size());
    assert(not partial_mult_transcripts.empty());

    int batch_king = partial_mult_transcripts.front().transcript.king;
    size_t expected_offset = 0;
    for (const auto& record : partial_mult_transcripts)
    {
        assert(record.length > 0);
        assert(record.transcript.king == batch_king);
        assert(record.has_king_evidence == (P.my_num() == batch_king));
        assert(record.offset == expected_offset);
        assert(record.offset + size_t(record.length) <= x_verify.size());

        T product = T{0};
        for (int j = 0; j < record.length; j++)
            product += x_verify.at(record.offset + j)
                    * y_verify.at(record.offset + j);

        assert(record.transcript.e_2t
                == product + record.transcript.r_2t);
        assert(record.transcript.e_t
                - record.transcript.r_t
                == z_verify.at(record.offset));
        validate_double_sharing_decomposition(
                record.transcript.r_decomposition,
                record.transcript.r_t,
                record.transcript.r_2t);

        if (record.has_king_evidence)
        {
            assert(record.king_evidence.king == batch_king);
            assert(record.king_evidence.received_e_2t.size()
                    == size_t(P.num_players()));
            assert(record.king_evidence.distributed_e_t.size()
                    == size_t(P.num_players()));
        }

        expected_offset += record.length;
    }

    assert(expected_offset == x_verify.size());
#endif
}

template<class T>
void AtlasGsz<T>::validate_current_virtual_transcript() const
{
#ifndef NDEBUG
    assert(have_current_virtual_transcript);
    assert(x_verify.size() == y_verify.size());
    assert(not x_verify.empty());

    T product = T{0};
    for (size_t i = 0; i < x_verify.size(); i++)
        product += x_verify.at(i) * y_verify.at(i);

    assert(current_virtual_transcript.e_2t
            == product + current_virtual_transcript.r_2t);
    assert(current_virtual_transcript.e_t
            - current_virtual_transcript.r_t
            == z_de_linearized);
    validate_double_sharing_decomposition(
            current_virtual_transcript.r_decomposition,
            current_virtual_transcript.r_t,
            current_virtual_transcript.r_2t);

    int king = current_virtual_transcript.king;
    assert(have_current_virtual_king_evidence == (P.my_num() == king));

    if (P.my_num() == king)
    {
        assert(current_virtual_king_evidence.king == king);
        assert(current_virtual_king_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(current_virtual_king_evidence.distributed_e_t.size()
                == size_t(P.num_players()));

        typename Atlas<T>::share_value_type local_e_2t =
                current_virtual_transcript.e_2t;
        typename Atlas<T>::share_value_type local_e_t =
                current_virtual_transcript.e_t;

        assert(current_virtual_king_evidence.received_e_2t.at(king)
                == local_e_2t);
        assert(current_virtual_king_evidence.distributed_e_t.at(king)
                == local_e_t);

        int t = ShamirMachine::s().threshold;
        typename Atlas<T>::share_value_type received_secret(0);
        typename Atlas<T>::share_value_type distributed_secret(0);

        for (int i = 0; i < 2 * t + 1; i++)
            received_secret +=
                    current_virtual_king_evidence.received_e_2t.at(i)
                    * Shamir<T>::get_rec_factor(i, 2 * t + 1);

        for (int i = 0; i < t + 1; i++)
            distributed_secret +=
                    current_virtual_king_evidence.distributed_e_t.at(i)
                    * Shamir<T>::get_rec_factor(i, t + 1);

        assert(received_secret == distributed_secret);
    }
#endif
}

template<class T>
typename T::open_type AtlasGsz<T>::sample_agreed_challenge()
{
    vector<T> challenge_sharings;
    challenge_sharings.push_back(get_random());

    vector<typename T::open_type> opened;
    malicious_mc.POpen(opened, challenge_sharings, P);

    assert(opened.size() == 1);
    return opened.at(0);
}

template<class T>
vector<vector<typename T::open_type>> AtlasGsz<T>::broadcast_local_shares(
        const vector<T>& local_shares)
{
    vector<octetStream> streams(P.num_players());
    for (const auto& share : local_shares)
    {
        typename T::open_type local_share = share;
        local_share.pack(streams.at(P.my_num()));
    }

    P.Broadcast_Receive(streams);
    P.Check_Broadcast();

    vector<vector<typename T::open_type>> result(
            local_shares.size(),
            vector<typename T::open_type>(P.num_players()));

    for (int player = 0; player < P.num_players(); player++)
    {
        for (size_t i = 0; i < local_shares.size(); i++)
            result.at(i).at(player).unpack(streams.at(player));
        assert(not streams.at(player).left());
    }

    for (const auto& shares : result)
        assert(shares.size() == size_t(P.num_players()));

    return result;
}

template<class T>
typename AtlasGsz<T>::PublishedDegreeTSharing
AtlasGsz<T>::classify_degree_t_sharing(
        const vector<typename T::open_type>& shares)
{
    assert(shares.size() == size_t(P.num_players()));

    PublishedDegreeTSharing result{};
    result.shares = shares;
    malicious_mc.init_open(P);
    vector<typename T::open_type> relative_shares;
    relative_shares.reserve(P.num_players());
    for (int i = 0; i < P.num_players(); i++)
        relative_shares.push_back(result.shares.at(P.get_player(i)));
    try
    {
        result.value = malicious_mc.reconstruct(relative_shares);
        result.consistent = true;
    }
    catch (const mac_fail&)
    {
        result.consistent = false;
    }
    return result;
}

template<class T>
typename AtlasGsz<T>::PublishedDegree2TVector
AtlasGsz<T>::collect_degree_2t_vector(
        const vector<typename T::open_type>& shares)
{
    assert(shares.size() == size_t(P.num_players()));

    PublishedDegree2TVector result{};
    result.shares = shares;
    result.value = typename T::open_type{};
    for (int i = 0; i < P.num_players(); i++)
        result.value += result.shares.at(i)
                * Shamir<T>::get_rec_factor(i, P.num_players());

    return result;
}

template<class T>
typename Atlas<T>::DoubleSharingDecomposition
AtlasGsz<T>::zero_double_sharing_decomposition() const
{
    typename Atlas<T>::DoubleSharingDecomposition res{};
    res.dealer_components.resize(P.num_players());
    res.own_dealer_evidence.r_t_shares.assign(
            P.num_players(), typename Atlas<T>::share_value_type{});
    res.own_dealer_evidence.r_2t_shares.assign(
            P.num_players(), typename Atlas<T>::share_value_type{});
    res.validated_residual.r_t = T{0};
    res.validated_residual.r_2t = T{0};
    for (auto& component : res.dealer_components)
    {
        component.r_t = T{0};
        component.r_2t = T{0};
    }
    return res;
}

template<class T>
typename Atlas<T>::DealerDoubleSharingContribution
AtlasGsz<T>::sum_double_sharing_decomposition(
        const typename Atlas<T>::DoubleSharingDecomposition&
            decomposition) const
{
    assert(decomposition.dealer_components.size() == size_t(P.num_players()));
    assert(decomposition.own_dealer_evidence.r_t_shares.size()
            == size_t(P.num_players()));
    assert(decomposition.own_dealer_evidence.r_2t_shares.size()
            == size_t(P.num_players()));
    typename Atlas<T>::DealerDoubleSharingContribution sum{};
    sum.r_t = decomposition.validated_residual.r_t;
    sum.r_2t = decomposition.validated_residual.r_2t;
    for (const auto& component : decomposition.dealer_components)
    {
        sum.r_t += component.r_t;
        sum.r_2t += component.r_2t;
    }
    return sum;
}

template<class T>
void AtlasGsz<T>::validate_double_sharing_decomposition(
        const typename Atlas<T>::DoubleSharingDecomposition& decomposition,
        const T& r_t,
        const T& r_2t) const
{
    auto sum = sum_double_sharing_decomposition(decomposition);
    assert(sum.r_t == r_t);
    assert(sum.r_2t == r_2t);
    assert(decomposition.own_dealer_evidence.r_t_shares.at(P.my_num())
            == decomposition.dealer_components.at(P.my_num()).r_t);
    assert(decomposition.own_dealer_evidence.r_2t_shares.at(P.my_num())
            == decomposition.dealer_components.at(P.my_num()).r_2t);
}

template<class T>
void AtlasGsz<T>::add_scaled_double_sharing_decomposition(
        typename Atlas<T>::DoubleSharingDecomposition& accumulator,
        const typename Atlas<T>::DoubleSharingDecomposition& source,
        const typename T::open_type& coefficient) const
{
    assert(accumulator.dealer_components.size() == size_t(P.num_players()));
    assert(source.dealer_components.size() == size_t(P.num_players()));
    assert(accumulator.own_dealer_evidence.r_t_shares.size()
            == size_t(P.num_players()));
    assert(accumulator.own_dealer_evidence.r_2t_shares.size()
            == size_t(P.num_players()));
    assert(source.own_dealer_evidence.r_t_shares.size()
            == size_t(P.num_players()));
    assert(source.own_dealer_evidence.r_2t_shares.size()
            == size_t(P.num_players()));
    accumulator.validated_residual.r_t +=
            source.validated_residual.r_t * coefficient;
    accumulator.validated_residual.r_2t +=
            source.validated_residual.r_2t * coefficient;
    for (int i = 0; i < P.num_players(); i++)
    {
        accumulator.dealer_components.at(i).r_t +=
                source.dealer_components.at(i).r_t * coefficient;
        accumulator.dealer_components.at(i).r_2t +=
                source.dealer_components.at(i).r_2t * coefficient;
        accumulator.own_dealer_evidence.r_t_shares.at(i) +=
                source.own_dealer_evidence.r_t_shares.at(i) * coefficient;
        accumulator.own_dealer_evidence.r_2t_shares.at(i) +=
                source.own_dealer_evidence.r_2t_shares.at(i) * coefficient;
    }
}

template<class T>
typename Atlas<T>::DoubleSharingDecomposition
AtlasGsz<T>::subtract_double_sharing_decomposition(
        const typename Atlas<T>::DoubleSharingDecomposition& left,
        const typename Atlas<T>::DoubleSharingDecomposition& right) const
{
    auto res = zero_double_sharing_decomposition();
    typename T::open_type one(1);
    typename T::open_type minus_one = typename T::open_type(0) - one;
    add_scaled_double_sharing_decomposition(res, left, one);
    add_scaled_double_sharing_decomposition(res, right, minus_one);
    return res;
}

template<class T>
typename Atlas<T>::DoubleSharingDecomposition
AtlasGsz<T>::interpolate_double_sharing_decompositions(
        const typename Atlas<T>::DoubleSharingDecomposition& point_0,
        const typename Atlas<T>::DoubleSharingDecomposition& point_1,
        const typename Atlas<T>::DoubleSharingDecomposition& point_2,
        const typename T::open_type& L0,
        const typename T::open_type& L1,
        const typename T::open_type& L2) const
{
    auto res = zero_double_sharing_decomposition();
    add_scaled_double_sharing_decomposition(res, point_0, L0);
    add_scaled_double_sharing_decomposition(res, point_1, L1);
    add_scaled_double_sharing_decomposition(res, point_2, L2);
    return res;
}

template<class T>
typename AtlasGsz<T>::UltimateFailureDecision
AtlasGsz<T>::diagnose_ultimate_failure(
        const UltimateFailureContext& context) const
{
    assert(context.valid);

    UltimateFailureDecision decision{};
    decision.valid = true;

    if (not context.alpha_t.consistent)
    {
        decision.action = UltimateFailureAction::analyze_alpha;
        return decision;
    }

    if (not context.beta_t.consistent)
    {
        decision.action = UltimateFailureAction::analyze_beta;
        return decision;
    }

    if (not context.delta_t.consistent
            || context.delta_t.value != context.delta_2t.value)
    {
        decision.action = UltimateFailureAction::check_double_rand;
        return decision;
    }

    assert(context.alpha_t.shares.size() == size_t(P.num_players()));
    assert(context.beta_t.shares.size() == size_t(P.num_players()));
    assert(context.delta_t.shares.size() == size_t(P.num_players()));
    assert(context.delta_2t.shares.size() == size_t(P.num_players()));
    assert(context.eta_2t.shares.size() == size_t(P.num_players()));
    assert(context.eta_t.shares.size() == size_t(P.num_players()));
    assert(context.gamma_t.shares.size() == size_t(P.num_players()));

    for (int i = 0; i < P.num_players(); i++)
    {
        bool eta_2t_equation =
                context.eta_2t.shares.at(i)
                == context.alpha_t.shares.at(i)
                * context.beta_t.shares.at(i)
                + context.delta_2t.shares.at(i);
        bool gamma_equation =
                context.gamma_t.shares.at(i)
                == context.eta_t.shares.at(i)
                - context.delta_t.shares.at(i);

        if (not eta_2t_equation || not gamma_equation)
        {
            decision.action =
                    UltimateFailureAction::identify_corrupted_party;
            decision.source =
                    UltimateFailureDecisionSource::
                        local_transcript_equation;
            decision.party = i;
            return decision;
        }
    }

    if (not context.king_distributed_eta_t.consistent
            || context.king_distributed_eta_t.value
                    != context.king_received_eta_2t.value)
    {
        decision.action = UltimateFailureAction::identify_corrupted_party;
        decision.source =
                UltimateFailureDecisionSource::invalid_king_evidence;
        decision.party = context.king;
        return decision;
    }

    if (not context.received_eta_2t_mismatch_players.empty())
    {
        decision.action = UltimateFailureAction::king_party_disagreement;
        decision.king = context.king;
        decision.counterparty = *min_element(
                context.received_eta_2t_mismatch_players.begin(),
                context.received_eta_2t_mismatch_players.end());
        decision.mismatch_kind =
                KingEvidenceMismatchKind::received_eta_2t;
        return decision;
    }

    if (not context.distributed_eta_t_mismatch_players.empty())
    {
        decision.action = UltimateFailureAction::king_party_disagreement;
        decision.king = context.king;
        decision.counterparty = *min_element(
                context.distributed_eta_t_mismatch_players.begin(),
                context.distributed_eta_t_mismatch_players.end());
        decision.mismatch_kind =
                KingEvidenceMismatchKind::distributed_eta_t;
        return decision;
    }

#ifndef NDEBUG
    assert(false);
#endif
    decision.valid = false;
    return decision;
}

template<class T>
typename AtlasGsz<T>::CheckDoubleRandContext
AtlasGsz<T>::run_check_double_rand_diagnosis(
        const typename Atlas<T>::DoubleSharingDecomposition&
            decomposition)
{
    int n = P.num_players();
    assert(decomposition.dealer_components.size() == size_t(n));
    assert(decomposition.own_dealer_evidence.r_t_shares.size()
            == size_t(n));
    assert(decomposition.own_dealer_evidence.r_2t_shares.size()
            == size_t(n));
    assert(decomposition.own_dealer_evidence.r_t_shares.at(P.my_num())
            == decomposition.dealer_components.at(P.my_num()).r_t);
    assert(decomposition.own_dealer_evidence.r_2t_shares.at(P.my_num())
            == decomposition.dealer_components.at(P.my_num()).r_2t);

    vector<octetStream> streams(n);
    for (int recipient = 0; recipient < n; recipient++)
        decomposition.own_dealer_evidence.r_t_shares.at(recipient)
                .pack(streams.at(P.my_num()));
    for (int recipient = 0; recipient < n; recipient++)
        decomposition.own_dealer_evidence.r_2t_shares.at(recipient)
                .pack(streams.at(P.my_num()));
    for (int dealer = 0; dealer < n; dealer++)
    {
        typename T::open_type local_component =
                decomposition.dealer_components.at(dealer).r_t;
        local_component.pack(streams.at(P.my_num()));
    }
    for (int dealer = 0; dealer < n; dealer++)
    {
        typename T::open_type local_component =
                decomposition.dealer_components.at(dealer).r_2t;
        local_component.pack(streams.at(P.my_num()));
    }

    P.Broadcast_Receive(streams);
    P.Check_Broadcast();

    CheckDoubleRandContext context{};
    context.valid = true;
    context.dealer_claims.resize(n);
    context.recipient_views.resize(
            n, vector<typename Atlas<T>::DealerDoubleSharingContribution>(n));
    context.dealer_r_t.resize(n);
    context.dealer_r_2t.resize(n);

    for (int player = 0; player < n; player++)
    {
        auto& dealer_claim = context.dealer_claims.at(player);
        dealer_claim.r_t_shares.resize(n);
        dealer_claim.r_2t_shares.resize(n);

        for (int recipient = 0; recipient < n; recipient++)
            dealer_claim.r_t_shares.at(recipient)
                    .unpack(streams.at(player));
        for (int recipient = 0; recipient < n; recipient++)
            dealer_claim.r_2t_shares.at(recipient)
                    .unpack(streams.at(player));
        for (int dealer = 0; dealer < n; dealer++)
        {
            typename T::open_type local_component;
            local_component.unpack(streams.at(player));
            context.recipient_views.at(player).at(dealer).r_t =
                    local_component;
        }
        for (int dealer = 0; dealer < n; dealer++)
        {
            typename T::open_type local_component;
            local_component.unpack(streams.at(player));
            context.recipient_views.at(player).at(dealer).r_2t =
                    local_component;
        }
        assert(not streams.at(player).left());
    }

    assert(context.dealer_claims.size() == size_t(n));
    assert(context.recipient_views.size() == size_t(n));
    for (int i = 0; i < n; i++)
    {
        assert(context.dealer_claims.at(i).r_t_shares.size()
                == size_t(n));
        assert(context.dealer_claims.at(i).r_2t_shares.size()
                == size_t(n));
        assert(context.recipient_views.at(i).size() == size_t(n));
    }

    for (int dealer = 0; dealer < n; dealer++)
    {
        context.dealer_r_t.at(dealer) =
                classify_degree_t_sharing(
                        context.dealer_claims.at(dealer).r_t_shares);
        context.dealer_r_2t.at(dealer) =
                collect_degree_2t_vector(
                        context.dealer_claims.at(dealer).r_2t_shares);
    }

    assert(context.dealer_r_t.size() == size_t(n));
    assert(context.dealer_r_2t.size() == size_t(n));

    for (int dealer = 0; dealer < n; dealer++)
    {
        if (not context.dealer_r_t.at(dealer).consistent
                || context.dealer_r_t.at(dealer).value
                        != context.dealer_r_2t.at(dealer).value)
        {
            context.decision.valid = true;
            context.decision.action =
                    CheckDoubleRandAction::identify_corrupted_party;
            context.decision.mismatch_kind =
                    CheckDoubleRandMismatchKind::
                        invalid_dealer_double_sharing;
            context.decision.dealer = dealer;
            context.decision.party = dealer;
            assert(context.dealer_r_t.size() == size_t(n));
            assert(context.dealer_r_2t.size() == size_t(n));
            return context;
        }
    }

    for (int dealer = 0; dealer < n; dealer++)
    {
        for (int recipient = 0; recipient < n; recipient++)
        {
            typename T::open_type recipient_r_t =
                    context.recipient_views.at(recipient)
                        .at(dealer).r_t;
            typename T::open_type recipient_r_2t =
                    context.recipient_views.at(recipient)
                        .at(dealer).r_2t;

            if (context.dealer_claims.at(dealer)
                    .r_t_shares.at(recipient) != recipient_r_t)
            {
                context.decision.valid = true;
                context.decision.action =
                        CheckDoubleRandAction::
                            dealer_recipient_disagreement;
                context.decision.mismatch_kind =
                        CheckDoubleRandMismatchKind::r_t_share_mismatch;
                context.decision.dealer = dealer;
                context.decision.recipient = recipient;
                assert(context.dealer_r_t.size() == size_t(n));
                assert(context.dealer_r_2t.size() == size_t(n));
                return context;
            }

            if (context.dealer_claims.at(dealer)
                    .r_2t_shares.at(recipient) != recipient_r_2t)
            {
                context.decision.valid = true;
                context.decision.action =
                        CheckDoubleRandAction::
                            dealer_recipient_disagreement;
                context.decision.mismatch_kind =
                        CheckDoubleRandMismatchKind::r_2t_share_mismatch;
                context.decision.dealer = dealer;
                context.decision.recipient = recipient;
                assert(context.dealer_r_t.size() == size_t(n));
                assert(context.dealer_r_2t.size() == size_t(n));
                return context;
            }
        }
    }

#ifndef NDEBUG
    assert(false);
#endif
    context.valid = false;
    return context;
}

template<class T>
typename AtlasGsz<T>::FaultLocalizationOutcome
AtlasGsz<T>::derive_fault_localization_outcome(
        const UltimateFailureContext& context) const
{
    assert(context.valid);
    assert(context.decision.valid);

    FaultLocalizationOutcome outcome{};

    switch (context.decision.action)
    {
    case UltimateFailureAction::analyze_alpha:
        outcome.valid = true;
        outcome.action = FaultLocalizationAction::needs_analyze_sharing;
        outcome.source = FaultLocalizationSource::inconsistent_alpha;
        outcome.sharing_to_analyze = SharingToAnalyze::alpha;
        return outcome;

    case UltimateFailureAction::analyze_beta:
        outcome.valid = true;
        outcome.action = FaultLocalizationAction::needs_analyze_sharing;
        outcome.source = FaultLocalizationSource::inconsistent_beta;
        outcome.sharing_to_analyze = SharingToAnalyze::beta;
        return outcome;

    case UltimateFailureAction::identify_corrupted_party:
        outcome.valid = true;
        outcome.action = FaultLocalizationAction::identify_corrupted_party;
        outcome.corrupted_party = context.decision.party;
        if (context.decision.source
                == UltimateFailureDecisionSource::local_transcript_equation)
            outcome.source =
                    FaultLocalizationSource::local_transcript_equation;
        else if (context.decision.source
                == UltimateFailureDecisionSource::invalid_king_evidence)
            outcome.source = FaultLocalizationSource::invalid_king_evidence;
        else
        {
#ifndef NDEBUG
            assert(false);
#endif
            outcome.valid = false;
            outcome.action = FaultLocalizationAction::none;
        }
        return outcome;

    case UltimateFailureAction::king_party_disagreement:
        outcome.valid = true;
        outcome.action = FaultLocalizationAction::identify_disputed_pair;
        outcome.source = FaultLocalizationSource::king_party_disagreement;
        outcome.primary_party = context.decision.king;
        outcome.counterparty = context.decision.counterparty;
        outcome.disputed_party_a = min(
                outcome.primary_party, outcome.counterparty);
        outcome.disputed_party_b = max(
                outcome.primary_party, outcome.counterparty);
        return outcome;

    case UltimateFailureAction::check_double_rand:
    {
        assert(context.has_check_double_rand_context);
        assert(context.check_double_rand_context.valid);
        assert(context.check_double_rand_context.decision.valid);
        const auto& decision =
                context.check_double_rand_context.decision;

        if (decision.action
                == CheckDoubleRandAction::identify_corrupted_party)
        {
            outcome.valid = true;
            outcome.action =
                    FaultLocalizationAction::identify_corrupted_party;
            outcome.source =
                    FaultLocalizationSource::invalid_double_sharing_dealer;
            outcome.corrupted_party = decision.party;
            assert(decision.dealer == -1
                    || outcome.corrupted_party == decision.dealer);
            return outcome;
        }

        if (decision.action
                == CheckDoubleRandAction::dealer_recipient_disagreement)
        {
            outcome.valid = true;
            outcome.action =
                    FaultLocalizationAction::identify_disputed_pair;
            outcome.source = FaultLocalizationSource::
                    double_sharing_dealer_recipient_disagreement;
            outcome.primary_party = decision.dealer;
            outcome.counterparty = decision.recipient;
            outcome.disputed_party_a = min(
                    outcome.primary_party, outcome.counterparty);
            outcome.disputed_party_b = max(
                    outcome.primary_party, outcome.counterparty);
            return outcome;
        }
        break;
    }

    case UltimateFailureAction::none:
        break;
    }

#ifndef NDEBUG
    assert(false);
#endif
    return outcome;
}

template<class T>
typename AtlasGsz<T>::AnalyzeSharingRequest
AtlasGsz<T>::build_analyze_sharing_request(
        const UltimateFailureContext& context)
{
    assert(context.valid);
    assert(context.fault_localization.valid);
    assert(context.fault_localization.action
            == FaultLocalizationAction::needs_analyze_sharing);

    AnalyzeSharingRequest request{};

    switch (context.fault_localization.sharing_to_analyze)
    {
    case SharingToAnalyze::alpha:
        assert(context.fault_localization.source
                == FaultLocalizationSource::inconsistent_alpha);
        assert(not context.alpha_t.consistent);
        request.valid = true;
        request.target = AnalyzeSharingRequestTarget::alpha;
        request.sharing_to_analyze = SharingToAnalyze::alpha;
        request.published_sharing = context.alpha_t;
        request.published_shares = context.alpha_t.shares;
        request.source = FaultLocalizationSource::inconsistent_alpha;
        request.registered_snapshot_id =
                register_published_degree_t_snapshot(
                        context.alpha_t,
                        RegisteredSharingKind::analyze_request_snapshot);
        request.has_registered_snapshot = true;
        {
            const auto* snapshot = find_registered_sharing(
                    request.registered_snapshot_id);
            assert(snapshot != 0);
            assert(snapshot->published_shares == request.published_shares);
        }
        request.authentication_plan_record_ids =
                create_analyze_snapshot_authentication_plan(
                        request.registered_snapshot_id);
        request.has_authentication_plan = true;
        create_material_placeholders_for_auth_records(
                request.authentication_plan_record_ids);
        for (auto record_id : request.authentication_plan_record_ids)
        {
            const auto* material =
                    find_authentication_material_for_auth_record(record_id);
            assert(material != 0);
            request.authentication_material_record_ids.push_back(
                    material->id);
        }
        request.has_authentication_material = true;
        validate_analyze_sharing_request(request);
        return request;

    case SharingToAnalyze::beta:
        assert(context.fault_localization.source
                == FaultLocalizationSource::inconsistent_beta);
        assert(not context.beta_t.consistent);
        request.valid = true;
        request.target = AnalyzeSharingRequestTarget::beta;
        request.sharing_to_analyze = SharingToAnalyze::beta;
        request.published_sharing = context.beta_t;
        request.published_shares = context.beta_t.shares;
        request.source = FaultLocalizationSource::inconsistent_beta;
        request.registered_snapshot_id =
                register_published_degree_t_snapshot(
                        context.beta_t,
                        RegisteredSharingKind::analyze_request_snapshot);
        request.has_registered_snapshot = true;
        {
            const auto* snapshot = find_registered_sharing(
                    request.registered_snapshot_id);
            assert(snapshot != 0);
            assert(snapshot->published_shares == request.published_shares);
        }
        request.authentication_plan_record_ids =
                create_analyze_snapshot_authentication_plan(
                        request.registered_snapshot_id);
        request.has_authentication_plan = true;
        create_material_placeholders_for_auth_records(
                request.authentication_plan_record_ids);
        for (auto record_id : request.authentication_plan_record_ids)
        {
            const auto* material =
                    find_authentication_material_for_auth_record(record_id);
            assert(material != 0);
            request.authentication_material_record_ids.push_back(
                    material->id);
        }
        request.has_authentication_material = true;
        validate_analyze_sharing_request(request);
        return request;

    case SharingToAnalyze::none:
        break;
    }

#ifndef NDEBUG
    assert(false);
#endif
    return request;
}

template<class T>
void AtlasGsz<T>::validate_analyze_sharing_request(
        const AnalyzeSharingRequest& request) const
{
    if (not request.valid)
    {
        assert(request.target == AnalyzeSharingRequestTarget::none);
        assert(request.sharing_to_analyze == SharingToAnalyze::none);
        assert(request.source == FaultLocalizationSource::none);
        assert(not request.has_registered_snapshot);
        assert(request.registered_snapshot_id == 0);
        assert(not request.has_authentication_plan);
        assert(request.authentication_plan_record_ids.empty());
        assert(not request.has_authentication_material);
        assert(request.authentication_material_record_ids.empty());
        return;
    }

    assert(request.target == AnalyzeSharingRequestTarget::alpha
            || request.target == AnalyzeSharingRequestTarget::beta);
    assert(request.sharing_to_analyze == SharingToAnalyze::alpha
            || request.sharing_to_analyze == SharingToAnalyze::beta);
    assert(request.published_shares
            == request.published_sharing.shares);

    if (request.target == AnalyzeSharingRequestTarget::alpha)
    {
        assert(request.sharing_to_analyze == SharingToAnalyze::alpha);
        assert(request.source == FaultLocalizationSource::inconsistent_alpha);
    }
    else
    {
        assert(request.sharing_to_analyze == SharingToAnalyze::beta);
        assert(request.source == FaultLocalizationSource::inconsistent_beta);
    }

    if (request.has_registered_snapshot)
    {
        const auto* snapshot = find_registered_sharing(
                request.registered_snapshot_id);
        assert(snapshot != 0);
        assert(snapshot->kind
                == RegisteredSharingKind::analyze_request_snapshot);
        assert(snapshot->degree == RegisteredSharingDegree::degree_t);
        assert(snapshot->has_published_snapshot);
        assert(snapshot->published_shares == request.published_shares);
    }
    else
    {
        assert(request.registered_snapshot_id == 0);
    }

    if (request.has_authentication_plan)
    {
        assert(request.has_registered_snapshot);
        assert(not request.authentication_plan_record_ids.empty());
        for (auto record_id : request.authentication_plan_record_ids)
        {
            const auto* record = find_authentication_plan_record(record_id);
            assert(record != 0);
            assert(record->sharing_id == request.registered_snapshot_id);
            assert(record->checkpoint_id == 0);
            assert(record->kind
                    == AuthenticationRecordKind::
                        analyze_request_snapshot);
            assert(record->status == AuthenticationPlanStatus::planned);
            assert(is_active_party(record->verifier));
            assert(is_active_party(record->holder));
            assert(record->verifier != record->holder);
        }
    }
    else
    {
        assert(request.authentication_plan_record_ids.empty());
    }

    if (request.has_authentication_material)
    {
        assert(request.has_authentication_plan);
        assert(request.authentication_material_record_ids.size()
                == request.authentication_plan_record_ids.size());
        for (auto material_id : request.authentication_material_record_ids)
        {
            const auto* material =
                    find_authentication_material_record(material_id);
            assert(material != 0);
            assert(material->sharing_id == request.registered_snapshot_id);
            assert(material->checkpoint_id == 0);
            assert(material->kind
                    == AuthenticationRecordKind::
                        analyze_request_snapshot);
            assert(material->status
                    == AuthenticationMaterialStatus::placeholder
                    || material->status
                        == AuthenticationMaterialStatus::
                            verifier_key_assigned
                    || material->status
                        == AuthenticationMaterialStatus::
                            holder_tag_assigned
                    || material->status
                        == AuthenticationMaterialStatus::complete);
            if (material->status == AuthenticationMaterialStatus::complete
                    && holder_share_available_for_material(*material))
            {
                auto equation =
                        check_authentication_equation(material->id);
                assert(equation.valid);
                assert(equation.status == AuthenticationEquationStatus::pass
                        || equation.status
                            == AuthenticationEquationStatus::fail);
            }
            assert(is_active_party(material->verifier));
            assert(is_active_party(material->holder));
            assert(material->verifier != material->holder);
            assert(std::find(
                    request.authentication_plan_record_ids.begin(),
                    request.authentication_plan_record_ids.end(),
                    material->auth_record_id)
                    != request.authentication_plan_record_ids.end());
        }
    }
    else
    {
        assert(request.authentication_material_record_ids.empty());
    }
}

template<class T>
void AtlasGsz<T>::ensure_verifiable_registry_initialized()
{
    if (not verifiable_registry.initialized)
    {
        verifiable_registry.next_sharing_id = 1;
        verifiable_registry.next_checkpoint_id = 1;
        verifiable_registry.current_segment_id = 0;
        verifiable_registry.sharings.clear();
        verifiable_registry.checkpoints.clear();
        verifiable_registry.initialized = true;
    }

    assert(verifiable_registry.next_sharing_id > 0);
    assert(verifiable_registry.next_checkpoint_id > 0);
}

template<class T>
uint64_t AtlasGsz<T>::register_verifiable_sharing(
        const T& local_share,
        RegisteredSharingDegree degree,
        RegisteredSharingKind kind)
{
    ensure_verifiable_registry_initialized();
    assert(degree != RegisteredSharingDegree::none);
    assert(kind != RegisteredSharingKind::none);

    RegisteredVerifiableSharing record{};
    record.valid = true;
    record.id = verifiable_registry.next_sharing_id++;
    assert(verifiable_registry.next_sharing_id > 0);
    record.degree = degree;
    record.kind = kind;
    record.status = VerifiableSharingStatus::registered;
    record.local_share = local_share;
    record.segment_id = verifiable_registry.current_segment_id;

    verifiable_registry.sharings.push_back(record);
    validate_verifiable_registry();
    return record.id;
}

template<class T>
uint64_t AtlasGsz<T>::register_published_degree_t_snapshot(
        const PublishedDegreeTSharing& published,
        RegisteredSharingKind kind)
{
    ensure_verifiable_registry_initialized();
    assert(kind != RegisteredSharingKind::none);
    assert(published.shares.size() == size_t(P.num_players()));

    RegisteredVerifiableSharing record{};
    record.valid = true;
    record.id = verifiable_registry.next_sharing_id++;
    assert(verifiable_registry.next_sharing_id > 0);
    record.degree = RegisteredSharingDegree::degree_t;
    record.kind = kind;
    record.status = VerifiableSharingStatus::analysis_pending;
    record.local_share = T{};
    record.has_published_snapshot = true;
    record.published_shares = published.shares;
    record.segment_id = verifiable_registry.current_segment_id;

    verifiable_registry.sharings.push_back(record);
    validate_verifiable_registry();
    return record.id;
}

template<class T>
typename AtlasGsz<T>::RegisteredVerifiableSharing*
AtlasGsz<T>::find_registered_sharing(uint64_t id)
{
    for (auto& sharing : verifiable_registry.sharings)
        if (sharing.id == id)
            return &sharing;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::RegisteredVerifiableSharing*
AtlasGsz<T>::find_registered_sharing(uint64_t id) const
{
    for (const auto& sharing : verifiable_registry.sharings)
        if (sharing.id == id)
            return &sharing;
    return 0;
}

template<class T>
uint64_t AtlasGsz<T>::create_checkpoint_record(
        const vector<uint64_t>& sharing_ids)
{
    ensure_verifiable_registry_initialized();
    for (auto id : sharing_ids)
        assert(find_registered_sharing(id) != 0);

    CheckpointRecord checkpoint{};
    checkpoint.valid = true;
    checkpoint.checkpoint_id = verifiable_registry.next_checkpoint_id++;
    assert(verifiable_registry.next_checkpoint_id > 0);
    checkpoint.segment_id = verifiable_registry.current_segment_id;
    checkpoint.sharing_ids = sharing_ids;

    for (auto id : sharing_ids)
    {
        auto* sharing = find_registered_sharing(id);
        assert(sharing != 0);
        sharing->checkpoint_id = checkpoint.checkpoint_id;
    }

    verifiable_registry.checkpoints.push_back(checkpoint);
    validate_verifiable_registry();
    return checkpoint.checkpoint_id;
}

template<class T>
void AtlasGsz<T>::mark_checkpoint_sealed(uint64_t checkpoint_id)
{
    ensure_verifiable_registry_initialized();
    bool found = false;
    for (auto& checkpoint : verifiable_registry.checkpoints)
        if (checkpoint.checkpoint_id == checkpoint_id)
        {
            checkpoint.sealed = true;
            found = true;
            break;
        }
    if (not found)
    {
#ifndef NDEBUG
        assert(false);
#endif
        return;
    }
    validate_verifiable_registry();
}

template<class T>
void AtlasGsz<T>::mark_checkpoint_authentication_requested(
        uint64_t checkpoint_id)
{
    ensure_verifiable_registry_initialized();
    bool found = false;
    for (auto& checkpoint : verifiable_registry.checkpoints)
        if (checkpoint.checkpoint_id == checkpoint_id)
        {
            checkpoint.authentication_requested = true;
            found = true;
            break;
        }
    if (not found)
    {
#ifndef NDEBUG
        assert(false);
#endif
        return;
    }
    validate_verifiable_registry();
}

template<class T>
void AtlasGsz<T>::mark_checkpoint_authenticated(uint64_t checkpoint_id)
{
    ensure_verifiable_registry_initialized();
    bool found = false;
    for (auto& checkpoint : verifiable_registry.checkpoints)
        if (checkpoint.checkpoint_id == checkpoint_id)
        {
            checkpoint.authenticated = true;
            found = true;
            break;
        }
    if (not found)
    {
#ifndef NDEBUG
        assert(false);
#endif
        return;
    }
    validate_verifiable_registry();
}

template<class T>
void AtlasGsz<T>::validate_verifiable_registry() const
{
    if (not verifiable_registry.initialized)
        return;

    assert(verifiable_registry.next_sharing_id > 0);
    assert(verifiable_registry.next_checkpoint_id > 0);

    for (size_t i = 0; i < verifiable_registry.sharings.size(); i++)
    {
        const auto& sharing = verifiable_registry.sharings.at(i);
        assert(sharing.valid);
        assert(sharing.id != 0);
        assert(sharing.degree != RegisteredSharingDegree::none);
        assert(sharing.kind != RegisteredSharingKind::none);
        assert(sharing.status != VerifiableSharingStatus::none);
        if (sharing.has_published_snapshot)
            assert(sharing.published_shares.size()
                    == size_t(P.num_players()));

        for (size_t j = i + 1; j < verifiable_registry.sharings.size(); j++)
            assert(sharing.id != verifiable_registry.sharings.at(j).id);
    }

    for (size_t i = 0; i < verifiable_registry.checkpoints.size(); i++)
    {
        const auto& checkpoint = verifiable_registry.checkpoints.at(i);
        assert(checkpoint.valid);
        assert(checkpoint.checkpoint_id != 0);

        for (size_t j = i + 1; j < verifiable_registry.checkpoints.size();
                j++)
            assert(checkpoint.checkpoint_id
                    != verifiable_registry.checkpoints.at(j).checkpoint_id);

        for (auto sharing_id : checkpoint.sharing_ids)
            assert(find_registered_sharing(sharing_id) != 0);
    }
}

template<class T>
void AtlasGsz<T>::ensure_segment_lifecycle_initialized()
{
    ensure_verifiable_registry_initialized();

    if (not segment_lifecycle.initialized)
    {
        segment_lifecycle.current_segment_id =
                verifiable_registry.current_segment_id;
        segment_lifecycle.last_completed_segment_id = 0;
        segment_lifecycle.segment_open = false;
        segment_lifecycle.checkpoint_open = false;
        segment_lifecycle.current_input_checkpoint_id = 0;
        segment_lifecycle.current_output_checkpoint_id = 0;
        segment_lifecycle.current_segment_input_sharings.clear();
        segment_lifecycle.current_segment_output_sharings.clear();
        segment_lifecycle.initialized = true;
    }

    assert(verifiable_registry.initialized);
    assert(verifiable_registry.current_segment_id
            == segment_lifecycle.current_segment_id);
}

template<class T>
void AtlasGsz<T>::validate_segment_lifecycle() const
{
    if (not segment_lifecycle.initialized)
        return;

    assert(verifiable_registry.initialized);
    assert(verifiable_registry.current_segment_id
            == segment_lifecycle.current_segment_id);

    if (not segment_lifecycle.segment_open)
        assert(not segment_lifecycle.checkpoint_open);

    auto find_checkpoint = [&](uint64_t checkpoint_id)
        -> const CheckpointRecord*
    {
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == checkpoint_id)
                return &checkpoint;
        return 0;
    };

    if (segment_lifecycle.current_input_checkpoint_id != 0)
    {
        const auto* checkpoint = find_checkpoint(
                segment_lifecycle.current_input_checkpoint_id);
        assert(checkpoint != 0);
        if (segment_lifecycle.segment_open)
            assert(checkpoint->segment_id
                    == segment_lifecycle.current_segment_id);
    }

    if (segment_lifecycle.current_output_checkpoint_id != 0)
    {
        const auto* checkpoint = find_checkpoint(
                segment_lifecycle.current_output_checkpoint_id);
        assert(checkpoint != 0);
        if (segment_lifecycle.segment_open)
            assert(checkpoint->segment_id
                    == segment_lifecycle.current_segment_id);
    }

    for (auto sharing_id :
            segment_lifecycle.current_segment_input_sharings)
    {
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_input);
        if (segment_lifecycle.segment_open)
            assert(sharing->segment_id
                    == segment_lifecycle.current_segment_id);
    }

    for (auto sharing_id :
            segment_lifecycle.current_segment_output_sharings)
    {
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        if (segment_lifecycle.segment_open)
            assert(sharing->segment_id
                    == segment_lifecycle.current_segment_id);
    }
}

template<class T>
uint64_t AtlasGsz<T>::begin_segment()
{
    ensure_segment_lifecycle_initialized();
    assert(not segment_lifecycle.segment_open);

    uint64_t next_segment_id = std::max(
            segment_lifecycle.current_segment_id,
            segment_lifecycle.last_completed_segment_id) + 1;
    assert(next_segment_id != 0);

    segment_lifecycle.current_segment_id = next_segment_id;
    verifiable_registry.current_segment_id = next_segment_id;
    segment_lifecycle.current_segment_input_sharings.clear();
    segment_lifecycle.current_segment_output_sharings.clear();
    segment_lifecycle.current_input_checkpoint_id = 0;
    segment_lifecycle.current_output_checkpoint_id = 0;
    segment_lifecycle.segment_open = true;
    segment_lifecycle.checkpoint_open = false;

    validate_verifiable_registry();
    validate_segment_lifecycle();
    return next_segment_id;
}

template<class T>
uint64_t AtlasGsz<T>::current_segment_id() const
{
    if (not segment_lifecycle.initialized)
        return 0;
    return segment_lifecycle.current_segment_id;
}

template<class T>
uint64_t AtlasGsz<T>::register_segment_input_sharing(
        const T& local_share)
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);

    uint64_t id = register_verifiable_sharing(
            local_share,
            RegisteredSharingDegree::degree_t,
            RegisteredSharingKind::checkpoint_input);
    segment_lifecycle.current_segment_input_sharings.push_back(id);
    validate_segment_lifecycle();
    return id;
}

template<class T>
uint64_t AtlasGsz<T>::register_segment_output_sharing(
        const T& local_share)
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);

    uint64_t id = register_verifiable_sharing(
            local_share,
            RegisteredSharingDegree::degree_t,
            RegisteredSharingKind::checkpoint_output);
    segment_lifecycle.current_segment_output_sharings.push_back(id);
    validate_segment_lifecycle();
    return id;
}

template<class T>
uint64_t AtlasGsz<T>::create_input_checkpoint_for_current_segment()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);
    assert(not segment_lifecycle.current_segment_input_sharings.empty());
    assert(segment_lifecycle.current_input_checkpoint_id == 0);

    uint64_t checkpoint_id = create_checkpoint_record(
            segment_lifecycle.current_segment_input_sharings);
    segment_lifecycle.current_input_checkpoint_id = checkpoint_id;
    validate_segment_lifecycle();
    return checkpoint_id;
}

template<class T>
uint64_t AtlasGsz<T>::create_output_checkpoint_for_current_segment()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);
    assert(not segment_lifecycle.current_segment_output_sharings.empty());
    assert(segment_lifecycle.current_output_checkpoint_id == 0);

    uint64_t checkpoint_id = create_checkpoint_record(
            segment_lifecycle.current_segment_output_sharings);
    segment_lifecycle.current_output_checkpoint_id = checkpoint_id;
    segment_lifecycle.checkpoint_open = true;
    validate_segment_lifecycle();
    return checkpoint_id;
}

template<class T>
void AtlasGsz<T>::seal_current_output_checkpoint()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);
    assert(segment_lifecycle.current_output_checkpoint_id != 0);

    mark_checkpoint_sealed(segment_lifecycle.current_output_checkpoint_id);
    segment_lifecycle.checkpoint_open = false;
    validate_segment_lifecycle();
}

template<class T>
void AtlasGsz<T>::mark_current_output_checkpoint_authentication_requested()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);
    assert(segment_lifecycle.current_output_checkpoint_id != 0);

    auto record_ids = authentication_records_for_checkpoint(
            segment_lifecycle.current_output_checkpoint_id);
    if (record_ids.empty())
        record_ids = create_checkpoint_authentication_plan(
                segment_lifecycle.current_output_checkpoint_id);
    assert(not record_ids.empty());
    create_material_placeholders_for_auth_records(record_ids);

    for (auto record_id : record_ids)
        mark_authentication_record_requested(record_id);

    mark_checkpoint_authentication_requested(
            segment_lifecycle.current_output_checkpoint_id);
    validate_authentication_material();
    validate_authentication_plan();
    validate_segment_lifecycle();
}

template<class T>
void AtlasGsz<T>::mark_current_output_checkpoint_authenticated()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);
    assert(segment_lifecycle.current_output_checkpoint_id != 0);

    auto record_ids = authentication_records_for_checkpoint(
            segment_lifecycle.current_output_checkpoint_id);
    if (record_ids.empty())
        record_ids = create_checkpoint_authentication_plan(
                segment_lifecycle.current_output_checkpoint_id);
    assert(not record_ids.empty());
    create_material_placeholders_for_auth_records(record_ids);

    for (auto record_id : record_ids)
        mark_authentication_record_authenticated(record_id);
    assert(checkpoint_authentication_plan_complete(
            segment_lifecycle.current_output_checkpoint_id));

    mark_checkpoint_authenticated(
            segment_lifecycle.current_output_checkpoint_id);
    validate_authentication_material();
    validate_authentication_plan();
    validate_segment_lifecycle();
}

template<class T>
void AtlasGsz<T>::complete_current_segment_successfully()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);

    if (segment_lifecycle.current_output_checkpoint_id != 0)
    {
        bool sealed = false;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id
                    == segment_lifecycle.current_output_checkpoint_id)
            {
                sealed = checkpoint.sealed;
                break;
            }
        assert(sealed);
    }

    segment_lifecycle.last_completed_segment_id =
            segment_lifecycle.current_segment_id;
    segment_lifecycle.segment_open = false;
    segment_lifecycle.checkpoint_open = false;

    validate_verifiable_registry();
    validate_segment_lifecycle();
}

template<class T>
void AtlasGsz<T>::abandon_current_segment_after_failure()
{
    ensure_segment_lifecycle_initialized();
    assert(segment_lifecycle.segment_open);

    // Skeleton only: retain all registered metadata and do not roll back
    // shares, Corr/Disp, or protocol state.
    segment_lifecycle.segment_open = false;
    segment_lifecycle.checkpoint_open = false;

    validate_verifiable_registry();
    validate_segment_lifecycle();
}

template<class T>
void AtlasGsz<T>::ensure_authentication_plan_initialized()
{
    ensure_verifiable_registry_initialized();

    if (not authentication_plan_state.initialized)
    {
        authentication_plan_state.next_auth_record_id = 1;
        authentication_plan_state.records.clear();
        authentication_plan_state.initialized = true;
    }

    assert(authentication_plan_state.next_auth_record_id > 0);
}

template<class T>
void AtlasGsz<T>::validate_authentication_plan() const
{
    if (not authentication_plan_state.initialized)
        return;

    assert(verifiable_registry.initialized);
    assert(authentication_plan_state.next_auth_record_id > 0);

    auto checkpoint_exists = [&](uint64_t checkpoint_id)
    {
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == checkpoint_id)
                return true;
        return false;
    };

    auto checkpoint_contains_sharing = [&](uint64_t checkpoint_id,
            uint64_t sharing_id)
    {
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == checkpoint_id)
                return std::find(
                        checkpoint.sharing_ids.begin(),
                        checkpoint.sharing_ids.end(),
                        sharing_id) != checkpoint.sharing_ids.end();
        return false;
    };

    for (size_t i = 0; i < authentication_plan_state.records.size(); i++)
    {
        const auto& record = authentication_plan_state.records.at(i);
        assert(record.valid);
        assert(record.id != 0);
        assert(record.sharing_id != 0);
        assert(find_registered_sharing(record.sharing_id) != 0);
        if (record.checkpoint_id != 0)
        {
            assert(checkpoint_exists(record.checkpoint_id));
            assert(checkpoint_contains_sharing(
                    record.checkpoint_id, record.sharing_id));
        }
        assert(0 <= record.verifier);
        assert(record.verifier < P.num_players());
        assert(0 <= record.holder);
        assert(record.holder < P.num_players());
        assert(record.verifier != record.holder);
        assert(record.kind != AuthenticationRecordKind::none);
        assert(record.status != AuthenticationPlanStatus::none);

        for (size_t j = i + 1;
                j < authentication_plan_state.records.size(); j++)
        {
            const auto& other = authentication_plan_state.records.at(j);
            assert(record.id != other.id);
            assert(not (record.sharing_id == other.sharing_id
                    && record.checkpoint_id == other.checkpoint_id
                    && record.verifier == other.verifier
                    && record.holder == other.holder
                    && record.kind == other.kind));
        }
    }
}

template<class T>
uint64_t AtlasGsz<T>::create_authentication_plan_record(
        uint64_t sharing_id,
        uint64_t checkpoint_id,
        int verifier,
        int holder,
        AuthenticationRecordKind kind)
{
    ensure_authentication_plan_initialized();
    assert(sharing_id != 0);
    const auto* sharing = find_registered_sharing(sharing_id);
    assert(sharing != 0);
    assert(0 <= verifier);
    assert(verifier < P.num_players());
    assert(0 <= holder);
    assert(holder < P.num_players());
    assert(verifier != holder);
    assert(kind != AuthenticationRecordKind::none);

    if (checkpoint_id != 0)
    {
        bool found_checkpoint = false;
        bool contains_sharing = false;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == checkpoint_id)
            {
                found_checkpoint = true;
                contains_sharing = std::find(
                        checkpoint.sharing_ids.begin(),
                        checkpoint.sharing_ids.end(),
                        sharing_id) != checkpoint.sharing_ids.end();
                break;
            }
        assert(found_checkpoint);
        assert(contains_sharing);
    }

    for (const auto& record : authentication_plan_state.records)
        if (record.sharing_id == sharing_id
                && record.checkpoint_id == checkpoint_id
                && record.verifier == verifier
                && record.holder == holder
                && record.kind == kind)
            return record.id;

    AuthenticationPlanRecord record{};
    record.valid = true;
    record.id = authentication_plan_state.next_auth_record_id++;
    assert(authentication_plan_state.next_auth_record_id > 0);
    record.sharing_id = sharing_id;
    record.checkpoint_id = checkpoint_id;
    record.segment_id = sharing->segment_id;
    record.verifier = verifier;
    record.holder = holder;
    record.kind = kind;
    record.status = AuthenticationPlanStatus::planned;

    authentication_plan_state.records.push_back(record);
    validate_authentication_plan();
    return record.id;
}

template<class T>
vector<uint64_t> AtlasGsz<T>::create_checkpoint_authentication_plan(
        uint64_t checkpoint_id)
{
    ensure_authentication_plan_initialized();
    assert(checkpoint_id != 0);

    const CheckpointRecord* checkpoint = 0;
    for (const auto& candidate : verifiable_registry.checkpoints)
        if (candidate.checkpoint_id == checkpoint_id)
        {
            checkpoint = &candidate;
            break;
        }
    assert(checkpoint != 0);

    auto active = active_parties();
    vector<uint64_t> record_ids;
    for (auto sharing_id : checkpoint->sharing_ids)
    {
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        for (auto verifier : active)
            for (auto holder : active)
            {
                if (verifier == holder)
                    continue;
                record_ids.push_back(create_authentication_plan_record(
                        sharing_id,
                        checkpoint_id,
                        verifier,
                        holder,
                        AuthenticationRecordKind::checkpoint_output_share));
            }
    }

    validate_authentication_plan();
    return record_ids;
}

template<class T>
typename AtlasGsz<T>::AuthenticationPlanRecord*
AtlasGsz<T>::find_authentication_plan_record(uint64_t id)
{
    for (auto& record : authentication_plan_state.records)
        if (record.id == id)
            return &record;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::AuthenticationPlanRecord*
AtlasGsz<T>::find_authentication_plan_record(uint64_t id) const
{
    for (const auto& record : authentication_plan_state.records)
        if (record.id == id)
            return &record;
    return 0;
}

template<class T>
vector<uint64_t> AtlasGsz<T>::authentication_records_for_checkpoint(
        uint64_t checkpoint_id) const
{
    vector<uint64_t> res;
    if (not authentication_plan_state.initialized)
        return res;

    for (const auto& record : authentication_plan_state.records)
        if (record.checkpoint_id == checkpoint_id)
            res.push_back(record.id);
    return res;
}

template<class T>
vector<uint64_t> AtlasGsz<T>::authentication_records_for_sharing(
        uint64_t sharing_id) const
{
    vector<uint64_t> res;
    if (not authentication_plan_state.initialized)
        return res;

    for (const auto& record : authentication_plan_state.records)
        if (record.sharing_id == sharing_id)
            res.push_back(record.id);
    return res;
}

template<class T>
void AtlasGsz<T>::mark_authentication_record_requested(uint64_t id)
{
    ensure_authentication_plan_initialized();
    auto* record = find_authentication_plan_record(id);
    assert(record != 0);
    record->status = AuthenticationPlanStatus::requested;
    validate_authentication_plan();
}

template<class T>
void AtlasGsz<T>::mark_authentication_record_authenticated(uint64_t id)
{
    ensure_authentication_plan_initialized();
    auto* record = find_authentication_plan_record(id);
    assert(record != 0);
    record->status = AuthenticationPlanStatus::authenticated;
    validate_authentication_plan();
}

template<class T>
bool AtlasGsz<T>::checkpoint_authentication_plan_complete(
        uint64_t checkpoint_id) const
{
    auto record_ids = authentication_records_for_checkpoint(checkpoint_id);
    if (record_ids.empty())
        return false;

    for (auto record_id : record_ids)
    {
        const auto* record = find_authentication_plan_record(record_id);
        assert(record != 0);
        if (record->status != AuthenticationPlanStatus::authenticated)
            return false;
    }
    return true;
}

template<class T>
vector<uint64_t> AtlasGsz<T>::create_analyze_snapshot_authentication_plan(
        uint64_t registered_snapshot_id)
{
    ensure_authentication_plan_initialized();
    const auto* sharing = find_registered_sharing(registered_snapshot_id);
    assert(sharing != 0);
    assert(sharing->kind == RegisteredSharingKind::analyze_request_snapshot);
    assert(sharing->degree == RegisteredSharingDegree::degree_t);

    auto active = active_parties();
    vector<uint64_t> record_ids;
    for (auto verifier : active)
        for (auto holder : active)
        {
            if (verifier == holder)
                continue;
            record_ids.push_back(create_authentication_plan_record(
                    registered_snapshot_id,
                    0,
                    verifier,
                    holder,
                    AuthenticationRecordKind::analyze_request_snapshot));
        }

    validate_authentication_plan();
    return record_ids;
}

template<class T>
void AtlasGsz<T>::ensure_authentication_material_initialized()
{
    ensure_authentication_plan_initialized();

    if (not authentication_material_state.initialized)
    {
        authentication_material_state.next_material_id = 1;
        authentication_material_state.records.clear();
        authentication_material_state.initialized = true;
    }

    assert(authentication_material_state.next_material_id > 0);
}

template<class T>
void AtlasGsz<T>::validate_authentication_material() const
{
    if (not authentication_material_state.initialized)
        return;

    assert(authentication_plan_state.initialized);
    assert(authentication_material_state.next_material_id > 0);

    for (size_t i = 0; i < authentication_material_state.records.size(); i++)
    {
        const auto& material =
                authentication_material_state.records.at(i);
        assert(material.valid);
        assert(material.id != 0);
        assert(material.auth_record_id != 0);

        const auto* plan_record = find_authentication_plan_record(
                material.auth_record_id);
        assert(plan_record != 0);
        assert(material.sharing_id == plan_record->sharing_id);
        assert(material.checkpoint_id == plan_record->checkpoint_id);
        assert(material.segment_id == plan_record->segment_id);
        assert(material.verifier == plan_record->verifier);
        assert(material.holder == plan_record->holder);
        assert(material.kind == plan_record->kind);
        assert(0 <= material.verifier);
        assert(material.verifier < P.num_players());
        assert(0 <= material.holder);
        assert(material.holder < P.num_players());
        assert(material.verifier != material.holder);
        assert(material.kind != AuthenticationRecordKind::none);
        assert(material.status != AuthenticationMaterialStatus::none);

        if (material.status
                == AuthenticationMaterialStatus::verifier_key_assigned)
            assert(material.has_verifier_key);
        if (material.status
                == AuthenticationMaterialStatus::holder_tag_assigned)
            assert(material.has_holder_tag);
        if (material.status == AuthenticationMaterialStatus::complete)
        {
            assert(material.has_verifier_key);
            assert(material.has_holder_tag);
        }

        auto equation = check_authentication_equation(material.id);
        assert(equation.valid);
        auto vote = authentication_vote_from_material(material.id);
        validate_authentication_vote(vote);
        if (material.status == AuthenticationMaterialStatus::complete)
        {
            if (holder_share_available_for_material(material))
                assert(equation.status == AuthenticationEquationStatus::pass
                        || equation.status
                            == AuthenticationEquationStatus::fail);
            else
                assert(equation.status
                        == AuthenticationEquationStatus::
                            holder_share_unavailable);
        }
        else
        {
            assert(equation.status == AuthenticationEquationStatus::not_ready);
        }

        for (size_t j = i + 1;
                j < authentication_material_state.records.size(); j++)
        {
            const auto& other =
                    authentication_material_state.records.at(j);
            assert(material.id != other.id);
            assert(material.auth_record_id != other.auth_record_id);
        }
    }

    vector<uint64_t> sharing_ids;
    for (const auto& material : authentication_material_state.records)
        if (std::find(sharing_ids.begin(), sharing_ids.end(),
                material.sharing_id) == sharing_ids.end())
            sharing_ids.push_back(material.sharing_id);

    for (auto sharing_id : sharing_ids)
    {
        auto sharing_decision =
                authentication_sharing_decision(sharing_id);
        validate_authentication_sharing_decision(sharing_decision);

        auto decisions =
                authentication_holder_decisions_for_sharing(sharing_id);
        for (const auto& decision : decisions)
            validate_authentication_holder_decision(decision);
    }

    vector<uint64_t> checkpoint_ids;
    for (const auto& material : authentication_material_state.records)
        if (material.checkpoint_id != 0
                && std::find(checkpoint_ids.begin(), checkpoint_ids.end(),
                    material.checkpoint_id) == checkpoint_ids.end())
            checkpoint_ids.push_back(material.checkpoint_id);

    for (auto checkpoint_id : checkpoint_ids)
    {
        auto checkpoint_decision =
                authentication_checkpoint_decision(checkpoint_id);
        validate_authentication_checkpoint_decision(checkpoint_decision);
    }
}

template<class T>
uint64_t AtlasGsz<T>::create_authentication_material_placeholder(
        uint64_t auth_record_id)
{
    ensure_authentication_material_initialized();
    assert(auth_record_id != 0);
    const auto* plan_record =
            find_authentication_plan_record(auth_record_id);
    assert(plan_record != 0);

    if (const auto* existing =
            find_authentication_material_for_auth_record(auth_record_id))
        return existing->id;

    AuthenticationMaterialRecord material{};
    material.valid = true;
    material.id = authentication_material_state.next_material_id++;
    assert(authentication_material_state.next_material_id > 0);
    material.auth_record_id = auth_record_id;
    material.sharing_id = plan_record->sharing_id;
    material.checkpoint_id = plan_record->checkpoint_id;
    material.segment_id = plan_record->segment_id;
    material.verifier = plan_record->verifier;
    material.holder = plan_record->holder;
    material.kind = plan_record->kind;
    material.status = AuthenticationMaterialStatus::placeholder;

    authentication_material_state.records.push_back(material);
    validate_authentication_material();
    return material.id;
}

template<class T>
typename AtlasGsz<T>::AuthenticationMaterialRecord*
AtlasGsz<T>::find_authentication_material_record(uint64_t id)
{
    for (auto& material : authentication_material_state.records)
        if (material.id == id)
            return &material;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::AuthenticationMaterialRecord*
AtlasGsz<T>::find_authentication_material_record(uint64_t id) const
{
    for (const auto& material : authentication_material_state.records)
        if (material.id == id)
            return &material;
    return 0;
}

template<class T>
typename AtlasGsz<T>::AuthenticationMaterialRecord*
AtlasGsz<T>::find_authentication_material_for_auth_record(
        uint64_t auth_record_id)
{
    for (auto& material : authentication_material_state.records)
        if (material.auth_record_id == auth_record_id)
            return &material;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::AuthenticationMaterialRecord*
AtlasGsz<T>::find_authentication_material_for_auth_record(
        uint64_t auth_record_id) const
{
    for (const auto& material : authentication_material_state.records)
        if (material.auth_record_id == auth_record_id)
            return &material;
    return 0;
}

template<class T>
vector<uint64_t> AtlasGsz<T>::authentication_material_for_checkpoint(
        uint64_t checkpoint_id) const
{
    vector<uint64_t> res;
    if (not authentication_material_state.initialized)
        return res;

    for (const auto& material : authentication_material_state.records)
        if (material.checkpoint_id == checkpoint_id)
            res.push_back(material.id);
    return res;
}

template<class T>
vector<uint64_t> AtlasGsz<T>::authentication_material_for_sharing(
        uint64_t sharing_id) const
{
    vector<uint64_t> res;
    if (not authentication_material_state.initialized)
        return res;

    for (const auto& material : authentication_material_state.records)
        if (material.sharing_id == sharing_id)
            res.push_back(material.id);
    return res;
}

template<class T>
void AtlasGsz<T>::assign_authentication_verifier_key_placeholder(
        uint64_t material_id,
        const typename T::open_type& mu,
        const typename T::open_type& nu)
{
    ensure_authentication_material_initialized();
    auto* material = find_authentication_material_record(material_id);
    assert(material != 0);
    material->has_verifier_key = true;
    material->verifier_key_mu = mu;
    material->verifier_key_nu = nu;
    material->status = material->has_holder_tag
            ? AuthenticationMaterialStatus::complete
            : AuthenticationMaterialStatus::verifier_key_assigned;
    validate_authentication_material();
}

template<class T>
void AtlasGsz<T>::assign_authentication_holder_tag_placeholder(
        uint64_t material_id,
        const typename T::open_type& tag)
{
    ensure_authentication_material_initialized();
    auto* material = find_authentication_material_record(material_id);
    assert(material != 0);
    material->has_holder_tag = true;
    material->holder_tag = tag;
    material->status = material->has_verifier_key
            ? AuthenticationMaterialStatus::complete
            : AuthenticationMaterialStatus::holder_tag_assigned;
    validate_authentication_material();
}

template<class T>
bool AtlasGsz<T>::authentication_material_complete(
        uint64_t material_id) const
{
    const auto* material = find_authentication_material_record(material_id);
    assert(material != 0);
    return material != 0
            && material->status == AuthenticationMaterialStatus::complete
            && material->has_verifier_key
            && material->has_holder_tag;
}

template<class T>
void AtlasGsz<T>::create_material_placeholders_for_auth_records(
        const vector<uint64_t>& auth_record_ids)
{
    for (auto auth_record_id : auth_record_ids)
        create_authentication_material_placeholder(auth_record_id);
    validate_authentication_material();
}

template<class T>
bool AtlasGsz<T>::holder_share_available_for_material(
        const AuthenticationMaterialRecord& material) const
{
    const auto* sharing = find_registered_sharing(material.sharing_id);
    assert(sharing != 0);
    assert(0 <= material.holder);
    assert(material.holder < P.num_players());

    if (sharing->has_published_snapshot)
    {
        assert(sharing->published_shares.size()
                == size_t(P.num_players()));
        return true;
    }

    return material.holder == P.my_num();
}

template<class T>
typename T::open_type AtlasGsz<T>::holder_share_for_material(
        const AuthenticationMaterialRecord& material) const
{
    assert(holder_share_available_for_material(material));
    const auto* sharing = find_registered_sharing(material.sharing_id);
    assert(sharing != 0);

    if (sharing->has_published_snapshot)
        return sharing->published_shares.at(material.holder);

    typename T::open_type share = sharing->local_share;
    return share;
}

template<class T>
typename AtlasGsz<T>::AuthenticationEquationResult
AtlasGsz<T>::check_authentication_equation(uint64_t material_id) const
{
    AuthenticationEquationResult result{};
    const auto* material = find_authentication_material_record(material_id);
    assert(material != 0);
    if (material == 0)
        return result;

    result.valid = true;
    result.material_id = material->id;
    result.auth_record_id = material->auth_record_id;
    result.sharing_id = material->sharing_id;
    result.verifier = material->verifier;
    result.holder = material->holder;

    bool complete = material->status == AuthenticationMaterialStatus::complete
            && material->has_verifier_key
            && material->has_holder_tag;
    if (not complete)
    {
        result.status = AuthenticationEquationStatus::not_ready;
        return result;
    }

    if (not holder_share_available_for_material(*material))
    {
        result.status =
                AuthenticationEquationStatus::holder_share_unavailable;
        return result;
    }

    result.has_holder_share = true;
    result.holder_share = holder_share_for_material(*material);
    result.has_expected_tag = true;
    result.expected_tag =
            material->verifier_key_mu * result.holder_share
            + material->verifier_key_nu;
    result.has_actual_tag = true;
    result.actual_tag = material->holder_tag;
    result.status = result.actual_tag == result.expected_tag
            ? AuthenticationEquationStatus::pass
            : AuthenticationEquationStatus::fail;
    return result;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationEquationResult>
AtlasGsz<T>::check_authentication_equations_for_checkpoint(
        uint64_t checkpoint_id) const
{
    vector<AuthenticationEquationResult> res;
    for (auto material_id :
            authentication_material_for_checkpoint(checkpoint_id))
        res.push_back(check_authentication_equation(material_id));
    return res;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationEquationResult>
AtlasGsz<T>::check_authentication_equations_for_sharing(
        uint64_t sharing_id) const
{
    vector<AuthenticationEquationResult> res;
    for (auto material_id :
            authentication_material_for_sharing(sharing_id))
        res.push_back(check_authentication_equation(material_id));
    return res;
}

template<class T>
bool AtlasGsz<T>::authentication_equation_passes(
        uint64_t material_id) const
{
    auto result = check_authentication_equation(material_id);
    return result.valid
            && result.status == AuthenticationEquationStatus::pass;
}

template<class T>
bool AtlasGsz<T>::all_available_authentication_equations_pass(
        const vector<uint64_t>& material_ids) const
{
    for (auto material_id : material_ids)
    {
        auto result = check_authentication_equation(material_id);
        assert(result.valid);
        if (result.status == AuthenticationEquationStatus::fail)
            return false;
    }
    return true;
}

template<class T>
typename AtlasGsz<T>::AuthenticationVerifierVote
AtlasGsz<T>::authentication_vote_from_material(
        uint64_t material_id) const
{
    AuthenticationVerifierVote vote{};
    const auto* material = find_authentication_material_record(material_id);
    assert(material != 0);
    if (material == 0)
        return vote;

    auto equation = check_authentication_equation(material_id);
    assert(equation.valid);

    vote.valid = true;
    vote.material_id = material->id;
    vote.auth_record_id = material->auth_record_id;
    vote.sharing_id = material->sharing_id;
    vote.checkpoint_id = material->checkpoint_id;
    vote.segment_id = material->segment_id;
    vote.verifier = material->verifier;
    vote.holder = material->holder;
    vote.kind = material->kind;
    vote.equation_status = equation.status;

    switch (equation.status)
    {
    case AuthenticationEquationStatus::not_ready:
        vote.status = AuthenticationVerifierVoteStatus::not_ready;
        break;
    case AuthenticationEquationStatus::holder_share_unavailable:
        vote.status =
                AuthenticationVerifierVoteStatus::
                    holder_share_unavailable;
        break;
    case AuthenticationEquationStatus::pass:
        vote.status = AuthenticationVerifierVoteStatus::accept;
        vote.contributes_to_decision = true;
        break;
    case AuthenticationEquationStatus::fail:
        vote.status = AuthenticationVerifierVoteStatus::reject;
        vote.contributes_to_decision = true;
        break;
    case AuthenticationEquationStatus::none:
        break;
    }

    validate_authentication_vote(vote);
    return vote;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationVerifierVote>
AtlasGsz<T>::authentication_votes_for_sharing(
        uint64_t sharing_id) const
{
    vector<AuthenticationVerifierVote> res;
    for (auto material_id : authentication_material_for_sharing(sharing_id))
    {
        auto vote = authentication_vote_from_material(material_id);
        validate_authentication_vote(vote);
        res.push_back(vote);
    }
    return res;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationVerifierVote>
AtlasGsz<T>::authentication_votes_for_checkpoint(
        uint64_t checkpoint_id) const
{
    vector<AuthenticationVerifierVote> res;
    for (auto material_id :
            authentication_material_for_checkpoint(checkpoint_id))
    {
        auto vote = authentication_vote_from_material(material_id);
        validate_authentication_vote(vote);
        res.push_back(vote);
    }
    return res;
}

template<class T>
typename AtlasGsz<T>::AuthenticationHolderDecision
AtlasGsz<T>::authentication_holder_decision_for_sharing(
        uint64_t sharing_id,
        int holder) const
{
    AuthenticationHolderDecision decision{};
    const auto* sharing = find_registered_sharing(sharing_id);
    assert(sharing != 0);
    assert(0 <= holder);
    assert(holder < P.num_players());
    assert(is_active_party(holder));
    if (sharing == 0)
        return decision;

    decision.valid = true;
    decision.sharing_id = sharing_id;
    decision.checkpoint_id = sharing->checkpoint_id;
    decision.segment_id = sharing->segment_id;
    decision.holder = holder;
    decision.decision_threshold = corruption_threshold() + 1;

    switch (sharing->kind)
    {
    case RegisteredSharingKind::checkpoint_output:
        decision.kind =
                AuthenticationRecordKind::checkpoint_output_share;
        break;
    case RegisteredSharingKind::analyze_request_snapshot:
        decision.kind =
                AuthenticationRecordKind::analyze_request_snapshot;
        break;
    case RegisteredSharingKind::none:
    case RegisteredSharingKind::checkpoint_input:
    case RegisteredSharingKind::segment_intermediate:
        break;
    }

    auto active = active_parties();
    int expected_votes = 0;
    for (auto verifier : active)
        if (verifier != holder)
            expected_votes++;

    for (auto material_id : authentication_material_for_sharing(sharing_id))
    {
        const auto* material = find_authentication_material_record(
                material_id);
        assert(material != 0);
        if (material->holder != holder)
            continue;
        if (not is_active_party(material->verifier))
            continue;

        auto vote = authentication_vote_from_material(material_id);
        validate_authentication_vote(vote);

        assert(vote.sharing_id == decision.sharing_id);
        assert(vote.checkpoint_id == decision.checkpoint_id);
        assert(vote.segment_id == decision.segment_id);
        assert(vote.holder == decision.holder);
        if (decision.kind == AuthenticationRecordKind::none)
            decision.kind = vote.kind;
        else
            assert(decision.kind == vote.kind);

        decision.material_ids.push_back(material_id);
        decision.total_votes++;

        switch (vote.status)
        {
        case AuthenticationVerifierVoteStatus::accept:
            decision.accept_votes++;
            decision.contributing_votes++;
            break;
        case AuthenticationVerifierVoteStatus::reject:
            decision.reject_votes++;
            decision.contributing_votes++;
            break;
        case AuthenticationVerifierVoteStatus::not_ready:
            decision.not_ready_votes++;
            break;
        case AuthenticationVerifierVoteStatus::holder_share_unavailable:
            decision.unavailable_votes++;
            break;
        case AuthenticationVerifierVoteStatus::none:
            break;
        }
    }

    assert(0 <= expected_votes);
    if (expected_votes < decision.decision_threshold)
        decision.status =
                AuthenticationHolderDecisionStatus::insufficient_votes;
    else if (decision.reject_votes >= decision.decision_threshold)
        decision.status = AuthenticationHolderDecisionStatus::rejected;
    else if (decision.unavailable_votes > 0)
        decision.status =
                AuthenticationHolderDecisionStatus::
                    holder_share_unavailable;
    else if (decision.not_ready_votes > 0
            || decision.total_votes < expected_votes)
        decision.status = AuthenticationHolderDecisionStatus::not_ready;
    else if (decision.contributing_votes < expected_votes)
        decision.status =
                AuthenticationHolderDecisionStatus::insufficient_votes;
    else
        decision.status = AuthenticationHolderDecisionStatus::accepted;

    validate_authentication_holder_decision(decision);
    return decision;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationHolderDecision>
AtlasGsz<T>::authentication_holder_decisions_for_sharing(
        uint64_t sharing_id) const
{
    vector<AuthenticationHolderDecision> res;
    assert(find_registered_sharing(sharing_id) != 0);

    for (auto holder : active_parties())
    {
        auto decision = authentication_holder_decision_for_sharing(
                sharing_id, holder);
        validate_authentication_holder_decision(decision);
        res.push_back(decision);
    }
    return res;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationHolderDecision>
AtlasGsz<T>::authentication_holder_decisions_for_checkpoint(
        uint64_t checkpoint_id) const
{
    vector<AuthenticationHolderDecision> res;
    const CheckpointRecord* checkpoint = 0;
    if (verifiable_registry.initialized)
        for (const auto& candidate : verifiable_registry.checkpoints)
            if (candidate.checkpoint_id == checkpoint_id)
            {
                checkpoint = &candidate;
                break;
            }
    assert(checkpoint != 0);
    if (checkpoint == 0)
        return res;

    for (auto sharing_id : checkpoint->sharing_ids)
    {
        auto decisions =
                authentication_holder_decisions_for_sharing(sharing_id);
        res.insert(res.end(), decisions.begin(), decisions.end());
    }
    return res;
}

template<class T>
typename AtlasGsz<T>::AuthenticationSharingDecision
AtlasGsz<T>::authentication_sharing_decision(
        uint64_t sharing_id) const
{
    AuthenticationSharingDecision decision{};
    const auto* sharing = find_registered_sharing(sharing_id);
    assert(sharing != 0);
    if (sharing == 0)
        return decision;

    decision.valid = true;
    decision.sharing_id = sharing_id;
    decision.checkpoint_id = sharing->checkpoint_id;
    decision.segment_id = sharing->segment_id;
    decision.expected_holders = int(active_parties().size());

    switch (sharing->kind)
    {
    case RegisteredSharingKind::checkpoint_output:
        decision.kind =
                AuthenticationRecordKind::checkpoint_output_share;
        break;
    case RegisteredSharingKind::analyze_request_snapshot:
        decision.kind =
                AuthenticationRecordKind::analyze_request_snapshot;
        break;
    case RegisteredSharingKind::none:
    case RegisteredSharingKind::checkpoint_input:
    case RegisteredSharingKind::segment_intermediate:
        break;
    }

    auto holder_decisions =
            authentication_holder_decisions_for_sharing(sharing_id);
    for (const auto& holder_decision : holder_decisions)
    {
        validate_authentication_holder_decision(holder_decision);
        assert(holder_decision.sharing_id == decision.sharing_id);
        assert(holder_decision.checkpoint_id == decision.checkpoint_id);
        assert(holder_decision.segment_id == decision.segment_id);
        assert(is_active_party(holder_decision.holder));

        if (decision.kind == AuthenticationRecordKind::none)
            decision.kind = holder_decision.kind;
        else if (holder_decision.kind != AuthenticationRecordKind::none)
            assert(decision.kind == holder_decision.kind);

        decision.holder_ids.push_back(holder_decision.holder);
        decision.total_holder_decisions++;

        switch (holder_decision.status)
        {
        case AuthenticationHolderDecisionStatus::accepted:
            decision.accepted_holders++;
            break;
        case AuthenticationHolderDecisionStatus::rejected:
            decision.rejected_holders++;
            decision.rejected_holder_ids.push_back(
                    holder_decision.holder);
            break;
        case AuthenticationHolderDecisionStatus::not_ready:
            decision.not_ready_holders++;
            break;
        case AuthenticationHolderDecisionStatus::holder_share_unavailable:
            decision.unavailable_holders++;
            break;
        case AuthenticationHolderDecisionStatus::insufficient_votes:
            decision.insufficient_holders++;
            break;
        case AuthenticationHolderDecisionStatus::none:
            break;
        }
    }

    if (decision.rejected_holders > 0)
        decision.status = AuthenticationSharingDecisionStatus::rejected;
    else if (decision.unavailable_holders > 0)
        decision.status =
                AuthenticationSharingDecisionStatus::
                    holder_share_unavailable;
    else if (decision.not_ready_holders > 0)
        decision.status = AuthenticationSharingDecisionStatus::not_ready;
    else if (decision.insufficient_holders > 0
            || decision.total_holder_decisions < decision.expected_holders)
        decision.status =
                AuthenticationSharingDecisionStatus::insufficient_votes;
    else if (decision.expected_holders > 0
            && decision.accepted_holders == decision.expected_holders
            && decision.total_holder_decisions == decision.expected_holders)
        decision.status = AuthenticationSharingDecisionStatus::accepted;
    else
        decision.status =
                AuthenticationSharingDecisionStatus::insufficient_votes;

    validate_authentication_sharing_decision(decision);
    return decision;
}

template<class T>
vector<typename AtlasGsz<T>::AuthenticationSharingDecision>
AtlasGsz<T>::authentication_sharing_decisions_for_checkpoint(
        uint64_t checkpoint_id) const
{
    vector<AuthenticationSharingDecision> res;
    const CheckpointRecord* checkpoint = 0;
    if (verifiable_registry.initialized)
        for (const auto& candidate : verifiable_registry.checkpoints)
            if (candidate.checkpoint_id == checkpoint_id)
            {
                checkpoint = &candidate;
                break;
            }
    assert(checkpoint != 0);
    if (checkpoint == 0)
        return res;

    for (auto sharing_id : checkpoint->sharing_ids)
    {
        auto decision = authentication_sharing_decision(sharing_id);
        validate_authentication_sharing_decision(decision);
        res.push_back(decision);
    }
    return res;
}

template<class T>
typename AtlasGsz<T>::AuthenticationCheckpointDecision
AtlasGsz<T>::authentication_checkpoint_decision(
        uint64_t checkpoint_id) const
{
    AuthenticationCheckpointDecision decision{};
    const CheckpointRecord* checkpoint = 0;
    if (verifiable_registry.initialized)
        for (const auto& candidate : verifiable_registry.checkpoints)
            if (candidate.checkpoint_id == checkpoint_id)
            {
                checkpoint = &candidate;
                break;
            }
    assert(checkpoint != 0);
    if (checkpoint == 0)
        return decision;

    decision.valid = true;
    decision.checkpoint_id = checkpoint_id;
    decision.segment_id = checkpoint->segment_id;
    decision.expected_sharings = int(checkpoint->sharing_ids.size());

    auto sharing_decisions =
            authentication_sharing_decisions_for_checkpoint(checkpoint_id);
    for (const auto& sharing_decision : sharing_decisions)
    {
        validate_authentication_sharing_decision(sharing_decision);
        assert(sharing_decision.checkpoint_id == decision.checkpoint_id);
        assert(sharing_decision.segment_id == decision.segment_id);

        decision.sharing_ids.push_back(sharing_decision.sharing_id);
        decision.total_sharing_decisions++;

        switch (sharing_decision.status)
        {
        case AuthenticationSharingDecisionStatus::accepted:
            decision.accepted_sharings++;
            break;
        case AuthenticationSharingDecisionStatus::rejected:
            decision.rejected_sharings++;
            decision.rejected_sharing_ids.push_back(
                    sharing_decision.sharing_id);
            for (auto holder : sharing_decision.rejected_holder_ids)
                if (std::find(decision.rejected_holder_ids.begin(),
                        decision.rejected_holder_ids.end(), holder)
                        == decision.rejected_holder_ids.end())
                    decision.rejected_holder_ids.push_back(holder);
            break;
        case AuthenticationSharingDecisionStatus::not_ready:
            decision.not_ready_sharings++;
            break;
        case AuthenticationSharingDecisionStatus::holder_share_unavailable:
            decision.unavailable_sharings++;
            break;
        case AuthenticationSharingDecisionStatus::insufficient_votes:
            decision.insufficient_sharings++;
            break;
        case AuthenticationSharingDecisionStatus::none:
            break;
        }
    }

    if (decision.rejected_sharings > 0)
        decision.status = AuthenticationCheckpointDecisionStatus::rejected;
    else if (decision.unavailable_sharings > 0)
        decision.status =
                AuthenticationCheckpointDecisionStatus::
                    holder_share_unavailable;
    else if (decision.not_ready_sharings > 0)
        decision.status =
                AuthenticationCheckpointDecisionStatus::not_ready;
    else if (decision.insufficient_sharings > 0
            || decision.total_sharing_decisions < decision.expected_sharings)
        decision.status =
                AuthenticationCheckpointDecisionStatus::insufficient_votes;
    else if (decision.expected_sharings > 0
            && decision.accepted_sharings == decision.expected_sharings
            && decision.total_sharing_decisions == decision.expected_sharings)
        decision.status = AuthenticationCheckpointDecisionStatus::accepted;
    else
        decision.status =
                AuthenticationCheckpointDecisionStatus::insufficient_votes;

    validate_authentication_checkpoint_decision(decision);
    return decision;
}

template<class T>
typename AtlasGsz<T>::AuthenticationCheckpointDecision
AtlasGsz<T>::current_output_checkpoint_authentication_decision() const
{
    AuthenticationCheckpointDecision decision{};
    assert(segment_lifecycle.initialized);
    if (not segment_lifecycle.initialized)
        return decision;

    assert(segment_lifecycle.current_output_checkpoint_id != 0);
    if (segment_lifecycle.current_output_checkpoint_id == 0)
        return decision;

    return authentication_checkpoint_decision(
            segment_lifecycle.current_output_checkpoint_id);
}

template<class T>
void AtlasGsz<T>::validate_authentication_vote(
        const AuthenticationVerifierVote& vote) const
{
    assert(vote.valid);
    assert(vote.status != AuthenticationVerifierVoteStatus::none);
    assert(vote.material_id != 0);
    assert(vote.auth_record_id != 0);
    assert(vote.sharing_id != 0);
    assert(0 <= vote.verifier);
    assert(vote.verifier < P.num_players());
    assert(0 <= vote.holder);
    assert(vote.holder < P.num_players());
    assert(vote.verifier != vote.holder);
    assert(vote.kind != AuthenticationRecordKind::none);
    assert(vote.equation_status != AuthenticationEquationStatus::none);

    const auto* material = find_authentication_material_record(
            vote.material_id);
    assert(material != 0);
    assert(material->auth_record_id == vote.auth_record_id);
    assert(material->sharing_id == vote.sharing_id);
    assert(material->checkpoint_id == vote.checkpoint_id);
    assert(material->segment_id == vote.segment_id);
    assert(material->verifier == vote.verifier);
    assert(material->holder == vote.holder);
    assert(material->kind == vote.kind);

    switch (vote.status)
    {
    case AuthenticationVerifierVoteStatus::not_ready:
        assert(vote.equation_status
                == AuthenticationEquationStatus::not_ready);
        assert(not vote.contributes_to_decision);
        break;
    case AuthenticationVerifierVoteStatus::holder_share_unavailable:
        assert(vote.equation_status
                == AuthenticationEquationStatus::
                    holder_share_unavailable);
        assert(not vote.contributes_to_decision);
        break;
    case AuthenticationVerifierVoteStatus::accept:
        assert(vote.equation_status == AuthenticationEquationStatus::pass);
        assert(vote.contributes_to_decision);
        break;
    case AuthenticationVerifierVoteStatus::reject:
        assert(vote.equation_status == AuthenticationEquationStatus::fail);
        assert(vote.contributes_to_decision);
        break;
    case AuthenticationVerifierVoteStatus::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_holder_decision(
        const AuthenticationHolderDecision& decision) const
{
    assert(decision.valid);
    assert(decision.status != AuthenticationHolderDecisionStatus::none);
    assert(decision.sharing_id != 0);
    assert(0 <= decision.holder);
    assert(decision.holder < P.num_players());
    assert(is_active_party(decision.holder));
    assert(decision.decision_threshold == corruption_threshold() + 1);
    assert(0 < decision.decision_threshold);
    assert(0 <= decision.total_votes);
    assert(0 <= decision.accept_votes);
    assert(0 <= decision.reject_votes);
    assert(0 <= decision.not_ready_votes);
    assert(0 <= decision.unavailable_votes);
    assert(0 <= decision.contributing_votes);
    assert(decision.total_votes
            == int(decision.material_ids.size()));
    assert(decision.contributing_votes
            == decision.accept_votes + decision.reject_votes);
    assert(decision.total_votes
            == decision.accept_votes + decision.reject_votes
            + decision.not_ready_votes + decision.unavailable_votes);

    const auto* sharing = find_registered_sharing(decision.sharing_id);
    assert(sharing != 0);
    assert(decision.checkpoint_id == sharing->checkpoint_id);
    assert(decision.segment_id == sharing->segment_id);

    int expected_votes = 0;
    for (auto verifier : active_parties())
        if (verifier != decision.holder)
            expected_votes++;

    for (auto material_id : decision.material_ids)
    {
        const auto* material = find_authentication_material_record(
                material_id);
        assert(material != 0);
        assert(material->sharing_id == decision.sharing_id);
        assert(material->checkpoint_id == decision.checkpoint_id);
        assert(material->segment_id == decision.segment_id);
        assert(is_active_party(material->verifier));
        assert(material->holder == decision.holder);
        assert(material->kind == decision.kind);
    }

    switch (decision.status)
    {
    case AuthenticationHolderDecisionStatus::not_ready:
        assert(decision.reject_votes < decision.decision_threshold);
        assert(decision.unavailable_votes == 0);
        assert(decision.not_ready_votes > 0
                || decision.total_votes < expected_votes);
        break;
    case AuthenticationHolderDecisionStatus::holder_share_unavailable:
        assert(decision.reject_votes < decision.decision_threshold);
        assert(decision.unavailable_votes > 0);
        break;
    case AuthenticationHolderDecisionStatus::insufficient_votes:
        assert(decision.reject_votes < decision.decision_threshold);
        assert(expected_votes < decision.decision_threshold
                || decision.contributing_votes < expected_votes);
        break;
    case AuthenticationHolderDecisionStatus::accepted:
        assert(decision.reject_votes < decision.decision_threshold);
        assert(decision.not_ready_votes == 0);
        assert(decision.unavailable_votes == 0);
        assert(decision.total_votes == expected_votes);
        assert(decision.contributing_votes == expected_votes);
        assert(decision.kind != AuthenticationRecordKind::none);
        break;
    case AuthenticationHolderDecisionStatus::rejected:
        assert(decision.reject_votes >= decision.decision_threshold);
        assert(decision.kind != AuthenticationRecordKind::none);
        break;
    case AuthenticationHolderDecisionStatus::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_sharing_decision(
        const AuthenticationSharingDecision& decision) const
{
    assert(decision.valid);
    assert(decision.status != AuthenticationSharingDecisionStatus::none);
    assert(decision.sharing_id != 0);
    assert(0 <= decision.expected_holders);
    assert(0 <= decision.total_holder_decisions);
    assert(0 <= decision.accepted_holders);
    assert(0 <= decision.rejected_holders);
    assert(0 <= decision.not_ready_holders);
    assert(0 <= decision.unavailable_holders);
    assert(0 <= decision.insufficient_holders);
    assert(decision.total_holder_decisions
            == int(decision.holder_ids.size()));
    assert(decision.rejected_holders
            == int(decision.rejected_holder_ids.size()));
    assert(decision.total_holder_decisions
            == decision.accepted_holders + decision.rejected_holders
            + decision.not_ready_holders + decision.unavailable_holders
            + decision.insufficient_holders);

    const auto* sharing = find_registered_sharing(decision.sharing_id);
    assert(sharing != 0);
    assert(decision.checkpoint_id == sharing->checkpoint_id);
    assert(decision.segment_id == sharing->segment_id);
    assert(decision.expected_holders == int(active_parties().size()));

    for (size_t i = 0; i < decision.holder_ids.size(); i++)
    {
        int holder = decision.holder_ids.at(i);
        assert(0 <= holder);
        assert(holder < P.num_players());
        assert(is_active_party(holder));
        for (size_t j = i + 1; j < decision.holder_ids.size(); j++)
            assert(holder != decision.holder_ids.at(j));
    }

    for (auto holder : decision.rejected_holder_ids)
    {
        assert(std::find(decision.holder_ids.begin(),
                decision.holder_ids.end(), holder)
                != decision.holder_ids.end());
        auto holder_decision =
                authentication_holder_decision_for_sharing(
                        decision.sharing_id, holder);
        assert(holder_decision.status
                == AuthenticationHolderDecisionStatus::rejected);
    }

    switch (decision.status)
    {
    case AuthenticationSharingDecisionStatus::rejected:
        assert(decision.rejected_holders > 0);
        assert(decision.kind != AuthenticationRecordKind::none);
        break;
    case AuthenticationSharingDecisionStatus::holder_share_unavailable:
        assert(decision.rejected_holders == 0);
        assert(decision.unavailable_holders > 0);
        break;
    case AuthenticationSharingDecisionStatus::not_ready:
        assert(decision.rejected_holders == 0);
        assert(decision.unavailable_holders == 0);
        assert(decision.not_ready_holders > 0);
        break;
    case AuthenticationSharingDecisionStatus::insufficient_votes:
        assert(decision.rejected_holders == 0);
        assert(decision.unavailable_holders == 0);
        assert(decision.not_ready_holders == 0);
        assert(decision.insufficient_holders > 0
                || decision.total_holder_decisions
                    < decision.expected_holders
                || decision.expected_holders == 0);
        break;
    case AuthenticationSharingDecisionStatus::accepted:
        assert(decision.expected_holders > 0);
        assert(decision.total_holder_decisions
                == decision.expected_holders);
        assert(decision.accepted_holders == decision.expected_holders);
        assert(decision.rejected_holders == 0);
        assert(decision.not_ready_holders == 0);
        assert(decision.unavailable_holders == 0);
        assert(decision.insufficient_holders == 0);
        assert(decision.kind != AuthenticationRecordKind::none);
        break;
    case AuthenticationSharingDecisionStatus::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_checkpoint_decision(
        const AuthenticationCheckpointDecision& decision) const
{
    assert(decision.valid);
    assert(decision.status != AuthenticationCheckpointDecisionStatus::none);
    assert(decision.checkpoint_id != 0);
    assert(0 <= decision.expected_sharings);
    assert(0 <= decision.total_sharing_decisions);
    assert(0 <= decision.accepted_sharings);
    assert(0 <= decision.rejected_sharings);
    assert(0 <= decision.not_ready_sharings);
    assert(0 <= decision.unavailable_sharings);
    assert(0 <= decision.insufficient_sharings);
    assert(decision.total_sharing_decisions
            == int(decision.sharing_ids.size()));
    assert(decision.rejected_sharings
            == int(decision.rejected_sharing_ids.size()));
    assert(decision.total_sharing_decisions
            == decision.accepted_sharings + decision.rejected_sharings
            + decision.not_ready_sharings + decision.unavailable_sharings
            + decision.insufficient_sharings);

    const CheckpointRecord* checkpoint = 0;
    if (verifiable_registry.initialized)
        for (const auto& candidate : verifiable_registry.checkpoints)
            if (candidate.checkpoint_id == decision.checkpoint_id)
            {
                checkpoint = &candidate;
                break;
            }
    assert(checkpoint != 0);
    assert(decision.segment_id == checkpoint->segment_id);
    assert(decision.expected_sharings
            == int(checkpoint->sharing_ids.size()));

    for (size_t i = 0; i < decision.sharing_ids.size(); i++)
    {
        auto sharing_id = decision.sharing_ids.at(i);
        assert(std::find(checkpoint->sharing_ids.begin(),
                checkpoint->sharing_ids.end(), sharing_id)
                != checkpoint->sharing_ids.end());
        for (size_t j = i + 1; j < decision.sharing_ids.size(); j++)
            assert(sharing_id != decision.sharing_ids.at(j));
    }

    for (auto sharing_id : decision.rejected_sharing_ids)
    {
        assert(std::find(decision.sharing_ids.begin(),
                decision.sharing_ids.end(), sharing_id)
                != decision.sharing_ids.end());
        auto sharing_decision =
                authentication_sharing_decision(sharing_id);
        assert(sharing_decision.status
                == AuthenticationSharingDecisionStatus::rejected);
    }

    for (auto holder : decision.rejected_holder_ids)
    {
        assert(0 <= holder);
        assert(holder < P.num_players());
        assert(is_active_party(holder));
        bool found = false;
        for (auto sharing_id : decision.rejected_sharing_ids)
        {
            auto sharing_decision =
                    authentication_sharing_decision(sharing_id);
            if (std::find(sharing_decision.rejected_holder_ids.begin(),
                    sharing_decision.rejected_holder_ids.end(), holder)
                    != sharing_decision.rejected_holder_ids.end())
            {
                found = true;
                break;
            }
        }
        assert(found);
    }

    switch (decision.status)
    {
    case AuthenticationCheckpointDecisionStatus::rejected:
        assert(decision.rejected_sharings > 0);
        assert(not decision.rejected_holder_ids.empty());
        break;
    case AuthenticationCheckpointDecisionStatus::holder_share_unavailable:
        assert(decision.rejected_sharings == 0);
        assert(decision.unavailable_sharings > 0);
        break;
    case AuthenticationCheckpointDecisionStatus::not_ready:
        assert(decision.rejected_sharings == 0);
        assert(decision.unavailable_sharings == 0);
        assert(decision.not_ready_sharings > 0);
        break;
    case AuthenticationCheckpointDecisionStatus::insufficient_votes:
        assert(decision.rejected_sharings == 0);
        assert(decision.unavailable_sharings == 0);
        assert(decision.not_ready_sharings == 0);
        assert(decision.insufficient_sharings > 0
                || decision.total_sharing_decisions
                    < decision.expected_sharings
                || decision.expected_sharings == 0);
        break;
    case AuthenticationCheckpointDecisionStatus::accepted:
        assert(decision.expected_sharings > 0);
        assert(decision.total_sharing_decisions
                == decision.expected_sharings);
        assert(decision.accepted_sharings == decision.expected_sharings);
        assert(decision.rejected_sharings == 0);
        assert(decision.not_ready_sharings == 0);
        assert(decision.unavailable_sharings == 0);
        assert(decision.insufficient_sharings == 0);
        assert(decision.rejected_sharing_ids.empty());
        assert(decision.rejected_holder_ids.empty());
        break;
    case AuthenticationCheckpointDecisionStatus::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::ensure_dispute_control_state_initialized()
{
    int n = P.num_players();
    if (not dispute_control_state.initialized)
    {
        dispute_control_state.corr.assign(n, false);
        dispute_control_state.disp.assign(n, vector<bool>(n, false));
        dispute_control_state.initialized = true;
    }

    assert(dispute_control_state.corr.size() == size_t(n));
    assert(dispute_control_state.disp.size() == size_t(n));
    for (int i = 0; i < n; i++)
    {
        assert(dispute_control_state.disp.at(i).size() == size_t(n));
        assert(not dispute_control_state.disp.at(i).at(i));
        for (int j = 0; j < n; j++)
            assert(dispute_control_state.disp.at(i).at(j)
                    == dispute_control_state.disp.at(j).at(i));
    }
}

template<class T>
void AtlasGsz<T>::validate_dispute_control_state() const
{
    if (not dispute_control_state.initialized)
        return;

    int n = P.num_players();
    int t = corruption_threshold();
    assert(dispute_control_state.corr.size() == size_t(n));
    assert(dispute_control_state.disp.size() == size_t(n));

    for (int i = 0; i < n; i++)
    {
        assert(dispute_control_state.disp.at(i).size() == size_t(n));
        assert(not dispute_control_state.disp.at(i).at(i));
        for (int j = 0; j < n; j++)
            assert(dispute_control_state.disp.at(i).at(j)
                    == dispute_control_state.disp.at(j).at(i));
    }

    for (int i = 0; i < n; i++)
    {
        if (dispute_control_state.corr.at(i))
        {
            for (int j = 0; j < n; j++)
            {
                if (i == j)
                    continue;
                assert(dispute_control_state.disp.at(i).at(j));
                assert(dispute_control_state.disp.at(j).at(i));
            }
        }
        else
            assert(count_disputes(i) <= t);
    }
}

template<class T>
int AtlasGsz<T>::corruption_threshold() const
{
    return (P.num_players() - 1) / 2;
}

template<class T>
bool AtlasGsz<T>::has_dispute_control_state() const
{
    return dispute_control_state.initialized;
}

template<class T>
vector<int> AtlasGsz<T>::active_parties() const
{
    vector<int> res;
    for (int i = 0; i < P.num_players(); i++)
        if (is_active_party(i))
            res.push_back(i);
    return res;
}

template<class T>
bool AtlasGsz<T>::is_active_party(int party) const
{
    assert(0 <= party);
    assert(party < P.num_players());
    return not is_corrupted_party(party);
}

template<class T>
int AtlasGsz<T>::num_active_parties() const
{
    return active_parties().size();
}

template<class T>
bool AtlasGsz<T>::is_corrupted_party(int party) const
{
    assert(0 <= party);
    assert(party < P.num_players());
    if (not dispute_control_state.initialized)
        return false;
    assert(dispute_control_state.corr.size() == size_t(P.num_players()));
    return dispute_control_state.corr.at(party);
}

template<class T>
bool AtlasGsz<T>::is_disputed_pair(int a, int b) const
{
    assert(0 <= a);
    assert(a < P.num_players());
    assert(0 <= b);
    assert(b < P.num_players());
    if (a == b || not dispute_control_state.initialized)
        return false;
    assert(dispute_control_state.disp.size() == size_t(P.num_players()));
    return dispute_control_state.disp.at(a).at(b);
}

template<class T>
vector<int> AtlasGsz<T>::disputed_parties_of(int party) const
{
    assert(0 <= party);
    assert(party < P.num_players());
    vector<int> res;
    if (not dispute_control_state.initialized)
        return res;

    for (int i = 0; i < P.num_players(); i++)
        if (i != party && dispute_control_state.disp.at(party).at(i))
            res.push_back(i);
    return res;
}

template<class T>
int AtlasGsz<T>::count_disputes(int party) const
{
    assert(0 <= party);
    assert(party < P.num_players());
    if (not dispute_control_state.initialized)
        return 0;
    assert(dispute_control_state.disp.size() == size_t(P.num_players()));

    int res = 0;
    for (int i = 0; i < P.num_players(); i++)
        if (dispute_control_state.disp.at(party).at(i))
            res++;
    return res;
}

template<class T>
int AtlasGsz<T>::count_active_disputes(int party) const
{
    assert(0 <= party);
    assert(party < P.num_players());
    if (not dispute_control_state.initialized)
        return 0;

    int res = 0;
    for (int i = 0; i < P.num_players(); i++)
        if (i != party
                && is_active_party(i)
                && dispute_control_state.disp.at(party).at(i))
            res++;
    return res;
}

template<class T>
bool AtlasGsz<T>::can_communicate_directly(int sender, int receiver) const
{
    assert(0 <= sender);
    assert(sender < P.num_players());
    assert(0 <= receiver);
    assert(receiver < P.num_players());
    if (sender == receiver)
        return false;
    if (not dispute_control_state.initialized)
        return true;

    return is_active_party(sender)
            && is_active_party(receiver)
            && not is_disputed_pair(sender, receiver);
}

template<class T>
bool AtlasGsz<T>::share_from_dealer_is_suppressed(
        int dealer,
        int recipient) const
{
    assert(0 <= dealer);
    assert(dealer < P.num_players());
    assert(0 <= recipient);
    assert(recipient < P.num_players());
    return is_corrupted_party(dealer)
            || is_corrupted_party(recipient)
            || is_disputed_pair(dealer, recipient);
}

template<class T>
int AtlasGsz<T>::select_active_king() const
{
    auto active = active_parties();
    assert(not active.empty());
    if (active.empty())
        return -1;
    return active.front();
}

template<class T>
vector<int> AtlasGsz<T>::select_T_for_king(int king) const
{
    assert(0 <= king);
    assert(king < P.num_players());
    assert(is_active_party(king));

    int t = corruption_threshold();
    vector<int> res;
    if (not is_active_party(king))
        return res;

    res.push_back(king);
    for (int i = 0; i < P.num_players() && res.size() < size_t(t + 1); i++)
    {
        if (i == king)
            continue;
        if (is_active_party(i) && not is_disputed_pair(king, i))
            res.push_back(i);
    }

    assert(res.size() == size_t(t + 1));
    return res;
}

template<class T>
int AtlasGsz<T>::relay_for_disputed_pair(int a, int b) const
{
    assert(0 <= a);
    assert(a < P.num_players());
    assert(0 <= b);
    assert(b < P.num_players());
    assert(a != b);
    assert(is_active_party(a));
    assert(is_active_party(b));
    assert(is_disputed_pair(a, b));

    if (a == b || not is_active_party(a) || not is_active_party(b)
            || not is_disputed_pair(a, b))
        return -1;

    for (int r = 0; r < P.num_players(); r++)
        if (r != a
                && r != b
                && is_active_party(r)
                && not is_disputed_pair(a, r)
                && not is_disputed_pair(b, r))
            return r;

#ifndef NDEBUG
    assert(false);
#endif
    return -1;
}

template<class T>
bool AtlasGsz<T>::has_relay_for_disputed_pair(int a, int b) const
{
    assert(0 <= a);
    assert(a < P.num_players());
    assert(0 <= b);
    assert(b < P.num_players());
    assert(a != b);

    if (a == b || not is_active_party(a) || not is_active_party(b)
            || not is_disputed_pair(a, b))
        return false;

    for (int r = 0; r < P.num_players(); r++)
        if (r != a
                && r != b
                && is_active_party(r)
                && not is_disputed_pair(a, r)
                && not is_disputed_pair(b, r))
            return true;
    return false;
}

template<class T>
void AtlasGsz<T>::record_corrupted_party(
        int party,
        FaultLocalizationApplication& application)
{
    ensure_dispute_control_state_initialized();
    int n = P.num_players();
    assert(0 <= party);
    assert(party < n);
    application.corrupted_party = party;

    int threshold = corruption_threshold() + 1;
    auto mark_corrupted = [&](int p)
    {
        bool changed = false;
        if (not dispute_control_state.corr.at(p))
        {
            dispute_control_state.corr.at(p) = true;
            application.newly_corrupted_parties.push_back(p);
            if (application.corrupted_party < 0)
                application.corrupted_party = p;
            application.state_updated = true;
            changed = true;
        }

        for (int q = 0; q < n; q++)
        {
            if (q == p)
                continue;
            if (not dispute_control_state.disp.at(p).at(q))
            {
                dispute_control_state.disp.at(p).at(q) = true;
                dispute_control_state.disp.at(q).at(p) = true;
                application.state_updated = true;
                changed = true;
            }
        }
        assert(not dispute_control_state.disp.at(p).at(p));
        return changed;
    };

    mark_corrupted(party);

    bool changed;
    do
    {
        changed = false;
        for (int i = 0; i < n; i++)
            if (not dispute_control_state.corr.at(i)
                    && count_disputes(i) >= threshold)
                changed |= mark_corrupted(i);
    }
    while (changed);

    validate_dispute_control_state();
}

template<class T>
void AtlasGsz<T>::record_disputed_pair(
        int a,
        int b,
        FaultLocalizationApplication& application)
{
    ensure_dispute_control_state_initialized();
    int n = P.num_players();
    assert(0 <= a);
    assert(a < n);
    assert(0 <= b);
    assert(b < n);
    assert(a != b);

    application.primary_party = a;
    application.counterparty = b;
    int x = min(a, b);
    int y = max(a, b);
    application.disputed_party_a = x;
    application.disputed_party_b = y;

    if (not dispute_control_state.disp.at(x).at(y))
    {
        dispute_control_state.disp.at(x).at(y) = true;
        dispute_control_state.disp.at(y).at(x) = true;
        application.state_updated = true;
    }

    int threshold = corruption_threshold() + 1;
    auto mark_corrupted = [&](int p)
    {
        bool changed = false;
        if (not dispute_control_state.corr.at(p))
        {
            dispute_control_state.corr.at(p) = true;
            application.newly_corrupted_parties.push_back(p);
            if (application.corrupted_party < 0)
                application.corrupted_party = p;
            application.state_updated = true;
            changed = true;
        }

        for (int q = 0; q < n; q++)
        {
            if (q == p)
                continue;
            if (not dispute_control_state.disp.at(p).at(q))
            {
                dispute_control_state.disp.at(p).at(q) = true;
                dispute_control_state.disp.at(q).at(p) = true;
                application.state_updated = true;
                changed = true;
            }
        }
        assert(not dispute_control_state.disp.at(p).at(p));
        return changed;
    };

    bool changed;
    do
    {
        changed = false;
        for (int i = 0; i < n; i++)
            if (not dispute_control_state.corr.at(i)
                    && count_disputes(i) >= threshold)
                changed |= mark_corrupted(i);
    }
    while (changed);

    validate_dispute_control_state();
}

template<class T>
typename AtlasGsz<T>::FaultLocalizationApplication
AtlasGsz<T>::apply_fault_localization_outcome(
        const FaultLocalizationOutcome& outcome)
{
    FaultLocalizationApplication application{};

    if (not outcome.valid)
    {
#ifndef NDEBUG
        assert(false);
#endif
        return application;
    }

    switch (outcome.action)
    {
    case FaultLocalizationAction::needs_analyze_sharing:
        application.valid = true;
        application.action =
                FaultLocalizationApplicationAction::
                    pending_analyze_sharing;
        return application;

    case FaultLocalizationAction::identify_corrupted_party:
        application.valid = true;
        application.action =
                FaultLocalizationApplicationAction::
                    recorded_corrupted_party;
        record_corrupted_party(outcome.corrupted_party, application);
        validate_dispute_control_state();
        return application;

    case FaultLocalizationAction::identify_disputed_pair:
        application.valid = true;
        application.action =
                FaultLocalizationApplicationAction::
                    recorded_disputed_pair;
        record_disputed_pair(
                outcome.primary_party, outcome.counterparty, application);
        validate_dispute_control_state();
        return application;

    case FaultLocalizationAction::none:
        break;
    }

#ifndef NDEBUG
    assert(false);
#endif
    return application;
}

template<class T>
void AtlasGsz<T>::init(Preprocessing<T>& prep, typename T::MAC_Check& MC) {
    honest.init(prep, MC);
}

template<class T>
void AtlasGsz<T>::init_mul()
{
    maybe_check();
    honest.init_mul();
}

template<class T>
void AtlasGsz<T>::prepare_mul(const T& x, const T& y, int)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul(x, y);
}

template<class T>
void AtlasGsz<T>::exchange()
{
    honest.exchange();
}

template<class T>
T AtlasGsz<T>::finalize_mul(int)
{
    size_t n_records = partial_mult_transcripts.size();
    T res = honest.finalize_mul();
    size_t offset = z_verify.size();
    assert(offset < x_verify.size());
    PartialMultTranscriptRecord record{};
    record.offset = offset;
    record.length = 1;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.has_king_evidence = honest.has_last_king_partial_mult_evidence();
    if (record.has_king_evidence)
        record.king_evidence = honest.get_last_king_partial_mult_evidence();
    assert(record.has_king_evidence == (P.my_num() == record.transcript.king));
    if (record.has_king_evidence)
        assert(record.king_evidence.king == record.transcript.king);
    partial_mult_transcripts.push_back(record);
    assert(partial_mult_transcripts.size() == n_records + 1);
    z_verify.push_back(res);
    return res;
}

template<class T>
void AtlasGsz<T>::set_fixed_king(int king)
{
    honest.set_fixed_king(king);
}

template<class T>
T AtlasGsz<T>::get_random()
{
    return honest.get_random();
}

template<class T>
void AtlasGsz<T>::init_dotprod()
{
    maybe_check();
    honest.init_dotprod();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_dotprod(x, y);
}

template<class T>
void AtlasGsz<T>::next_dotprod()
{
    honest.next_dotprod();
}

template<class T>
T AtlasGsz<T>::finalize_dotprod(int length)
{
    size_t n_records = partial_mult_transcripts.size();
    T res = honest.finalize_dotprod(length);
    size_t offset = z_verify.size();
    assert(length > 0);
    assert(offset + size_t(length) <= x_verify.size());
    PartialMultTranscriptRecord record{};
    record.offset = offset;
    record.length = length;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.has_king_evidence = honest.has_last_king_partial_mult_evidence();
    if (record.has_king_evidence)
        record.king_evidence = honest.get_last_king_partial_mult_evidence();
    assert(record.has_king_evidence == (P.my_num() == record.transcript.king));
    if (record.has_king_evidence)
        assert(record.king_evidence.king == record.transcript.king);
    partial_mult_transcripts.push_back(record);
    assert(partial_mult_transcripts.size() == n_records + 1);
    z_verify.push_back(res);

    // The dot product result is stored in the first element,
    // the rest are padded with zeros to maintain 
    // z_verify is of the same length as x_verify and y_verify
    z_verify.insert(z_verify.end(), length - 1, T{0});
    return res;
}

template<class T>
void AtlasGsz<T>::init_mul_pub()
{
    maybe_check();
    honest.init_mul_pub();
}

template<class T>
void AtlasGsz<T>::prepare_mul_pub(T x, T y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul_pub(x, y);
}

template<class T>
void AtlasGsz<T>::exchange_mul_pub()
{
    honest.exchange_mul_pub();
}

template<class T>
T AtlasGsz<T>::finalize_mul_pub()
{
    size_t n_records = partial_mult_transcripts.size();
    T res = honest.finalize_mul_pub();

    PartialMultTranscriptRecord record{};
    record.offset = z_verify.size();
    record.length = 1;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.has_king_evidence = honest.has_last_king_partial_mult_evidence();
    if (record.has_king_evidence)
        record.king_evidence = honest.get_last_king_partial_mult_evidence();
    assert(record.has_king_evidence == (P.my_num() == 0));
    assert(record.transcript.king == 0);
    assert(record.transcript.r_t == T{0});
    assert(record.transcript.e_t - record.transcript.r_t == res);
    if (record.has_king_evidence)
    {
        assert(record.king_evidence.king == 0);
        assert(record.king_evidence.king == record.transcript.king);
        assert(record.king_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(record.king_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
    }
    partial_mult_transcripts.push_back(record);
    assert(partial_mult_transcripts.size() == n_records + 1);

    z_verify.push_back(res);
    return res;
}

template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

/**
 * @brief Multiplication with truncation, called by the instruction mul_trunc
 */
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, false_type)
{
    /*
     * We do not call honest.mul_trunc, 
     * because we need the intermediate results for verification.
     * Hence, we copied the code from honest.mul_trunc
     * to call the *_mul_trunc functions defined in this class.
     * These functions in turn call the corresponding functions in honest,
     * and store the intermediate results for verification.
     */

    // Parse the arguments
    struct MultTruncInfo {
        int dest_base;       // Destination register
        int x_base;         // First operand
        int y_base;         // Second operand 

        MultTruncInfo(const vector<int>& regs, int offset)
        {
            dest_base = regs[offset];
            x_base = regs[offset + 1]; 
            y_base = regs[offset + 2];
        }
    };

    vector<MultTruncInfo> infos;
    for (size_t i = 0; i < regs.size(); i += 3) 
    {
        infos.emplace_back(regs, i);
    }

    init_mul_trunc(infos.size() * size);

    for (const auto& info : infos)
    {
        for (int i = 0; i < size; ++i)
        {
            T x = proc.get_S_ref(info.x_base + i);
            T y = proc.get_S_ref(info.y_base + i);
            
            prepare_mul_trunc(x, y);
        }
    }

    exchange_mul_trunc();

    for (auto& info : infos)
    {
        for (int i = 0; i < size; ++i)
        {
            proc.get_S_ref(info.dest_base + i) = finalize_mul_trunc();
        }
    }
}


template<class T>
void AtlasGsz<T>::init_mul_trunc(int length)
{
    maybe_check();
    honest.init_mul_trunc(length);
}

template<class T>
void AtlasGsz<T>::prepare_mul_trunc(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_mul_trunc(x, y);
}

template<class T>
void AtlasGsz<T>::exchange_mul_trunc()
{
    honest.exchange_mul_trunc();
}

template<class T>
T AtlasGsz<T>::finalize_mul_trunc()
{
    size_t n_records = partial_mult_transcripts.size();
    T pre_trunc;
    T res = honest.finalize_mul_trunc(&pre_trunc);
    PartialMultTranscriptRecord record{};
    record.offset = z_verify.size();
    record.length = 1;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.has_king_evidence = honest.has_last_king_partial_mult_evidence();
    if (record.has_king_evidence)
        record.king_evidence = honest.get_last_king_partial_mult_evidence();
    assert(record.has_king_evidence == (P.my_num() == 0));
    assert(record.transcript.king == 0);
    assert(record.transcript.e_t - record.transcript.r_t == pre_trunc);
    if (record.has_king_evidence)
    {
        assert(record.king_evidence.king == 0);
        assert(record.king_evidence.king == record.transcript.king);
        assert(record.king_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(record.king_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
    }
    partial_mult_transcripts.push_back(record);
    assert(partial_mult_transcripts.size() == n_records + 1);
    z_verify.push_back(pre_trunc);

    return res;
}

template<class T>
void AtlasGsz<T>::init_dotprod_trunc()
{
    maybe_check();
    honest.init_dotprod_trunc();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
    x_verify.push_back(x);
    y_verify.push_back(y);
    honest.prepare_dotprod_trunc(x, y);
}

template<class T>
void AtlasGsz<T>::next_dotprod_trunc()
{
    honest.next_dotprod_trunc();
}

template<class T>
void AtlasGsz<T>::exchange_dotprod_trunc()
{
    honest.exchange_dotprod_trunc();
}

template<class T>
T AtlasGsz<T>::finalize_dotprod_trunc(int length)
{
    size_t n_records = partial_mult_transcripts.size();
    size_t offset = z_verify.size();
    assert(length > 0);
    assert(offset + size_t(length) <= x_verify.size());
    T pre_trunc;
    T res = honest.finalize_dotprod_trunc(length, &pre_trunc);
    PartialMultTranscriptRecord record{};
    record.offset = offset;
    record.length = length;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.has_king_evidence = honest.has_last_king_partial_mult_evidence();
    if (record.has_king_evidence)
        record.king_evidence = honest.get_last_king_partial_mult_evidence();
    assert(record.has_king_evidence == (P.my_num() == 0));
    assert(record.transcript.king == 0);
    assert(record.transcript.e_t - record.transcript.r_t == pre_trunc);
    if (record.has_king_evidence)
    {
        assert(record.king_evidence.king == 0);
        assert(record.king_evidence.king == record.transcript.king);
        assert(record.king_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(record.king_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
    }
    partial_mult_transcripts.push_back(record);
    assert(partial_mult_transcripts.size() == n_records + 1);
    z_verify.push_back(pre_trunc);
    z_verify.insert(z_verify.end(), length - 1, T{0});

    return res;
}

template<class T>
void AtlasGsz<T>::prepare_with_solved_bits(const typename T::open_type& product)
{
    honest.prepare_with_solved_bits(product);
}


/**
 * @brief Verification protocol in GSZ20
 * 
 * @details
 * We only implement compression factor 2, 
 * i.e., the vector is divided into two parts in each iteration.
 * 
 * See https://ia.cr/2020/134 for details.
 */
template<class T>
void AtlasGsz<T>::check()
{
    assert(not have_ultimate_failure_context);
    assert(not ultimate_failure_context.valid);
    validate_dispute_control_state();
#ifndef NDEBUG
    validate_verifiable_registry();
    validate_segment_lifecycle();
    validate_authentication_plan();
    validate_authentication_material();
#endif

#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_check = dispute_control_state.corr;
    auto disp_before_check = dispute_control_state.disp;
#endif

    if (x_verify.empty()) {
        return;
    }

    validate_partial_mult_transcript_coverage();

#ifdef DEBUG_CHECK
    cerr << "check()\n"
         << "x_verify.size() = " << x_verify.size() << '\n'
         << "x_verify.capacity() = " << x_verify.capacity() << '\n';
#endif

#ifdef DEBUG_CHECK_OPENED_VALUES
    typename T::MAC_Check debug_mc;
    vector<typename T::open_type> x_open, y_open, z_open;
    
    debug_mc.POpen(x_open, x_verify, this->P);
    debug_mc.POpen(y_open, y_verify, this->P);
    debug_mc.POpen(z_open, z_verify, this->P);

    cerr << "\nCheck\n" << "x_verify: ";
    for (auto x: x_open) {
        cerr << x << " ";
    }
    cerr << '\n' << "y_verify: ";
    for (auto y: y_open) {
        cerr << y << " ";
    }
    cerr << '\n' << "z_verify: ";
    for (auto z: z_open) {
        cerr << z << " ";
    }
    cerr << '\n';
#endif

    // Not sure if this will increase performance
    // BufferScope _(honest, 2 * x_verify.size());

    de_linearization();
    while (x_verify.size() > 1) {
        dimension_reduction();
    }
    randomization();

#ifndef NDEBUG
    assert(dispute_control_state.initialized
            == dispute_state_was_initialized);
    assert(dispute_control_state.corr == corr_before_check);
    assert(dispute_control_state.disp == disp_before_check);
#endif
    validate_dispute_control_state();
#ifndef NDEBUG
    validate_verifiable_registry();
    validate_segment_lifecycle();
    validate_authentication_plan();
    validate_authentication_material();
#endif
    
    x_verify.clear();
    y_verify.clear();
    z_verify.clear();
    partial_mult_transcripts.clear();
    current_virtual_transcript =
            typename Atlas<T>::PartialMultTranscript{};
    have_current_virtual_transcript = false;
    current_virtual_king_evidence =
            typename Atlas<T>::KingPartialMultEvidence{};
    have_current_virtual_king_evidence = false;
    ultimate_failure_context = UltimateFailureContext{};
    have_ultimate_failure_context = false;

    if (x_verify.capacity() > AtlasConfig::max_before_shrink) {
        x_verify.shrink_to_fit();
        y_verify.shrink_to_fit();
        z_verify.shrink_to_fit();
        partial_mult_transcripts.shrink_to_fit();
        x_verify.reserve(AtlasConfig::max_before_check);
        y_verify.reserve(AtlasConfig::max_before_check);
        z_verify.reserve(AtlasConfig::max_before_check);
        partial_mult_transcripts.reserve(AtlasConfig::max_before_check);
    }
}

template<class T>
void AtlasGsz<T>::de_linearization()
{
    assert(not partial_mult_transcripts.empty());
    z_de_linearized = T{0};
    current_virtual_transcript =
            typename Atlas<T>::PartialMultTranscript{};
    current_virtual_transcript.r_t = T{0};
    current_virtual_transcript.r_2t = T{0};
    current_virtual_transcript.e_2t = T{0};
    current_virtual_transcript.e_t = T{0};
    current_virtual_transcript.r_decomposition =
            zero_double_sharing_decomposition();
    have_current_virtual_transcript = false;
    current_virtual_king_evidence =
            typename Atlas<T>::KingPartialMultEvidence{};
    have_current_virtual_king_evidence = false;

    // Random coin
    typename T::open_type lambda = sample_agreed_challenge();
    typename T::open_type coefficient = 1;

    int batch_king = partial_mult_transcripts.front().transcript.king;
    current_virtual_transcript.king = batch_king;

    if (P.my_num() == batch_king)
    {
        current_virtual_king_evidence.king = batch_king;
        current_virtual_king_evidence.received_e_2t.assign(
                P.num_players(), typename Atlas<T>::share_value_type(0));
        current_virtual_king_evidence.distributed_e_t.assign(
                P.num_players(), typename Atlas<T>::share_value_type(0));
    }

#ifdef DEBUG_DE_LINEARIZATION
    vector<typename T::open_type> logical_coeffs;
    logical_coeffs.reserve(partial_mult_transcripts.size());
#endif

    for (const auto& record : partial_mult_transcripts)
    {
#ifdef DEBUG_DE_LINEARIZATION
        logical_coeffs.push_back(coefficient);
#endif
        assert(record.length > 0);
        assert(record.transcript.king == batch_king);
        assert(record.offset + size_t(record.length) <= x_verify.size());

        for (int j = 0; j < record.length; j++)
        {
            auto& x = x_verify.at(record.offset + j);
            x = x * coefficient;
        }

        z_de_linearized += z_verify.at(record.offset) * coefficient;
        for (int j = 1; j < record.length; j++)
            assert(z_verify.at(record.offset + j) == T{});

        current_virtual_transcript.r_t +=
                record.transcript.r_t * coefficient;
        current_virtual_transcript.r_2t +=
                record.transcript.r_2t * coefficient;
        current_virtual_transcript.e_2t +=
                record.transcript.e_2t * coefficient;
        current_virtual_transcript.e_t +=
                record.transcript.e_t * coefficient;
        add_scaled_double_sharing_decomposition(
                current_virtual_transcript.r_decomposition,
                record.transcript.r_decomposition,
                coefficient);

        if (P.my_num() == batch_king)
        {
            assert(record.has_king_evidence);
            assert(record.king_evidence.king == batch_king);
            assert(record.king_evidence.received_e_2t.size()
                    == size_t(P.num_players()));
            assert(record.king_evidence.distributed_e_t.size()
                    == size_t(P.num_players()));

            for (int j = 0; j < P.num_players(); j++)
            {
                current_virtual_king_evidence.received_e_2t.at(j) +=
                        record.king_evidence.received_e_2t.at(j)
                        * coefficient;
                current_virtual_king_evidence.distributed_e_t.at(j) +=
                        record.king_evidence.distributed_e_t.at(j)
                        * coefficient;
            }
        }
        else
        {
            assert(not record.has_king_evidence);
        }

        coefficient *= lambda;
    }

    have_current_virtual_transcript = true;
    have_current_virtual_king_evidence = (P.my_num() == batch_king);

    z_verify.clear();

    if (z_verify.capacity() > AtlasConfig::max_before_shrink) {
        z_verify.shrink_to_fit();
        z_verify.reserve(AtlasConfig::max_before_check);
    }

#ifdef DEBUG_DE_LINEARIZATION
    typename T::MAC_Check debug_mc;
    vector<typename T::open_type> x_verify_open, y_verify_open;
    debug_mc.POpen(x_verify_open, x_verify, this->P);
    debug_mc.POpen(y_verify_open, y_verify, this->P);
    
    cerr << "\nDe-linearization\n";
    cerr << "logical_coeffs: ";
    for (auto c: logical_coeffs) {
        cerr << c << " ";
    }
    cerr << "\nx_verify: ";
    for (auto x: x_verify_open) {
        cerr << x << " ";
    }
    cerr << "\ny_verify: ";
    for (auto y: y_verify_open) {
        cerr << y << " ";
    }
    cerr << "\nz_de_linearized: " << debug_mc.POpen(z_de_linearized, this->P) << '\n';
#endif

    validate_current_virtual_transcript();
}

/**
 * Protocol 14 and 12 in https://ia.cr/2020/134
 */
template<class T>
void AtlasGsz<T>::dimension_reduction()
{
    assert(have_current_virtual_transcript);
    assert(not x_verify.empty());
    assert(x_verify.size() == y_verify.size());

    int batch_king = current_virtual_transcript.king;
    assert(have_current_virtual_king_evidence
            == (P.my_num() == batch_king));

    validate_current_virtual_transcript();

    auto input_transcript = current_virtual_transcript;
    T input_z = z_de_linearized;
    typename Atlas<T>::KingPartialMultEvidence input_king_evidence{};
    if (P.my_num() == batch_king)
    {
        input_king_evidence = current_virtual_king_evidence;
        assert(input_king_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(input_king_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
    }

    if (x_verify.size() & 1) {
        x_verify.emplace_back(0);
        y_verify.emplace_back(0);
    }
    assert(x_verify.size() == y_verify.size());
    assert((x_verify.size() & 1) == 0);

    int half_size = x_verify.size() / 2;

    // Stored as f_i(x) = f_coeffs[i][0] + f_coeffs[i][1] * x
    vector<array<typename T::clear, 2>> f_coeffs(half_size);
    vector<array<typename T::clear, 2>> g_coeffs(half_size);

    for (int i = 0; i < half_size; ++i) {
        // Compute the coefficients of f_i such that f_i(0) = x_verify[i], f_i(1) = x_verify[i + half_size]
        f_coeffs[i][0] = x_verify[i];
        f_coeffs[i][1] = x_verify[i + half_size] - f_coeffs[i][0];
        // same for g(x)
        g_coeffs[i][0] = y_verify[i];
        g_coeffs[i][1] = y_verify[i + half_size] - g_coeffs[i][0];
    }

#ifndef NDEBUG
    T product_0 = T{0};
    T product_1 = T{0};
    T product_2 = T{0};
    for (int i = 0; i < half_size; ++i)
    {
        auto f0 = f_coeffs[i][0];
        auto f1 = f_coeffs[i][0] + f_coeffs[i][1];
        auto f2 = f_coeffs[i][0] + f_coeffs[i][1] * 2;
        auto g0 = g_coeffs[i][0];
        auto g1 = g_coeffs[i][0] + g_coeffs[i][1];
        auto g2 = g_coeffs[i][0] + g_coeffs[i][1] * 2;
        product_0 += f0 * g0;
        product_1 += f1 * g1;
        product_2 += f2 * g2;
    }
#endif

    honest.init_dotprod();

    // c_0 = a_0 dot b_0
    for (int i = 0; i < half_size; ++i) {
        honest.prepare_dotprod(x_verify[i], y_verify[i]);
    }
    
    x_verify.clear();
    y_verify.clear();
    
    honest.next_dotprod();

    // c_2 = f(2) dot g(2)
    for (int i = 0; i < half_size; ++i) {
        // f_i(2) * g_i(2)
        honest.prepare_dotprod(
            f_coeffs[i][0] + f_coeffs[i][1] * 2,
            g_coeffs[i][0] + g_coeffs[i][1] * 2
        );
    }
    honest.next_dotprod();

    honest.exchange();

    T c_0 = honest.finalize_dotprod(half_size);
    auto transcript_0 = honest.get_last_partial_mult_transcript();
    assert(transcript_0.king == batch_king);
    assert(transcript_0.e_t - transcript_0.r_t == c_0);
    bool has_evidence_0 = honest.has_last_king_partial_mult_evidence();
    assert(has_evidence_0 == (P.my_num() == batch_king));
    typename Atlas<T>::KingPartialMultEvidence evidence_0{};
    if (P.my_num() == batch_king)
    {
        evidence_0 = honest.get_last_king_partial_mult_evidence();
        assert(evidence_0.king == batch_king);
        assert(evidence_0.received_e_2t.size()
                == size_t(P.num_players()));
        assert(evidence_0.distributed_e_t.size()
                == size_t(P.num_players()));
    }

    T c_1 = input_z - c_0;
    typename Atlas<T>::PartialMultTranscript transcript_1{};
    transcript_1.king = batch_king;
    transcript_1.r_t = input_transcript.r_t - transcript_0.r_t;
    transcript_1.r_2t = input_transcript.r_2t - transcript_0.r_2t;
    transcript_1.e_2t = input_transcript.e_2t - transcript_0.e_2t;
    transcript_1.e_t = input_transcript.e_t - transcript_0.e_t;
    transcript_1.r_decomposition = subtract_double_sharing_decomposition(
            input_transcript.r_decomposition,
            transcript_0.r_decomposition);
    assert(transcript_1.e_t - transcript_1.r_t == c_1);

    typename Atlas<T>::KingPartialMultEvidence evidence_1{};
    if (P.my_num() == batch_king)
    {
        evidence_1.king = batch_king;
        evidence_1.received_e_2t.resize(P.num_players());
        evidence_1.distributed_e_t.resize(P.num_players());
        for (int j = 0; j < P.num_players(); j++)
        {
            evidence_1.received_e_2t.at(j) =
                    input_king_evidence.received_e_2t.at(j)
                    - evidence_0.received_e_2t.at(j);
            evidence_1.distributed_e_t.at(j) =
                    input_king_evidence.distributed_e_t.at(j)
                    - evidence_0.distributed_e_t.at(j);
        }

        assert(evidence_1.received_e_2t.at(batch_king)
                == typename Atlas<T>::share_value_type(
                        transcript_1.e_2t));
        assert(evidence_1.distributed_e_t.at(batch_king)
                == typename Atlas<T>::share_value_type(
                        transcript_1.e_t));
    }

    T c_2 = honest.finalize_dotprod(half_size);
    auto transcript_2 = honest.get_last_partial_mult_transcript();
    assert(transcript_2.king == batch_king);
    assert(transcript_2.e_t - transcript_2.r_t == c_2);
    bool has_evidence_2 = honest.has_last_king_partial_mult_evidence();
    assert(has_evidence_2 == (P.my_num() == batch_king));
    typename Atlas<T>::KingPartialMultEvidence evidence_2{};
    if (P.my_num() == batch_king)
    {
        evidence_2 = honest.get_last_king_partial_mult_evidence();
        assert(evidence_2.king == batch_king);
        assert(evidence_2.received_e_2t.size()
                == size_t(P.num_players()));
        assert(evidence_2.distributed_e_t.size()
                == size_t(P.num_players()));
    }

#ifndef NDEBUG
    assert(transcript_0.e_2t == product_0 + transcript_0.r_2t);
    assert(transcript_0.e_t - transcript_0.r_t == c_0);
    assert(transcript_1.e_2t == product_1 + transcript_1.r_2t);
    assert(transcript_1.e_t - transcript_1.r_t == c_1);
    assert(transcript_2.e_2t == product_2 + transcript_2.r_2t);
    assert(transcript_2.e_t - transcript_2.r_t == c_2);
    validate_double_sharing_decomposition(
            transcript_0.r_decomposition,
            transcript_0.r_t,
            transcript_0.r_2t);
    validate_double_sharing_decomposition(
            transcript_1.r_decomposition,
            transcript_1.r_t,
            transcript_1.r_2t);
    validate_double_sharing_decomposition(
            transcript_2.r_decomposition,
            transcript_2.r_t,
            transcript_2.r_2t);

    if (P.my_num() == batch_king)
    {
        int t = ShamirMachine::s().threshold;
        typename Atlas<T>::share_value_type evidence_1_received_secret(0);
        typename Atlas<T>::share_value_type evidence_1_distributed_secret(0);
        for (int i = 0; i < 2 * t + 1; i++)
            evidence_1_received_secret +=
                    evidence_1.received_e_2t.at(i)
                    * Shamir<T>::get_rec_factor(i, 2 * t + 1);
        for (int i = 0; i < t + 1; i++)
            evidence_1_distributed_secret +=
                    evidence_1.distributed_e_t.at(i)
                    * Shamir<T>::get_rec_factor(i, t + 1);
        assert(evidence_1_received_secret
                == evidence_1_distributed_secret);
    }
#endif

    typename T::open_type random_point = sample_agreed_challenge();
    static const typename T::open_type two_inverse =
            (typename T::open_type(2)).invert();
    typename T::open_type one(1);
    typename T::open_type two(2);
    auto L0 = (random_point - one) * (random_point - two)
            * two_inverse;
    auto L1 = random_point * (two - random_point);
    auto L2 = random_point * (random_point - one) * two_inverse;

    assert(L0 + L1 + L2 == one);
#ifndef NDEBUG
    typename T::open_type zero(0);
    auto basis_0 = [&](typename T::open_type q) {
        return (q - one) * (q - two) * two_inverse;
    };
    auto basis_1 = [&](typename T::open_type q) {
        return q * (two - q);
    };
    auto basis_2 = [&](typename T::open_type q) {
        return q * (q - one) * two_inverse;
    };
    assert(basis_0(zero) == one);
    assert(basis_1(zero) == zero);
    assert(basis_2(zero) == zero);
    assert(basis_0(one) == zero);
    assert(basis_1(one) == one);
    assert(basis_2(one) == zero);
    assert(basis_0(two) == zero);
    assert(basis_1(two) == zero);
    assert(basis_2(two) == one);
#endif

    // Evaluate f_i(random_point) and g_i(random_point), just put them in x_verify and y_verify
    vector<T> next_x;
    vector<T> next_y;
    next_x.reserve(half_size);
    next_y.reserve(half_size);
    for (int i = 0; i < half_size; ++i) {
        next_x.push_back(f_coeffs[i][0] + f_coeffs[i][1] * random_point);
        next_y.push_back(g_coeffs[i][0] + g_coeffs[i][1] * random_point);
    }
    x_verify = std::move(next_x);
    y_verify = std::move(next_y);

    z_de_linearized = c_0 * L0 + c_1 * L1 + c_2 * L2;

    typename Atlas<T>::PartialMultTranscript next_virtual_transcript{};
    next_virtual_transcript.king = batch_king;
    next_virtual_transcript.r_t =
            transcript_0.r_t * L0
            + transcript_1.r_t * L1
            + transcript_2.r_t * L2;
    next_virtual_transcript.r_2t =
            transcript_0.r_2t * L0
            + transcript_1.r_2t * L1
            + transcript_2.r_2t * L2;
    next_virtual_transcript.e_2t =
            transcript_0.e_2t * L0
            + transcript_1.e_2t * L1
            + transcript_2.e_2t * L2;
    next_virtual_transcript.e_t =
            transcript_0.e_t * L0
            + transcript_1.e_t * L1
            + transcript_2.e_t * L2;
    next_virtual_transcript.r_decomposition =
            interpolate_double_sharing_decompositions(
                    transcript_0.r_decomposition,
                    transcript_1.r_decomposition,
                    transcript_2.r_decomposition,
                    L0,
                    L1,
                    L2);
    validate_double_sharing_decomposition(
            next_virtual_transcript.r_decomposition,
            next_virtual_transcript.r_t,
            next_virtual_transcript.r_2t);
    current_virtual_transcript = next_virtual_transcript;
    have_current_virtual_transcript = true;

    if (P.my_num() == batch_king)
    {
        typename Atlas<T>::KingPartialMultEvidence next_virtual_evidence{};
        next_virtual_evidence.king = batch_king;
        next_virtual_evidence.received_e_2t.resize(P.num_players());
        next_virtual_evidence.distributed_e_t.resize(P.num_players());

        for (int j = 0; j < P.num_players(); j++)
        {
            next_virtual_evidence.received_e_2t.at(j) =
                    evidence_0.received_e_2t.at(j) * L0
                    + evidence_1.received_e_2t.at(j) * L1
                    + evidence_2.received_e_2t.at(j) * L2;
            next_virtual_evidence.distributed_e_t.at(j) =
                    evidence_0.distributed_e_t.at(j) * L0
                    + evidence_1.distributed_e_t.at(j) * L1
                    + evidence_2.distributed_e_t.at(j) * L2;
        }

        current_virtual_king_evidence = next_virtual_evidence;
        have_current_virtual_king_evidence = true;
    }
    else
    {
        current_virtual_king_evidence =
                typename Atlas<T>::KingPartialMultEvidence{};
        have_current_virtual_king_evidence = false;
    }

#ifdef DEBUG_DIM_REDUCTION
    typename T::MAC_Check debug_mc;
    for (int i = 0; i < half_size; ++i) {
        auto f_0_open = debug_mc.POpen(f_coeffs[i][0], this->P);
        auto f_1_open = debug_mc.POpen(f_coeffs[i][1], this->P);
        auto g_0_open = debug_mc.POpen(g_coeffs[i][0], this->P);
        auto g_1_open = debug_mc.POpen(g_coeffs[i][1], this->P);
        cerr << "f_" << i << "(x) = " << f_0_open << " + " << f_1_open << "x\n"
             << "g_" << i << "(x) = " << g_0_open << " + " << g_1_open << "x\n";
    }
    auto c_0_open = debug_mc.POpen(c_0, this->P);
    auto c_1_open = debug_mc.POpen(c_1, this->P);
    auto c_2_open = debug_mc.POpen(c_2, this->P);
    cerr << "random_point = " << random_point
         << " L0 = " << L0
         << " L1 = " << L1
         << " L2 = " << L2 << '\n';
    cerr << "c_0=" << c_0_open
         << " c_1=" << c_1_open
         << " c_2=" << c_2_open << '\n';

    vector<typename T::open_type> x_verify_open, y_verify_open;
    debug_mc.POpen(x_verify_open, x_verify, this->P);
    debug_mc.POpen(y_verify_open, y_verify, this->P);
    cerr << "x_verify: ";
    for (auto x: x_verify_open) {
        cerr << x << " ";
    }
    cerr << '\n' << "y_verify: ";
    for (auto y: y_verify_open) {
        cerr << y << " ";
    }
    cerr << '\n' << "z_de_linearized: " << debug_mc.POpen(z_de_linearized, this->P) << '\n';
#endif

    validate_current_virtual_transcript();
}

/**
 * Verify the last tuple from dimension_reduction using GSZ20
 * Randomization specialized to compression factor 2.
 */
template<class T>
void AtlasGsz<T>::randomization()
{
    assert(x_verify.size() == 1);
    assert(y_verify.size() == 1);
    assert(have_current_virtual_transcript);
    validate_current_virtual_transcript();

    T x_1 = x_verify.at(0);
    T y_1 = y_verify.at(0);
    T z_1 = z_de_linearized;
    auto transcript_1 = current_virtual_transcript;
    int batch_king = transcript_1.king;
    assert(have_current_virtual_king_evidence
            == (P.my_num() == batch_king));

    typename Atlas<T>::KingPartialMultEvidence evidence_1{};
    if (P.my_num() == batch_king)
    {
        evidence_1 = current_virtual_king_evidence;
        assert(evidence_1.king == batch_king);
        assert(evidence_1.received_e_2t.size()
                == size_t(P.num_players()));
        assert(evidence_1.distributed_e_t.size()
                == size_t(P.num_players()));
    }

    T x_0 = get_random();
    T y_0 = get_random();
    T x_2 = x_1 * 2 - x_0;
    T y_2 = y_1 * 2 - y_0;

    honest.init_mul();
    honest.prepare_mul(x_0, y_0);
    honest.prepare_mul(x_2, y_2);
    honest.exchange();

    T z_0 = honest.finalize_mul();
    auto transcript_0 = honest.get_last_partial_mult_transcript();
    bool has_evidence_0 = honest.has_last_king_partial_mult_evidence();
    assert(has_evidence_0 == (P.my_num() == batch_king));
    typename Atlas<T>::KingPartialMultEvidence evidence_0{};
    if (P.my_num() == batch_king)
    {
        evidence_0 = honest.get_last_king_partial_mult_evidence();
        assert(evidence_0.king == batch_king);
        assert(evidence_0.received_e_2t.size()
                == size_t(P.num_players()));
        assert(evidence_0.distributed_e_t.size()
                == size_t(P.num_players()));
    }

    T z_2 = honest.finalize_mul();
    auto transcript_2 = honest.get_last_partial_mult_transcript();
    bool has_evidence_2 = honest.has_last_king_partial_mult_evidence();
    assert(has_evidence_2 == (P.my_num() == batch_king));
    typename Atlas<T>::KingPartialMultEvidence evidence_2{};
    if (P.my_num() == batch_king)
    {
        evidence_2 = honest.get_last_king_partial_mult_evidence();
        assert(evidence_2.king == batch_king);
        assert(evidence_2.received_e_2t.size()
                == size_t(P.num_players()));
        assert(evidence_2.distributed_e_t.size()
                == size_t(P.num_players()));
    }

    assert(transcript_0.king == batch_king);
    assert(transcript_1.king == batch_king);
    assert(transcript_2.king == batch_king);
    assert(transcript_0.e_2t == x_0 * y_0 + transcript_0.r_2t);
    assert(transcript_0.e_t - transcript_0.r_t == z_0);
    assert(transcript_1.e_2t == x_1 * y_1 + transcript_1.r_2t);
    assert(transcript_1.e_t - transcript_1.r_t == z_1);
    assert(transcript_2.e_2t == x_2 * y_2 + transcript_2.r_2t);
    assert(transcript_2.e_t - transcript_2.r_t == z_2);
    validate_double_sharing_decomposition(
            transcript_0.r_decomposition,
            transcript_0.r_t,
            transcript_0.r_2t);
    validate_double_sharing_decomposition(
            transcript_1.r_decomposition,
            transcript_1.r_t,
            transcript_1.r_2t);
    validate_double_sharing_decomposition(
            transcript_2.r_decomposition,
            transcript_2.r_t,
            transcript_2.r_2t);

    typename T::open_type zero(0);
    typename T::open_type one(1);
    typename T::open_type two(2);
    typename T::open_type q = sample_agreed_challenge();
    while (q == zero || q == one)
        q = sample_agreed_challenge();

    static const typename T::open_type two_inverse =
            (typename T::open_type(2)).invert();
    auto L0 = (q - one) * (q - two) * two_inverse;
    auto L1 = q * (two - q);
    auto L2 = q * (q - one) * two_inverse;
    assert(L0 + L1 + L2 == one);

    T ultimate_x = x_0 * L0 + x_1 * L1 + x_2 * L2;
    T ultimate_y = y_0 * L0 + y_1 * L1 + y_2 * L2;
    T ultimate_z = z_0 * L0 + z_1 * L1 + z_2 * L2;

#ifndef NDEBUG
    assert(ultimate_x == x_0 + (x_1 - x_0) * q);
    assert(ultimate_y == y_0 + (y_1 - y_0) * q);
#endif

    typename Atlas<T>::PartialMultTranscript ultimate_transcript{};
    ultimate_transcript.king = batch_king;
    ultimate_transcript.r_t =
            transcript_0.r_t * L0
            + transcript_1.r_t * L1
            + transcript_2.r_t * L2;
    ultimate_transcript.r_2t =
            transcript_0.r_2t * L0
            + transcript_1.r_2t * L1
            + transcript_2.r_2t * L2;
    ultimate_transcript.e_2t =
            transcript_0.e_2t * L0
            + transcript_1.e_2t * L1
            + transcript_2.e_2t * L2;
    ultimate_transcript.e_t =
            transcript_0.e_t * L0
            + transcript_1.e_t * L1
            + transcript_2.e_t * L2;
    ultimate_transcript.r_decomposition =
            interpolate_double_sharing_decompositions(
                    transcript_0.r_decomposition,
                    transcript_1.r_decomposition,
                    transcript_2.r_decomposition,
                    L0,
                    L1,
                    L2);
    validate_double_sharing_decomposition(
            ultimate_transcript.r_decomposition,
            ultimate_transcript.r_t,
            ultimate_transcript.r_2t);

    current_virtual_transcript = ultimate_transcript;
    have_current_virtual_transcript = true;

    if (P.my_num() == batch_king)
    {
        typename Atlas<T>::KingPartialMultEvidence ultimate_evidence{};
        ultimate_evidence.king = batch_king;
        ultimate_evidence.received_e_2t.resize(P.num_players());
        ultimate_evidence.distributed_e_t.resize(P.num_players());

        for (int j = 0; j < P.num_players(); j++)
        {
            ultimate_evidence.received_e_2t.at(j) =
                    evidence_0.received_e_2t.at(j) * L0
                    + evidence_1.received_e_2t.at(j) * L1
                    + evidence_2.received_e_2t.at(j) * L2;
            ultimate_evidence.distributed_e_t.at(j) =
                    evidence_0.distributed_e_t.at(j) * L0
                    + evidence_1.distributed_e_t.at(j) * L1
                    + evidence_2.distributed_e_t.at(j) * L2;
        }

        current_virtual_king_evidence = ultimate_evidence;
        have_current_virtual_king_evidence = true;
    }
    else
    {
        current_virtual_king_evidence =
                typename Atlas<T>::KingPartialMultEvidence{};
        have_current_virtual_king_evidence = false;
    }

    x_verify.assign(1, ultimate_x);
    y_verify.assign(1, ultimate_y);
    z_de_linearized = ultimate_z;
    validate_current_virtual_transcript();

    vector<T> ultimate_tuple;
    ultimate_tuple.reserve(3);
    ultimate_tuple.push_back(ultimate_x);
    ultimate_tuple.push_back(ultimate_y);
    ultimate_tuple.push_back(ultimate_z);

    auto published_ultimate = broadcast_local_shares(ultimate_tuple);
    assert(published_ultimate.size() == 3);
    auto alpha = classify_degree_t_sharing(published_ultimate.at(0));
    auto beta = classify_degree_t_sharing(published_ultimate.at(1));
    auto gamma = classify_degree_t_sharing(published_ultimate.at(2));

    bool ultimate_tuple_passes =
            alpha.consistent
            && beta.consistent
            && gamma.consistent
            && alpha.value * beta.value == gamma.value;

    if (ultimate_tuple_passes)
    {
        ultimate_failure_context = UltimateFailureContext{};
        have_ultimate_failure_context = false;
        return;
    }

    UltimateFailureKind failure_kind =
            UltimateFailureKind::incorrect_multiplication;
    if (not alpha.consistent)
        failure_kind = UltimateFailureKind::inconsistent_alpha;
    else if (not beta.consistent)
        failure_kind = UltimateFailureKind::inconsistent_beta;
    else if (not gamma.consistent)
        failure_kind = UltimateFailureKind::inconsistent_gamma;

    vector<T> auxiliary_tuple;
    auxiliary_tuple.reserve(4);
    auxiliary_tuple.push_back(current_virtual_transcript.r_t);
    auxiliary_tuple.push_back(current_virtual_transcript.r_2t);
    auxiliary_tuple.push_back(current_virtual_transcript.e_2t);
    auxiliary_tuple.push_back(current_virtual_transcript.e_t);
    auto published_auxiliary = broadcast_local_shares(auxiliary_tuple);
    assert(published_auxiliary.size() == 4);

    UltimateFailureContext context{};
    context.valid = true;
    context.king = current_virtual_transcript.king;
    context.failure_kind = failure_kind;
    context.alpha_t = alpha;
    context.beta_t = beta;
    context.gamma_t = gamma;
    context.delta_t = classify_degree_t_sharing(published_auxiliary.at(0));
    context.delta_2t = collect_degree_2t_vector(published_auxiliary.at(1));
    context.eta_2t = collect_degree_2t_vector(published_auxiliary.at(2));
    context.eta_t = classify_degree_t_sharing(published_auxiliary.at(3));
    context.local_delta_decomposition =
            current_virtual_transcript.r_decomposition;
    validate_double_sharing_decomposition(
            context.local_delta_decomposition,
            current_virtual_transcript.r_t,
            current_virtual_transcript.r_2t);
    auto local_delta_sum = sum_double_sharing_decomposition(
            context.local_delta_decomposition);
    typename T::open_type local_delta_t = local_delta_sum.r_t;
    typename T::open_type local_delta_2t = local_delta_sum.r_2t;
    assert(local_delta_t == context.delta_t.shares.at(P.my_num()));
    assert(local_delta_2t == context.delta_2t.shares.at(P.my_num()));

    int king = context.king;
    vector<octetStream> evidence_streams(P.num_players());
    if (P.my_num() == king)
    {
        assert(have_current_virtual_king_evidence);
        assert(current_virtual_king_evidence.king == king);
        assert(current_virtual_king_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(current_virtual_king_evidence.distributed_e_t.size()
                == size_t(P.num_players()));

        for (const auto& share :
                current_virtual_king_evidence.received_e_2t)
            share.pack(evidence_streams.at(king));
        for (const auto& share :
                current_virtual_king_evidence.distributed_e_t)
            share.pack(evidence_streams.at(king));
    }

    P.Broadcast_Receive(evidence_streams);
    P.Check_Broadcast();

    typename Atlas<T>::KingPartialMultEvidence published_evidence{};
    published_evidence.king = king;
    published_evidence.received_e_2t.resize(P.num_players());
    published_evidence.distributed_e_t.resize(P.num_players());
    for (int i = 0; i < P.num_players(); i++)
        published_evidence.received_e_2t.at(i).unpack(
                evidence_streams.at(king));
    for (int i = 0; i < P.num_players(); i++)
        published_evidence.distributed_e_t.at(i).unpack(
                evidence_streams.at(king));
    assert(not evidence_streams.at(king).left());
    for (int i = 0; i < P.num_players(); i++)
        if (i != king)
            assert(not evidence_streams.at(i).left());

    assert(published_evidence.king == current_virtual_transcript.king);
    assert(published_evidence.received_e_2t.size()
            == size_t(P.num_players()));
    assert(published_evidence.distributed_e_t.size()
            == size_t(P.num_players()));
    if (P.my_num() == king)
    {
        assert(published_evidence.received_e_2t
                == current_virtual_king_evidence.received_e_2t);
        assert(published_evidence.distributed_e_t
                == current_virtual_king_evidence.distributed_e_t);
    }

    for (int i = 0; i < P.num_players(); i++)
    {
        if (published_evidence.received_e_2t.at(i)
                != context.eta_2t.shares.at(i))
            context.received_eta_2t_mismatch_players.push_back(i);

        if (published_evidence.distributed_e_t.at(i)
                != context.eta_t.shares.at(i))
            context.distributed_eta_t_mismatch_players.push_back(i);
    }

    context.published_king_evidence = published_evidence;
    context.has_published_king_evidence = true;
    context.king_received_eta_2t = collect_degree_2t_vector(
            context.published_king_evidence.received_e_2t);
    context.king_distributed_eta_t = classify_degree_t_sharing(
            context.published_king_evidence.distributed_e_t);
    context.decision = diagnose_ultimate_failure(context);
    if (context.decision.action == UltimateFailureAction::check_double_rand)
    {
        context.check_double_rand_context =
                run_check_double_rand_diagnosis(
                        context.local_delta_decomposition);
        context.has_check_double_rand_context = true;
        assert(context.check_double_rand_context.valid);
        assert(context.check_double_rand_context.decision.valid);
    }
    context.fault_localization =
            derive_fault_localization_outcome(context);
    assert(context.fault_localization.valid);
    assert(context.fault_localization.action
            != FaultLocalizationAction::none);
    context.fault_application =
            apply_fault_localization_outcome(
                    context.fault_localization);
    assert(context.fault_application.valid);
    if (context.fault_application.action
            == FaultLocalizationApplicationAction::
                pending_analyze_sharing)
    {
        context.analyze_sharing_request =
                build_analyze_sharing_request(context);
        context.has_analyze_sharing_request = true;
        assert(context.analyze_sharing_request.valid);
        validate_analyze_sharing_request(
                context.analyze_sharing_request);
    }
    else
    {
        assert(not context.has_analyze_sharing_request);
        assert(not context.analyze_sharing_request.valid);
        validate_analyze_sharing_request(
                context.analyze_sharing_request);
    }

    ultimate_failure_context = context;
    have_ultimate_failure_context = true;

    assert(have_ultimate_failure_context);
    assert(ultimate_failure_context.valid);
    assert(ultimate_failure_context.decision.valid);
    throw mac_fail(
            "AtlasGsz: ultimate tuple failed; failure transcript retained");
}

template <class T>
inline void AtlasGsz<T>::check_opened_values()
{
    auto& values = local_mc_2t.stored_values;
    auto& secrets = local_mc_2t.stored_secrets;
    if (values.size() == 0) {
        return;
    }
    assert(values.size() == secrets.size());
    auto r = local_mc_2t.POpen(get_random(), this->P);
    vector<T> random_coeffs(values.size());
    random_coeffs[0] = r;
    for (size_t i = 1; i < values.size(); ++i) {
        random_coeffs[i] = random_coeffs[i - 1] * r;
    }
    auto value_combined = std::inner_product(values.begin(), values.end(), random_coeffs.begin(), T{0});
    values.clear();
    auto secret_combined = std::inner_product(secrets.begin(), secrets.end(), random_coeffs.begin(), T{0});
    secrets.clear();

    // gf2n has no POpen for single element
    malicious_mc.init_open(P, 1);
    malicious_mc.prepare_open(secret_combined);
    malicious_mc.exchange(P);
    auto secret_combined_open = malicious_mc.finalize_open();

    if (value_combined != secret_combined_open) {
        throw mac_fail("AtlasGsz: check_opened_values failed");
    }
}

#endif /* PROTOCOLS_ATLASGSZ_HPP_ */
