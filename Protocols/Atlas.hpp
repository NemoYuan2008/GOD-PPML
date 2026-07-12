/*
 * Atlas.hpp
 *
 */

/**
 * TODO: Some Optimizations that can be done:
 *
 * 1. Use lazy mod for prepare_dotprod_trunc and prepare_dotprod
 * 2. Pass-by-value for T
 */


#ifndef PROTOCOLS_ATLAS_HPP_
#define PROTOCOLS_ATLAS_HPP_

#include "Atlas.h"
#include "AtlasConfig.h"


template<class T>
Atlas<T>::~Atlas()
{
#ifdef VERBOSE
    if (not double_sharings.empty())
        cerr << double_sharings.size() << " double sharings left" << endl;
#endif
}

template<class T>
typename Atlas<T>::DoubleSharingDecomposition
Atlas<T>::zero_double_sharing_decomposition() const
{
    DoubleSharingDecomposition res{};
    res.dealer_components.resize(P.num_players());
    res.own_dealer_evidence.r_t_shares.assign(
            P.num_players(), share_value_type{});
    res.own_dealer_evidence.r_2t_shares.assign(
            P.num_players(), share_value_type{});
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
Atlas<T>::sum_double_sharing_decomposition(
        const DoubleSharingDecomposition& decomposition) const
{
    assert(decomposition.dealer_components.size() == size_t(P.num_players()));
    assert(decomposition.own_dealer_evidence.r_t_shares.size()
            == size_t(P.num_players()));
    assert(decomposition.own_dealer_evidence.r_2t_shares.size()
            == size_t(P.num_players()));
    DealerDoubleSharingContribution sum{};
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
void Atlas<T>::validate_double_sharing_decomposition(
        const DoubleSharingDecomposition& decomposition,
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
void Atlas<T>::validate_randoms_provenance(
        const typename Shamir<T>::RandomsProvenance& provenance,
        const vector<T>& outputs,
        const vector<vector<T>>& dealer_contributions) const
{
    auto malformed = [] (const char* reason) {
        throw invalid_argument(
                string("Atlas: malformed Shamir random provenance: ")
                + reason);
    };
    const size_t n = P.num_players();
    if (n == 0 || outputs.empty() || outputs.size() % n != 0)
        malformed("invalid output count");
    if (dealer_contributions.size() != outputs.size())
        malformed("dealer contribution count mismatch");
    if (provenance.source_groups.size() != outputs.size() / n)
        malformed("input generation group count mismatch");
    if (provenance.output_derivations.size() != outputs.size())
        malformed("output derivation count mismatch");

    for (size_t group_index = 0;
            group_index < provenance.source_groups.size(); group_index++)
    {
        const auto& group = provenance.source_groups.at(group_index);
        if (group.input_batch_ordinal != group_index)
            malformed("non-canonical input generation ordinal");
        if (group.sources.size() != n)
            malformed("source group is not an exact all-dealer group");
        for (size_t dealer = 0; dealer < n; dealer++)
        {
            const auto& source = group.sources.at(dealer);
            if (source.dealer != int(dealer))
                malformed("non-canonical dealer ordering");
            if (source.input_batch_ordinal != group_index)
                malformed("source input generation ordinal mismatch");
        }
    }

    for (size_t output_index = 0; output_index < outputs.size();
            output_index++)
    {
        const auto& derivation =
                provenance.output_derivations.at(output_index);
        const size_t expected_group = output_index / n;
        if (derivation.output_ordinal != output_index)
            malformed("non-canonical output ordinal");
        if (derivation.input_batch_ordinal != expected_group)
            malformed("output input generation ordinal mismatch");
        if (derivation.terms.size() != n)
            malformed("output derivation is not an exact all-dealer sum");
        if (dealer_contributions.at(output_index).size() != n)
            malformed("dealer contribution width mismatch");

        const auto& sources =
                provenance.source_groups.at(expected_group).sources;
        T evaluated{};
        for (size_t term_index = 0; term_index < n; term_index++)
        {
            const auto& term = derivation.terms.at(term_index);
            if (term.source_index != term_index)
                malformed("non-canonical source-term ordering");
            T contribution = term.coefficient
                    * sources.at(term.source_index).local_share;
            if (contribution
                    != dealer_contributions.at(output_index).at(term_index))
                malformed("source term disagrees with dealer contribution");
            evaluated += contribution;
        }
        if (evaluated != outputs.at(output_index))
            malformed("derivation does not evaluate to output");
    }
}

template<class T>
void Atlas<T>::validate_paired_double_sharing_provenance(
        const DoubleSharingProducerProvenance& provenance) const
{
    auto malformed = [] (const char* reason) {
        throw invalid_argument(
                string("Atlas: unpaired DoubleRand provenance: ") + reason);
    };
    const auto& degree_t = provenance.degree_t;
    const auto& degree_2t = provenance.degree_2t;
    if (degree_t.source_groups.size() != degree_2t.source_groups.size())
        malformed("input generation group count mismatch");
    if (degree_t.output_derivations.size()
            != degree_2t.output_derivations.size())
        malformed("output derivation count mismatch");

    for (size_t group_index = 0;
            group_index < degree_t.source_groups.size(); group_index++)
    {
        const auto& t_group = degree_t.source_groups.at(group_index);
        const auto& two_t_group = degree_2t.source_groups.at(group_index);
        if (t_group.input_batch_ordinal
                != two_t_group.input_batch_ordinal)
            malformed("input generation ordinal mismatch");
        if (t_group.sources.size() != two_t_group.sources.size())
            malformed("source count mismatch");
        for (size_t source_index = 0;
                source_index < t_group.sources.size(); source_index++)
        {
            const auto& t_source = t_group.sources.at(source_index);
            const auto& two_t_source =
                    two_t_group.sources.at(source_index);
            if (t_source.dealer != two_t_source.dealer)
                malformed("dealer ordering mismatch");
            if (t_source.input_batch_ordinal
                    != two_t_source.input_batch_ordinal)
                malformed("source input generation ordinal mismatch");
        }
    }

    for (size_t output_index = 0;
            output_index < degree_t.output_derivations.size(); output_index++)
    {
        const auto& t_derivation =
                degree_t.output_derivations.at(output_index);
        const auto& two_t_derivation =
                degree_2t.output_derivations.at(output_index);
        if (t_derivation.output_ordinal != two_t_derivation.output_ordinal)
            malformed("output ordinal mismatch");
        if (t_derivation.input_batch_ordinal
                != two_t_derivation.input_batch_ordinal)
            malformed("output input generation ordinal mismatch");
        if (t_derivation.terms.size() != two_t_derivation.terms.size())
            malformed("public coefficient layout width mismatch");
        for (size_t term_index = 0;
                term_index < t_derivation.terms.size(); term_index++)
        {
            const auto& t_term = t_derivation.terms.at(term_index);
            const auto& two_t_term =
                    two_t_derivation.terms.at(term_index);
            if (t_term.source_index != two_t_term.source_index)
                malformed("source-term ordering mismatch");
            if (t_term.coefficient != two_t_term.coefficient)
                malformed("public coefficient mismatch");
        }
    }
}

template<class T>
void Atlas<T>::validate_double_sharing_material_provenance(
        const DoubleSharingMaterial& material) const
{
    if (not material.producer_reference.producer_provenance)
        throw invalid_argument(
                "Atlas: DoubleRand material lacks producer provenance");
    const auto& paired = *material.producer_reference.producer_provenance;
    if (material.producer_reference.producer_output_ordinal
            >= paired.degree_t.output_derivations.size())
        throw invalid_argument(
                "Atlas: DoubleRand producer output ordinal is out of range");

    auto evaluate = [&] (
            const typename Shamir<T>::RandomsProvenance& provenance,
            bool degree_two_t) {
        const auto& derivation = provenance.output_derivations.at(
                material.producer_reference.producer_output_ordinal);
        if (derivation.output_ordinal
                != material.producer_reference.producer_output_ordinal)
            throw invalid_argument(
                    "Atlas: DoubleRand material/output provenance mismatch");
        const auto& sources = provenance.source_groups.at(
                derivation.input_batch_ordinal).sources;
        T result{};
        for (size_t dealer = 0; dealer < derivation.terms.size(); dealer++)
        {
            const auto& term = derivation.terms.at(dealer);
            T contribution = term.coefficient
                    * sources.at(term.source_index).local_share;
            const auto& existing =
                    material.decomposition.dealer_components.at(dealer);
            if (contribution != (degree_two_t ? existing.r_2t : existing.r_t))
                throw invalid_argument(
                        "Atlas: DoubleRand source term/decomposition mismatch");
            result += contribution;
        }
        return result;
    };

    if (evaluate(paired.degree_t, false) != material.r_t)
        throw invalid_argument(
                "Atlas: degree-t DoubleRand derivation mismatch");
    if (evaluate(paired.degree_2t, true) != material.r_2t)
        throw invalid_argument(
                "Atlas: degree-2t DoubleRand derivation mismatch");
}

template<class T>
typename Atlas<T>::DoubleSharingMaterial Atlas<T>::get_double_sharing()
{
    if (double_sharings.empty())
    {
        SeededPRNG G;
        PRNG G2 = G;
        vector<vector<T>> random_dealer_contributions;
        vector<vector<T>> random2_dealer_contributions;
        vector<vector<share_value_type>> random_own_dealer_contributions;
        vector<vector<share_value_type>> random2_own_dealer_contributions;
        typename Shamir<T>::RandomsProvenance random_provenance;
        typename Shamir<T>::RandomsProvenance random2_provenance;
        auto random = shamir.get_randoms(G, 0,
                &random_dealer_contributions,
                &random_own_dealer_contributions,
                &random_provenance);
        auto random2 =
                shamir2.get_randoms(G2, 0,
                        &random2_dealer_contributions,
                        &random2_own_dealer_contributions,
                        &random2_provenance);
        assert(random.size() == random2.size());
        assert(random.size() == random_dealer_contributions.size());
        assert(random2.size() == random2_dealer_contributions.size());
        assert(random.size() == random_own_dealer_contributions.size());
        assert(random2.size() == random2_own_dealer_contributions.size());
        assert(random.size() % P.num_players() == 0);
        validate_randoms_provenance(random_provenance, random,
                random_dealer_contributions);
        validate_randoms_provenance(random2_provenance, random2,
                random2_dealer_contributions);
        auto paired_provenance =
                make_shared<DoubleSharingProducerProvenance>();
        paired_provenance->degree_t = std::move(random_provenance);
        paired_provenance->degree_2t = std::move(random2_provenance);
        validate_paired_double_sharing_provenance(*paired_provenance);
        vector<DoubleSharingMaterial> candidate_materials;
        candidate_materials.reserve(random.size());
        for (size_t i = 0; i < random.size(); i++)
        {
            DoubleSharingMaterial material{};
            material.r_t = random.at(i);
            material.r_2t = random2.at(i);
            material.decomposition = zero_double_sharing_decomposition();
            material.producer_reference.producer_provenance =
                    paired_provenance;
            material.producer_reference.producer_output_ordinal = i;
            assert(random_dealer_contributions.at(i).size()
                    == size_t(P.num_players()));
            assert(random2_dealer_contributions.at(i).size()
                    == size_t(P.num_players()));
            assert(random_own_dealer_contributions.at(i).size()
                    == size_t(P.num_players()));
            assert(random2_own_dealer_contributions.at(i).size()
                    == size_t(P.num_players()));
            for (int dealer = 0; dealer < P.num_players(); dealer++)
            {
                material.decomposition.dealer_components.at(dealer).r_t =
                        random_dealer_contributions.at(i).at(dealer);
                material.decomposition.dealer_components.at(dealer).r_2t =
                        random2_dealer_contributions.at(i).at(dealer);
            }
            for (int recipient = 0; recipient < P.num_players();
                    recipient++)
            {
                material.decomposition.own_dealer_evidence
                    .r_t_shares.at(recipient) =
                        random_own_dealer_contributions.at(i).at(recipient);
                material.decomposition.own_dealer_evidence
                    .r_2t_shares.at(recipient) =
                        random2_own_dealer_contributions.at(i).at(recipient);
            }
            validate_double_sharing_decomposition(
                    material.decomposition, material.r_t, material.r_2t);
            validate_double_sharing_material_provenance(material);
            candidate_materials.push_back(std::move(material));
        }
        double_sharings = std::move(candidate_materials);
    }

    auto res = double_sharings.back();
    double_sharings.pop_back();
    return res;
}

template<class T>
typename Atlas<T>::DoubleSharingProvenanceTestSummary
Atlas<T>::run_double_sharing_provenance_test()
{
    if (not double_sharings.empty())
        throw logic_error(
                "Atlas: producer-provenance test requires an empty DoubleRand buffer");

    auto sampled_material = get_double_sharing();
    const auto provenance =
            sampled_material.producer_reference.producer_provenance;
    if (not provenance || provenance->degree_t.source_groups.size() < 2)
        throw logic_error(
                "Atlas: producer-provenance test requires several input generations");
    validate_paired_double_sharing_provenance(*provenance);

    vector<bool> seen(provenance->degree_t.output_derivations.size(), false);
    auto validate_once = [&] (const DoubleSharingMaterial& material) {
        if (material.producer_reference.producer_provenance != provenance)
            throw logic_error(
                    "Atlas: buffered outputs do not share producer provenance");
        validate_double_sharing_decomposition(
                material.decomposition, material.r_t, material.r_2t);
        validate_double_sharing_material_provenance(material);
        if (seen.at(material.producer_reference.producer_output_ordinal))
            throw logic_error(
                    "Atlas: duplicate producer output ordinal");
        seen.at(material.producer_reference.producer_output_ordinal) = true;
    };
    validate_once(sampled_material);
    for (const auto& material : double_sharings)
        validate_once(material);
    for (bool output_seen : seen)
        if (not output_seen)
            throw logic_error(
                    "Atlas: missing buffered producer output ordinal");

    const size_t retained_buffer_size = double_sharings.size();
    vector<size_t> retained_output_ordinals;
    retained_output_ordinals.reserve(retained_buffer_size);
    for (const auto& material : double_sharings)
    {
        if (material.producer_reference.producer_provenance != provenance)
            throw logic_error(
                    "Atlas: unexpected producer provenance before rejection test");
        retained_output_ordinals.push_back(
                material.producer_reference.producer_output_ordinal);
    }
    DoubleSharingProducerProvenance malformed = *provenance;
    malformed.degree_2t.output_derivations.at(0).terms.at(0).coefficient +=
            share_value_type(1);
    bool rejected = false;
    try
    {
        validate_paired_double_sharing_provenance(malformed);
    }
    catch (const invalid_argument&)
    {
        rejected = true;
    }
    if (not rejected || double_sharings.size() != retained_buffer_size)
        throw logic_error(
                "Atlas: malformed producer provenance was not rejected atomically");
    for (size_t i = 0; i < double_sharings.size(); i++)
        if (double_sharings.at(i).producer_reference.producer_provenance
                    != provenance
                || double_sharings.at(i).producer_reference
                        .producer_output_ordinal
                        != retained_output_ordinals.at(i))
            throw logic_error(
                    "Atlas: rejected provenance changed the DoubleRand buffer");

    const size_t sampled_output_ordinal =
            sampled_material.producer_reference.producer_output_ordinal;
    const size_t original_buffer_size = retained_buffer_size + 1;
    if (original_buffer_size
            != provenance->degree_t.output_derivations.size()
            || sampled_output_ordinal != original_buffer_size - 1)
        throw logic_error(
                "Atlas: sampled material was not the original LIFO tail");
    double_sharings.push_back(std::move(sampled_material));
    if (double_sharings.size() != original_buffer_size)
        throw logic_error(
                "Atlas: failed to restore the original DoubleRand buffer size");

    vector<bool> restored_outputs(original_buffer_size, false);
    for (size_t i = 0; i < double_sharings.size(); i++)
    {
        const auto& material = double_sharings.at(i);
        if (material.producer_reference.producer_provenance != provenance
                || material.producer_reference.producer_output_ordinal != i
                || restored_outputs.at(
                        material.producer_reference.producer_output_ordinal))
            throw logic_error(
                    "Atlas: failed to restore the original DoubleRand buffer order");
        restored_outputs.at(
                material.producer_reference.producer_output_ordinal) = true;
    }
    for (bool output_restored : restored_outputs)
        if (not output_restored)
            throw logic_error(
                    "Atlas: restored DoubleRand buffer is missing a producer output");
    if (double_sharings.back().producer_reference.producer_provenance
                != provenance
            || double_sharings.back().producer_reference
                    .producer_output_ordinal
                    != sampled_output_ordinal)
        throw logic_error(
                "Atlas: sampled material was not restored to the LIFO tail");

    DoubleSharingProvenanceTestSummary summary;
    summary.input_generation_groups =
            provenance->degree_t.source_groups.size();
    summary.output_derivations =
            provenance->degree_t.output_derivations.size();
    summary.sources_per_group =
            provenance->degree_t.source_groups.front().sources.size();
    return summary;
}

template<class T>
void Atlas<T>::initialize_reconstruction_factors()
{
    int t = ShamirMachine::s().threshold;
    if (reconstruction.empty())
        for (int i = 0; i < 2 * t + 1; i++)
            reconstruction.push_back(Shamir<T>::get_rec_factor(i, 2 * t + 1));
    if (reconstruction_t.empty())
        for (int i = 0; i < t + 1; i++)
            reconstruction_t.push_back(Shamir<T>::get_rec_factor(i, t + 1));
}

template<class T>
vector<int> Atlas<T>::canonical_fixed_king_special_sharing_support(
        int king) const
{
    if (king < 0 || king >= P.num_players())
        throw out_of_range("invalid Atlas fixed king");

    int t = ShamirMachine::s().threshold;
    vector<int> support{king};
    for (int party = 0;
            party < P.num_players() && support.size() < size_t(t + 1);
            party++)
        if (party != king)
            support.push_back(party);
    sort(support.begin(), support.end());
    validate_fixed_king_special_sharing_support(king, support);
    return support;
}

template<class T>
void Atlas<T>::validate_fixed_king_special_sharing_support(
        int king, const vector<int>& support) const
{
    int t = ShamirMachine::s().threshold;
    if (king < 0 || king >= P.num_players())
        throw invalid_argument(
                "Atlas fixed-king special-sharing support has an invalid king");
    if (P.num_players() != 2 * t + 1)
        throw invalid_argument(
                "Atlas fixed-king special sharing requires n = 2t + 1");
    if (support.size() != size_t(t + 1))
        throw invalid_argument(
                "Atlas fixed-king special-sharing support must have size t + 1");

    vector<bool> seen(P.num_players(), false);
    bool contains_king = false;
    int previous = -1;
    for (int party : support)
    {
        if (party < 0 || party >= P.num_players())
            throw invalid_argument(
                    "Atlas fixed-king special-sharing support member is out of range");
        if (seen.at(party))
            throw invalid_argument(
                    "Atlas fixed-king special-sharing support contains a duplicate member");
        if (party <= previous)
            throw invalid_argument(
                    "Atlas fixed-king special-sharing support is not in canonical numeric order");
        seen.at(party) = true;
        contains_king |= party == king;
        previous = party;
    }
    if (not contains_king)
        throw invalid_argument(
                "Atlas fixed-king special-sharing support omits the king");

    vector<int> expected{king};
    for (int party = 0;
            party < P.num_players() && expected.size() < size_t(t + 1);
            party++)
        if (party != king)
            expected.push_back(party);
    sort(expected.begin(), expected.end());
    if (support != expected)
        throw invalid_argument(
                "Atlas fixed-king special-sharing support is not the deterministic canonical set");
}

template<class T>
bool Atlas<T>::fixed_king_special_sharing_support_contains(int party) const
{
    return find(fixed_king_special_sharing_support.begin(),
            fixed_king_special_sharing_support.end(), party)
            != fixed_king_special_sharing_support.end();
}

template<class T>
vector<typename Atlas<T>::share_value_type>
Atlas<T>::make_fixed_king_special_sharing(
        const share_value_type& secret,
        const vector<int>& support) const
{
    validate_fixed_king_special_sharing_support(fixed_king, support);

    vector<int> interpolation_points{-1};
    for (int party = 0; party < P.num_players(); party++)
        if (find(support.begin(), support.end(), party) == support.end())
            interpolation_points.push_back(party);
    if (interpolation_points.size()
            != size_t(ShamirMachine::s().threshold + 1))
        throw logic_error(
                "Atlas fixed-king special-sharing interpolation has the wrong number of points");

    vector<share_value_type> sharing(P.num_players(), share_value_type{});
    for (int party : support)
    {
        auto factors = Shamir<T>::get_rec_factors(
                interpolation_points, party);
        sharing.at(party) = secret * factors.front();
    }
    return sharing;
}

template<class T>
typename Atlas<T>::share_value_type Atlas<T>::reconstruct_received_e_2t(
        const vector<typename Atlas<T>::share_value_type>& sharing) const
{
    int t = ShamirMachine::s().threshold;
    assert(sharing.size() == size_t(P.num_players()));
    assert(reconstruction.size() >= size_t(2 * t + 1));
    share_value_type res{};
    for (int i = 0; i < 2 * t + 1; i++)
        res += sharing.at(i) * reconstruction.at(i);
    return res;
}

template<class T>
typename Atlas<T>::share_value_type Atlas<T>::reconstruct_distributed_e_t(
        const vector<typename Atlas<T>::share_value_type>& sharing,
        const vector<int>& support) const
{
    assert(sharing.size() == size_t(P.num_players()));
    validate_fixed_king_special_sharing_support(fixed_king, support);

    share_value_type res{};
    auto factors = Shamir<T>::get_rec_factors(support);
    for (size_t i = 0; i < support.size(); i++)
        res += sharing.at(support.at(i)) * factors.at(i);
    return res;
}

template<class T>
void Atlas<T>::validate_fixed_king_special_sharing_evidence(
        const PartialMultTranscript& transcript,
        const KingPartialMultEvidence& evidence) const
{
    validate_fixed_king_special_sharing_support(
            transcript.king, transcript.special_sharing_support);
    if (P.my_num() != transcript.king || evidence.king != transcript.king)
        throw logic_error(
                "Atlas fixed-king special-sharing evidence has the wrong owner");
    if (evidence.received_e_2t.size() != size_t(P.num_players())
            || evidence.distributed_e_t.size() != size_t(P.num_players()))
        throw logic_error(
                "Atlas fixed-king special-sharing evidence has the wrong width");

    for (int party = 0; party < P.num_players(); party++)
    {
        const bool in_support = find(
                transcript.special_sharing_support.begin(),
                transcript.special_sharing_support.end(), party)
                != transcript.special_sharing_support.end();
        if (not in_support
                && evidence.distributed_e_t.at(party) != share_value_type{})
            throw logic_error(
                    "Atlas fixed-king special sharing is nonzero outside its support");

        auto factors = Shamir<T>::get_rec_factors(
                transcript.special_sharing_support, party);
        share_value_type expected{};
        for (size_t i = 0;
                i < transcript.special_sharing_support.size(); i++)
            expected += evidence.distributed_e_t.at(
                    transcript.special_sharing_support.at(i))
                    * factors.at(i);
        if (expected != evidence.distributed_e_t.at(party))
            throw logic_error(
                    "Atlas fixed-king special sharing exceeds degree t");
    }

    const auto received_secret =
            reconstruct_received_e_2t(evidence.received_e_2t);
    const auto distributed_secret = reconstruct_distributed_e_t(
            evidence.distributed_e_t,
            transcript.special_sharing_support);
    if (received_secret != distributed_secret)
        throw logic_error(
                "Atlas fixed-king special sharing represents the wrong secret");

    share_value_type local_e_2t = transcript.e_2t;
    share_value_type local_e_t = transcript.e_t;
    if (evidence.received_e_2t.at(transcript.king) != local_e_2t
            || evidence.distributed_e_t.at(transcript.king) != local_e_t)
        throw logic_error(
                "Atlas fixed-king special-sharing evidence disagrees with the concrete transcript");
}

template<class T>
void Atlas<T>::build_public_opening_king_evidence(
        size_t transcript_index,
        const share_value_type& opened_value)
{
    assert(P.my_num() == 0);
    initialize_reconstruction_factors();
    assert(transcript_index < pending_partial_mult_operations.size());
    if (pending_king_partial_mult_evidence.empty())
        pending_king_partial_mult_evidence.resize(
                pending_partial_mult_operations.size());
    assert(pending_king_partial_mult_evidence.size()
            == pending_partial_mult_operations.size());

    auto& evidence = pending_king_partial_mult_evidence.at(transcript_index);
    evidence.received_e_2t =
            local_mc_2t.get_recorded_received_sharing(transcript_index);
    evidence.distributed_e_t.assign(P.num_players(), opened_value);
    evidence.king = 0;

    assert(evidence.received_e_2t.size() == size_t(P.num_players()));
    assert(evidence.distributed_e_t.size() == size_t(P.num_players()));
    assert(evidence.king == 0);
    assert(reconstruct_received_e_2t(evidence.received_e_2t)
            == opened_value);
    const auto support =
            canonical_fixed_king_special_sharing_support(0);
    assert(reconstruct_distributed_e_t(
            evidence.distributed_e_t, support)
            == opened_value);

    const auto& transcript =
            pending_partial_mult_operations.at(transcript_index).transcript;
    share_value_type local_e_2t = transcript.e_2t;
    share_value_type local_e_t = transcript.e_t;
    assert(evidence.received_e_2t.at(0) == local_e_2t);
    assert(evidence.distributed_e_t.at(0) == local_e_t);
}

template<class T>
void Atlas<T>::init(Preprocessing<T>& prep, typename T::MAC_Check& MC)
{
    this->prep = &prep;
    (void) MC;
}

template<class T>
void Atlas<T>::init_mul()
{
    assert(next_partial_mult_transcript == pending_partial_mult_operations.size());
    assert(pending_king_partial_mult_evidence.empty()
            || pending_king_partial_mult_evidence.size()
                    == next_partial_mult_transcript);
    oss.reset();
    oss2.reset();
    masks.clear();
    base_king = next_king;
    pending_partial_mult_operations.clear();
    pending_king_partial_mult_evidence.clear();
    fixed_king_special_e_t_shares.clear();
    next_partial_mult_transcript = 0;
    have_last_partial_mult_transcript = false;
    have_last_king_partial_mult_evidence = false;
}

template<class T>
void Atlas<T>::prepare_mul(const T& x, const T& y, int)
{
    prepare(x * y);
}

template<class T>
void Atlas<T>::prepare(const typename T::open_type& product)
{
    auto r = get_double_sharing();
    int king = fixed_king_enabled ? fixed_king : next_king;
    T e_2t = product + r.r_2t;
    e_2t.pack(oss2[king]);
    if (not fixed_king_enabled)
        next_king = (next_king + 1) % P.num_players();
    masks.push_back(r.r_t);

    PartialMultTranscript transcript{};
    transcript.r_t = r.r_t;
    transcript.r_2t = r.r_2t;
    transcript.e_2t = e_2t;
    transcript.king = king;
    if (fixed_king_enabled)
    {
        validate_fixed_king_special_sharing_support(
                king, fixed_king_special_sharing_support);
        transcript.special_sharing_support =
                fixed_king_special_sharing_support;
    }
    transcript.r_decomposition = r.decomposition;
    validate_double_sharing_decomposition(
            transcript.r_decomposition, transcript.r_t, transcript.r_2t);
    PendingPartialMultOperation operation{};
    operation.transcript = transcript;
    operation.producer_reference = r.producer_reference;
    pending_partial_mult_operations.push_back(std::move(operation));
}

template<class T>
void Atlas<T>::exchange()
{
    if (fixed_king_enabled)
        validate_fixed_king_special_sharing_support(
                fixed_king, fixed_king_special_sharing_support);
    P.send_receive_all(oss2, oss);
    oss.mine = oss2.mine;
    assert(pending_partial_mult_operations.size() == masks.size());

    int t = ShamirMachine::s().threshold;
    initialize_reconstruction_factors();

    if (fixed_king_enabled)
    {
        vector<octetStream> special_sharing_outgoing(P.num_players());
        vector<octetStream> special_sharing_incoming;
        vector<vector<bool>> special_sharing_channels(
                P.num_players(), vector<bool>(P.num_players(), false));
        for (int recipient : fixed_king_special_sharing_support)
            if (recipient != fixed_king)
                special_sharing_channels.at(fixed_king).at(recipient) = true;

        if (P.my_num() == fixed_king)
        {
            assert(pending_king_partial_mult_evidence.empty());

            for (size_t j = 0; j < masks.size(); j++)
            {
                typename T::open_type e{};
                KingPartialMultEvidence evidence{};
                evidence.received_e_2t.resize(P.num_players());
                evidence.king = fixed_king;
                for (int i = 0; i < P.num_players(); i++)
                {
                    auto tmp = oss[i].template get<T>();
                    evidence.received_e_2t.at(i) = tmp;
                    if (i < 2 * t + 1)
                        e += evidence.received_e_2t.at(i) * reconstruction.at(i);
                }
                assert(evidence.received_e_2t.size() == size_t(P.num_players()));
                assert(evidence.king == fixed_king);
                assert(reconstruct_received_e_2t(evidence.received_e_2t) == e);
                evidence.distributed_e_t = make_fixed_king_special_sharing(
                        e, fixed_king_special_sharing_support);
                for (int recipient : fixed_king_special_sharing_support)
                    if (recipient != fixed_king)
                        evidence.distributed_e_t.at(recipient).pack(
                                special_sharing_outgoing.at(recipient));
                pending_king_partial_mult_evidence.push_back(evidence);
            }
            assert(pending_king_partial_mult_evidence.size() == masks.size());
        }
        else
            assert(pending_king_partial_mult_evidence.empty());

        P.send_receive_all(special_sharing_channels,
                special_sharing_outgoing, special_sharing_incoming);

        fixed_king_special_e_t_shares.reserve(masks.size());
        for (size_t j = 0; j < masks.size(); j++)
        {
            if (P.my_num() == fixed_king)
                fixed_king_special_e_t_shares.push_back(T(
                        pending_king_partial_mult_evidence.at(j)
                                .distributed_e_t.at(fixed_king)));
            else if (fixed_king_special_sharing_support_contains(P.my_num()))
                fixed_king_special_e_t_shares.push_back(
                        special_sharing_incoming.at(fixed_king)
                                .template get<T>());
            else
                fixed_king_special_e_t_shares.push_back(T{0});
        }
        if (P.my_num() != fixed_king
                && fixed_king_special_sharing_support_contains(P.my_num())
                && not special_sharing_incoming.at(fixed_king).done())
            throw logic_error(
                    "Atlas fixed-king special-sharing stream has trailing data");
    }
    else
    {
        resharing.reset_all(P);
        for (size_t j = P.get_player(-base_king); j < masks.size();
                j += P.num_players())
        {
            typename T::open_type e;
            for (int i = 0; i < 2 * t + 1; i++)
            {
                auto tmp = oss[i].template get<T>();
                e += tmp * reconstruction.at(i);
            }
            resharing.add_mine(e);
        }

        for (size_t i = 0; i < min(masks.size(), size_t(P.num_players())); i++)
        {
            int j = (base_king + i) % P.num_players();
            resharing.add_sender(j);
        }
        resharing.exchange();
    }
}

template<class T>
T Atlas<T>::finalize_mul(int)
{
    int king = fixed_king_enabled ? fixed_king : base_king;
    size_t transcript_index = next_partial_mult_transcript;
    assert(transcript_index < pending_partial_mult_operations.size());
    T e_t = fixed_king_enabled
            ? fixed_king_special_e_t_shares.at(transcript_index)
            : resharing.finalize(king);
    T r_t = masks.next();
    T res = e_t - r_t;
    auto& operation = pending_partial_mult_operations.at(transcript_index);
    auto& transcript = operation.transcript;
    next_partial_mult_transcript++;
    assert(transcript.king == king);
    assert(transcript.r_t == r_t);
    transcript.e_t = e_t;
    if (fixed_king_enabled)
    {
        validate_fixed_king_special_sharing_support(
                transcript.king, transcript.special_sharing_support);
        if (not fixed_king_special_sharing_support_contains(P.my_num())
                && transcript.e_t != T{0})
            throw logic_error(
                    "Atlas fixed-king special-sharing local component is nonzero outside support");
        if (res != transcript.e_t - transcript.r_t)
            throw logic_error(
                    "Atlas fixed-king special-sharing transcript does not match the returned result");
    }
    if (fixed_king_enabled && P.my_num() == fixed_king)
    {
        assert(transcript_index < pending_king_partial_mult_evidence.size());
        last_king_partial_mult_evidence =
                pending_king_partial_mult_evidence.at(transcript_index);
        have_last_king_partial_mult_evidence = true;
        assert(last_king_partial_mult_evidence.king == transcript.king);
        assert(last_king_partial_mult_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(last_king_partial_mult_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
        validate_fixed_king_special_sharing_evidence(
                transcript, last_king_partial_mult_evidence);
    }
    else
    {
        have_last_king_partial_mult_evidence = false;
    }
    if (not fixed_king_enabled)
        base_king = (base_king + 1) % P.num_players();
    last_completed_partial_mult_operation = operation;
    have_last_partial_mult_transcript = true;
    return res;
}

template<class T>
void Atlas<T>::set_fixed_king(int king)
{
    if (king < 0 || king >= P.num_players())
        throw std::out_of_range("invalid Atlas fixed king");
    assert(next_partial_mult_transcript == pending_partial_mult_operations.size());
    fixed_king_enabled = true;
    fixed_king = king;
    fixed_king_special_sharing_support =
            canonical_fixed_king_special_sharing_support(king);
}

template<class T>
void Atlas<T>::set_fixed_king_special_sharing_support(
        const vector<int>& support)
{
    if (not fixed_king_enabled)
        throw logic_error(
                "Atlas special-sharing support requires a fixed king");
    if (next_partial_mult_transcript != pending_partial_mult_operations.size())
        throw logic_error(
                "Atlas special-sharing support cannot change during an operation batch");
    validate_fixed_king_special_sharing_support(fixed_king, support);
    fixed_king_special_sharing_support = support;
}

template<class T>
const typename Atlas<T>::PartialMultTranscript&
Atlas<T>::get_last_partial_mult_transcript() const
{
    assert(have_last_partial_mult_transcript);
    return last_completed_partial_mult_operation.transcript;
}

template<class T>
const typename Atlas<T>::DoubleSharingProducerReference&
Atlas<T>::get_last_double_sharing_producer_reference() const
{
    assert(have_last_partial_mult_transcript);
    return last_completed_partial_mult_operation.producer_reference;
}

template<class T>
bool Atlas<T>::has_last_king_partial_mult_evidence() const
{
    return have_last_king_partial_mult_evidence;
}

template<class T>
const typename Atlas<T>::KingPartialMultEvidence&
Atlas<T>::get_last_king_partial_mult_evidence() const
{
    assert(have_last_king_partial_mult_evidence);
    return last_king_partial_mult_evidence;
}

template<class T>
void Atlas<T>::init_dotprod()
{
    init_mul();
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share += x * y;
}

template<class T>
void Atlas<T>::next_dotprod()
{
    prepare(dotprod_share);
    dotprod_share = 0;
}

template<class T>
T Atlas<T>::finalize_dotprod(int)
{
    return finalize_mul();
}

template<class T>
T Atlas<T>::get_random()
{
    return shamir.get_random();
}

template <class T>
inline void Atlas<T>::init_mul_pub()
{
    init_mul();
    assert(not fixed_king_enabled || fixed_king == 0);
    assert(local_mc_2t.num_recorded_received_sharings() == 0);
    local_mc_2t.clear_recorded_received_sharings();
    local_mc_2t.init_open(P);
}

template <class T>
inline void Atlas<T>::prepare_mul_pub(T x, T y)
{
    auto rho = get_double_sharing();
    T product = x * y;
    T o_2t = rho.r_2t - rho.r_t;
    T e_2t = product + o_2t;
    local_mc_2t.prepare_open(e_2t);

    PartialMultTranscript transcript{};
    transcript.r_t = T{0};
    transcript.r_2t = o_2t;
    transcript.e_2t = e_2t;
    transcript.king = 0;
    transcript.r_decomposition = zero_double_sharing_decomposition();
    for (int dealer = 0; dealer < P.num_players(); dealer++)
    {
        auto& component =
                transcript.r_decomposition.dealer_components.at(dealer);
        const auto& rho_component =
                rho.decomposition.dealer_components.at(dealer);
        component.r_t = T{0};
        component.r_2t = rho_component.r_2t - rho_component.r_t;
    }
    for (int recipient = 0; recipient < P.num_players(); recipient++)
    {
        transcript.r_decomposition.own_dealer_evidence
            .r_t_shares.at(recipient) = share_value_type{};
        transcript.r_decomposition.own_dealer_evidence
            .r_2t_shares.at(recipient) =
                rho.decomposition.own_dealer_evidence
                    .r_2t_shares.at(recipient)
                - rho.decomposition.own_dealer_evidence
                    .r_t_shares.at(recipient);
    }
    assert(transcript.e_2t == product + transcript.r_2t);
    validate_double_sharing_decomposition(
            transcript.r_decomposition, transcript.r_t, transcript.r_2t);
    PendingPartialMultOperation operation{};
    operation.transcript = transcript;
    operation.producer_reference = rho.producer_reference;
    pending_partial_mult_operations.push_back(std::move(operation));
}

template <class T>
inline void Atlas<T>::exchange_mul_pub()
{
    local_mc_2t.begin_received_sharing_recording();
    local_mc_2t.exchange(P);
    local_mc_2t.end_received_sharing_recording();
    if (P.my_num() == 0)
        assert(local_mc_2t.num_recorded_received_sharings()
                == pending_partial_mult_operations.size());
    else
        assert(local_mc_2t.num_recorded_received_sharings() == 0);
}

template <class T>
inline T Atlas<T>::finalize_mul_pub()
{
    typename T::open_type alpha = local_mc_2t.finalize_open();
    T alpha_t = alpha;

    size_t transcript_index = next_partial_mult_transcript;
    assert(transcript_index < pending_partial_mult_operations.size());
    auto& operation = pending_partial_mult_operations.at(transcript_index);
    auto& transcript = operation.transcript;
    next_partial_mult_transcript++;
    assert(transcript.king == 0);
    assert(transcript.r_t == T{0});
    transcript.e_t = alpha_t;
    if (P.my_num() == 0)
    {
        build_public_opening_king_evidence(transcript_index, alpha);
        last_king_partial_mult_evidence =
                pending_king_partial_mult_evidence.at(transcript_index);
        have_last_king_partial_mult_evidence = true;
        assert(last_king_partial_mult_evidence.king == 0);
        assert(last_king_partial_mult_evidence.king == transcript.king);
        assert(last_king_partial_mult_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(last_king_partial_mult_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
        assert(reconstruct_received_e_2t(
                last_king_partial_mult_evidence.received_e_2t) == alpha);
        assert(reconstruct_distributed_e_t(
                last_king_partial_mult_evidence.distributed_e_t,
                canonical_fixed_king_special_sharing_support(0)) == alpha);
    }
    else
    {
        have_last_king_partial_mult_evidence = false;
    }
    assert(transcript.e_t - transcript.r_t == alpha_t);

    if (next_partial_mult_transcript
            == pending_partial_mult_operations.size())
        local_mc_2t.clear_recorded_received_sharings();

    last_completed_partial_mult_operation = operation;
    have_last_partial_mult_transcript = true;
    return alpha_t;
}

template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

template<class T>
void Atlas<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, false_type) {
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
void Atlas<T>::init_mul_trunc(int length)
{   
    init_mul();
    assert(not fixed_king_enabled || fixed_king == 0);
    assert(local_mc_2t.num_recorded_received_sharings() == 0);
    local_mc_2t.clear_recorded_received_sharings();
    local_mc_2t.init_open(P, length);
}

template<class T>
void Atlas<T>::prepare_mul_trunc(const T& x, const T& y)
{
    prepare_with_solved_bits(x * y);
    
#ifdef DEBUG_MUL_TRUNC
    cerr << "\nprepare_mul_trunc(): " << "k = " << k << ' ' << "f = " << f << '\n'
         << "x = " << x << ", y = " << y << '\n';
    
    typename T::MAC_Check debug_mc;
    cerr << "x_open = " << debug_mc.POpen(x, P) << ' ' 
         << "y_open = " << debug_mc.POpen(y, P) << '\n';
#endif
}

/**
 * prepare_with_solved_bits()
 * 
 * This function is like prepare(),
 * but the random mask is from the solved bits, 
 * not from a double sharing.
 */
template<class T>
void Atlas<T>::prepare_with_solved_bits(const typename T::open_type& product)
{
    constexpr static int k = T::bit_length, f = AtlasConfig::fixed_point_precision;

#ifdef DEBUG_MUL_TRUNC
    cerr << "\nprepare_with_solved_bits(): \n"
         << "product = " << product << '\n';

    // Open the product for debugging
    typename T::MAC_Check_2t debug_mc_2t;
    auto product_open = debug_mc_2t.POpen(product, P);
    cerr << "product_open = " << product_open << '\n';
#endif

    // get the individual bits [r_i]
    vector<T> r_bits(k);
    for (auto& r_i : r_bits) {
        prep->get_one(DATA_BIT, r_i);
    }

    // Compose [r_i] into [r]
    // r = sum_{i=0}^{k-1} r_i * 2^i
    T r = 0;
    for (int i = 0; i < k; ++i) {
        r += r_bits[i] << i;
    }

    T r_msb = r_bits.back();

    // Compute [r'] from [r_i]
    // r' = sum_{i=f}^{k-1} 2^{i-f} * r_i + sum_{i=k-f}^{k-1} 2^i * r_msb
    T r_prime = 0;
    for (int i = f; i < k; ++i) {
        r_prime += r_bits[i] << (i - f);
    }
    for (int i = k - f; i < k; ++i) {
        r_prime += r_msb << i;
    }

    auto s = get_double_sharing();
    T r_hat_2t = r + s.r_2t - s.r_t;
    T e_2t = product + r_hat_2t;
    local_mc_2t.prepare_open(e_2t);

    PartialMultTranscript transcript{};
    transcript.r_t = r;
    transcript.r_2t = r_hat_2t;
    transcript.e_2t = e_2t;
    transcript.king = 0;
    transcript.r_decomposition = zero_double_sharing_decomposition();
    transcript.r_decomposition.validated_residual.r_t = r;
    transcript.r_decomposition.validated_residual.r_2t = r;
    for (int dealer = 0; dealer < P.num_players(); dealer++)
    {
        auto& component =
                transcript.r_decomposition.dealer_components.at(dealer);
        const auto& s_component =
                s.decomposition.dealer_components.at(dealer);
        component.r_t = T{0};
        component.r_2t = s_component.r_2t - s_component.r_t;
    }
    for (int recipient = 0; recipient < P.num_players(); recipient++)
    {
        transcript.r_decomposition.own_dealer_evidence
            .r_t_shares.at(recipient) = share_value_type{};
        transcript.r_decomposition.own_dealer_evidence
            .r_2t_shares.at(recipient) =
                s.decomposition.own_dealer_evidence
                    .r_2t_shares.at(recipient)
                - s.decomposition.own_dealer_evidence
                    .r_t_shares.at(recipient);
    }
    assert(transcript.e_2t == product + transcript.r_2t);
    validate_double_sharing_decomposition(
            transcript.r_decomposition, transcript.r_t, transcript.r_2t);
    PendingPartialMultOperation operation{};
    operation.transcript = transcript;
    operation.producer_reference = s.producer_reference;
    pending_partial_mult_operations.push_back(std::move(operation));

#ifdef DEBUG_MUL_TRUNC
    // Open r, r_bits, r_msb, r_prime for debugging
    typename T::MAC_Check debug_mc;

    auto r_open = debug_mc.POpen(r, P);
    auto r_msb_open = debug_mc.POpen(r_msb, P);
    auto r_prime_open = debug_mc.POpen(r_prime, P);

    vector<typename T::open_type> r_bits_open;
    debug_mc.POpen(r_bits_open, r_bits, P);

    // Compose the bits
    T r_composed = 0;
    for (int i = 0; i < k; ++i) {
        r_composed += r_bits_open[i] << i;
    }

    // Print the values for debugging
    cerr << "r_open= " << r_open << '\n'
         << "r_composed = " << r_composed << '\n'
         << "r_bits_open = ";
    for (int i = 0; i < k; ++i) {
        cerr << r_bits_open[i] << ' ';
    }
    cerr << '\n'
         << "r_msb_open = " << r_msb_open << '\n'
         << "r_prime_open = " << r_prime_open << '\n';
#endif

    next_king = (next_king + 1) % P.num_players();

    masks.push_back(r_msb);
    masks.push_back(r_prime);
    masks.push_back(r); // This is needed for verification in the maliciously secure version
}

template<class T>
void Atlas<T>::exchange_mul_trunc()
{
    local_mc_2t.begin_received_sharing_recording();
    local_mc_2t.exchange(P);
    local_mc_2t.end_received_sharing_recording();
    if (P.my_num() == 0)
        assert(local_mc_2t.num_recorded_received_sharings()
                == pending_partial_mult_operations.size());
    else
        assert(local_mc_2t.num_recorded_received_sharings() == 0);
}

/**
 * @brief Finalize the multiplication with truncation
 * 
 * @param pre_trunc the pointer used to return the pre-truncation share (optional)
 * @return T the truncated share
 */
template<class T>
T Atlas<T>::finalize_mul_trunc(T* pre_trunc)
{
    constexpr static int k = T::bit_length, f = AtlasConfig::fixed_point_precision;

    const static typename T::clear two_power_k_minus_two = T::power_of_two(1, k - 2);
    const static typename T::clear two_power_k_minus_f = T::power_of_two(1, k - f);
    const static typename T::clear two_power_k_minus_f_minus_two = T::power_of_two(1, k - f - 2);

    typename T::clear c = local_mc_2t.finalize_open();
    T r_msb = masks.next();
    T r_prime = masks.next();
    T r = masks.next();

    size_t transcript_index = next_partial_mult_transcript;
    assert(transcript_index < pending_partial_mult_operations.size());
    auto& operation = pending_partial_mult_operations.at(transcript_index);
    auto& transcript = operation.transcript;
    next_partial_mult_transcript++;
    assert(transcript.king == 0);
    assert(transcript.r_t == r);
    T e_t = c;
    transcript.e_t = e_t;
    if (P.my_num() == 0)
    {
        build_public_opening_king_evidence(transcript_index, c);
        last_king_partial_mult_evidence =
                pending_king_partial_mult_evidence.at(transcript_index);
        have_last_king_partial_mult_evidence = true;
        assert(last_king_partial_mult_evidence.king == 0);
        assert(last_king_partial_mult_evidence.king == transcript.king);
        assert(last_king_partial_mult_evidence.received_e_2t.size()
                == size_t(P.num_players()));
        assert(last_king_partial_mult_evidence.distributed_e_t.size()
                == size_t(P.num_players()));
        assert(reconstruct_received_e_2t(
                last_king_partial_mult_evidence.received_e_2t) == c);
        assert(reconstruct_distributed_e_t(
                last_king_partial_mult_evidence.distributed_e_t,
                canonical_fixed_king_special_sharing_support(0)) == c);
    }
    else
    {
        have_last_king_partial_mult_evidence = false;
    }

    T a = e_t - r;
    if (pre_trunc != nullptr) {
        *pre_trunc = a; // This is needed for verification in the maliciously secure version
    }
    assert(transcript.e_t - transcript.r_t == a);

    if (next_partial_mult_transcript
            == pending_partial_mult_operations.size())
        local_mc_2t.clear_recorded_received_sharings();

    c += two_power_k_minus_two;
    typename T::clear c_msb = c >> (k - 1);
    typename T::clear c_trunc = c.truncate(f);

    typename T::clear e(1);
    e = (e - r_msb) * c_msb;

#ifdef DEBUG_MUL_TRUNC
    typename T::MAC_Check debug_mc;
    auto r_msb_open = debug_mc.POpen(r_msb, P);
    auto r_prime_open = debug_mc.POpen(r_prime, P);
    auto e_open = debug_mc.POpen(e, P);

    T res = c_trunc - r_prime + e * (two_power_k_minus_f - 1) - two_power_k_minus_f_minus_two;
    auto res_open = debug_mc.POpen(res, P);

    cerr << "\nfinalize_mul_trunc(): " << "k = " << k << ' ' << "f = " << f << '\n'
         << "two_power_k_minus_f = " << two_power_k_minus_f << '\n'
         << "two_power_k_minus_f_minus_two = " << two_power_k_minus_f_minus_two << '\n'
         << "c = " << c << '\n'
         << "c_trunc = " << c_trunc << '\n'
         << "r_msb_open = " << r_msb_open << '\n'
         << "r_prime_open = " << r_prime_open << '\n'
         << "e_open = " << e_open << '\n'
         << "res_open = " << res_open << '\n';
#endif

    T res = c_trunc - r_prime + e * (two_power_k_minus_f - 1)
            - two_power_k_minus_f_minus_two;
    last_completed_partial_mult_operation = operation;
    have_last_partial_mult_transcript = true;
    return res;
}

template<class T>
void Atlas<T>::init_dotprod_trunc()
{
    init_mul_trunc(100); // We don't know the length yet, but it is only used for vector::reserve
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
#ifdef DEBUG_DOTPROD
    cerr << "\nprepare_dotprod()\n"
         << "x = " << x << ", y = " << y << '\n'
         << "dotprod_share (pre addition): " << dotprod_share << '\n';

    typename T::MAC_Check debug_mc;
    typename T::MAC_Check_2t debug_mc_2t;

    auto x_open = debug_mc.POpen(x, P);
    auto y_open = debug_mc.POpen(y, P);
    auto dotprod_share_open = debug_mc_2t.POpen(dotprod_share, P);

    cerr << "x_open = " << x_open << '\n'
         << "y_open = " << y_open << '\n'
         << "dotprod_share_open (pre addition) = " << dotprod_share_open << '\n';
#endif

    dotprod_share += x * y;
}

template<class T>
void Atlas<T>::next_dotprod_trunc()
{
#ifdef DEBUG_DOTPROD
    // Open the product for debugging
    typename T::MAC_Check_2t debug_mc_2t;
    auto dotprod_open = debug_mc_2t.POpen(dotprod_share, P);
    cerr << "\nnext_dotprod_trunc()\n"
         << "dotprod_open:\n" << dotprod_open << "\n\n";
#endif

    prepare_with_solved_bits(dotprod_share);
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::exchange_dotprod_trunc()
{
    exchange_mul_trunc();
}

/**
 * @brief Finalize the dot product with truncation
 * 
 * @param length Unused 
 * @param pre_trunc 
 * @return T 
 */
template<class T>
T Atlas<T>::finalize_dotprod_trunc(int length, T* pre_trunc)
{
    (void) length;
    return finalize_mul_trunc(pre_trunc);
}


#endif /* PROTOCOLS_ATLAS_HPP_ */
