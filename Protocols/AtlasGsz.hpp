/*
 * AtlasGsz.hpp
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_HPP_
#define PROTOCOLS_ATLASGSZ_HPP_

#include "AtlasGsz.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <type_traits>
#include "BufferScope.h"
#include "AtlasConfig.h"


template<class T>
AtlasGsz<T>::AtlasGsz(Player& P) : AtlasGsz(P,
        parse_base_field_ftag_chunk_width(),
        PreserveBaseFieldFTagChunkWidth{})
{
}

template<class T>
AtlasGsz<T>::AtlasGsz(Player& P, uint64_t base_field_ftag_chunk_width,
        PreserveBaseFieldFTagChunkWidth) :
        base_field_ftag_chunk_width_(base_field_ftag_chunk_width), honest(P),
        optimistic_authentication_input(0, P), P(P)
{
    if (base_field_ftag_chunk_width_ == 0
            || base_field_ftag_chunk_width_
                    > uint64_t(numeric_limits<size_t>::max()))
        throw invalid_argument(
                "AtlasGsz: base-field FTag chunk width is out of range");
    honest.set_fixed_king(0);
    x_verify.reserve(AtlasConfig::max_before_check);
    y_verify.reserve(AtlasConfig::max_before_check);
    z_verify.reserve(AtlasConfig::max_before_check);
    partial_mult_transcripts.reserve(AtlasConfig::max_before_check);
}

template<class T>
uint64_t AtlasGsz<T>::parse_base_field_ftag_chunk_width()
{
    const char* input = getenv("ATLAS_GSZ_FTAG_CHUNK_WIDTH");
    if (input == 0)
        return 4;
    if (*input == '\0')
        throw invalid_argument(
                "ATLAS_GSZ_FTAG_CHUNK_WIDTH must be a non-empty unsigned integer greater than zero");

    uint64_t result = 0;
    for (const char* cursor = input; *cursor != '\0'; cursor++)
    {
        if (*cursor < '0' || *cursor > '9')
            throw invalid_argument(
                    "ATLAS_GSZ_FTAG_CHUNK_WIDTH must contain only unsigned decimal digits");
        uint64_t digit = uint64_t(*cursor - '0');
        if (result > (numeric_limits<uint64_t>::max() - digit) / 10)
            throw invalid_argument(
                    "ATLAS_GSZ_FTAG_CHUNK_WIDTH overflows uint64_t");
        result = result * 10 + digit;
    }
    if (result == 0)
        throw invalid_argument(
                "ATLAS_GSZ_FTAG_CHUNK_WIDTH must be greater than zero");
    if (result > uint64_t(numeric_limits<size_t>::max()))
        throw invalid_argument(
                "ATLAS_GSZ_FTAG_CHUNK_WIDTH exceeds the local addressable size");
    return result;
}

template<class T>
size_t AtlasGsz<T>::base_field_ftag_chunk_width() const
{
    assert(base_field_ftag_chunk_width_ > 0);
    assert(base_field_ftag_chunk_width_
            <= uint64_t(numeric_limits<size_t>::max()));
    return size_t(base_field_ftag_chunk_width_);
}

template<class T>
size_t AtlasGsz<T>::base_field_ftag_chunk_count(
        size_t original_source_count) const
{
    const size_t width = base_field_ftag_chunk_width();
    return original_source_count / width
            + (original_source_count % width != 0);
}

template<class T>
size_t AtlasGsz<T>::checked_size_product(
        size_t left, size_t right, const char* description)
{
    if (left != 0 && right > numeric_limits<size_t>::max() / left)
        throw overflow_error(description);
    return left * right;
}

template<class T>
size_t AtlasGsz<T>::checked_size_sum(
        size_t left, size_t right, const char* description)
{
    if (right > numeric_limits<size_t>::max() - left)
        throw overflow_error(description);
    return left + right;
}

template<class T>
bool AtlasGsz<T>::begin_tentative_double_rand_capture()
{
    auto& state = tentative_double_rand_capture_state;
    if (state.active || state.finalized_candidate
            || not state.producer_records.empty()
            || not state.consumptions.empty()
            || not state.producer_record_ordinals.empty()
            || not state.consumed_outputs_by_producer.empty())
        return false;
    state.active = true;
    return true;
}

template<class T>
void AtlasGsz<T>::discard_tentative_double_rand_capture()
{
    tentative_double_rand_capture_state =
            TentativeDoubleRandCaptureState{};
}

template<class T>
const typename AtlasGsz<T>::TentativeDoubleRandCaptureCandidate*
AtlasGsz<T>::inspect_tentative_double_rand_capture() const
{
    return tentative_double_rand_capture_state.finalized_candidate.get();
}

template<class T>
bool AtlasGsz<T>::validate_tentative_paired_producer_record(
        const typename Atlas<T>::DoubleSharingProducerProvenance&
            producer) const
{
    const size_t n = P.num_players();
    const auto& degree_t = producer.degree_t;
    const auto& degree_2t = producer.degree_2t;
    if (n == 0 || degree_t.output_derivations.empty()
            || degree_t.output_derivations.size() % n != 0
            || degree_t.source_groups.size()
                    != degree_t.output_derivations.size() / n
            || degree_t.source_groups.size()
                    != degree_2t.source_groups.size()
            || degree_t.output_derivations.size()
                    != degree_2t.output_derivations.size())
        return false;

    for (size_t group_ordinal = 0;
            group_ordinal < degree_t.source_groups.size(); group_ordinal++)
    {
        const auto& t_group = degree_t.source_groups.at(group_ordinal);
        const auto& two_t_group =
                degree_2t.source_groups.at(group_ordinal);
        if (t_group.input_batch_ordinal != group_ordinal
                || two_t_group.input_batch_ordinal != group_ordinal
                || t_group.sources.size() != n
                || two_t_group.sources.size() != n)
            return false;
        for (size_t dealer = 0; dealer < n; dealer++)
        {
            const auto& t_source = t_group.sources.at(dealer);
            const auto& two_t_source = two_t_group.sources.at(dealer);
            if (t_source.dealer != int(dealer)
                    || two_t_source.dealer != int(dealer)
                    || t_source.input_batch_ordinal != group_ordinal
                    || two_t_source.input_batch_ordinal != group_ordinal)
                return false;
        }
    }

    for (size_t output_ordinal = 0;
            output_ordinal < degree_t.output_derivations.size();
            output_ordinal++)
    {
        const auto& t_derivation =
                degree_t.output_derivations.at(output_ordinal);
        const auto& two_t_derivation =
                degree_2t.output_derivations.at(output_ordinal);
        const size_t expected_group = output_ordinal / n;
        if (t_derivation.output_ordinal != output_ordinal
                || two_t_derivation.output_ordinal != output_ordinal
                || t_derivation.input_batch_ordinal != expected_group
                || two_t_derivation.input_batch_ordinal != expected_group
                || t_derivation.terms.size() != n
                || two_t_derivation.terms.size() != n)
            return false;
        for (size_t dealer = 0; dealer < n; dealer++)
        {
            const auto& t_term = t_derivation.terms.at(dealer);
            const auto& two_t_term = two_t_derivation.terms.at(dealer);
            if (t_term.source_index != dealer
                    || two_t_term.source_index != dealer
                    || t_term.coefficient != two_t_term.coefficient)
                return false;
        }
    }
    return true;
}

template<class T>
bool AtlasGsz<T>::capture_completed_ordinary_double_rand(
        const PartialMultTranscriptRecord& record,
        size_t record_ordinal,
        OrdinaryDoubleRandOperationKind operation_kind)
{
    auto& state = tentative_double_rand_capture_state;
    if (not state.active || state.finalized_candidate)
        return false;

    if (record_ordinal >= partial_mult_transcripts.size()
            || record_ordinal + 1 != partial_mult_transcripts.size()
            || record.operation_kind != operation_kind)
    {
        discard_tentative_double_rand_capture();
        return false;
    }

    TentativeConcreteEtSource concrete_e_t_source{};
    concrete_e_t_source.king = record.transcript.king;
    concrete_e_t_source.special_sharing_support =
            record.transcript.special_sharing_support;
    concrete_e_t_source.local_share = record.transcript.e_t;
    if (not validate_tentative_concrete_e_t_source(concrete_e_t_source,
            record_ordinal, operation_kind))
    {
        discard_tentative_double_rand_capture();
        return false;
    }

    const auto& reference = record.producer_reference;
    if (not reference.producer_provenance)
    {
        discard_tentative_double_rand_capture();
        return false;
    }

    const void* producer_identity = reference.producer_provenance.get();
    auto producer_position =
            state.producer_record_ordinals.find(producer_identity);
    size_t producer_record_ordinal = 0;
    if (producer_position == state.producer_record_ordinals.end())
    {
        producer_record_ordinal = state.producer_records.size();
        state.producer_record_ordinals.emplace(
                producer_identity, producer_record_ordinal);
        state.producer_records.push_back(reference.producer_provenance);
        state.consumed_outputs_by_producer.emplace_back();
    }
    else
        producer_record_ordinal = producer_position->second;
    if (producer_record_ordinal >= state.producer_records.size()
            || producer_record_ordinal
                    >= state.consumed_outputs_by_producer.size()
            || state.producer_records.at(producer_record_ordinal)
                    != reference.producer_provenance
            || not state.consumed_outputs_by_producer.at(
                    producer_record_ordinal).emplace(
                            reference.producer_output_ordinal, true).second)
    {
        // A repeated exact material key is a failed round, never a second
        // source or an idempotent capture.
        discard_tentative_double_rand_capture();
        return false;
    }

    TentativeCapturedConsumption consumption{};
    consumption.capture_order_ordinal = state.consumptions.size();
    consumption.producer_record_ordinal = producer_record_ordinal;
    consumption.producer_reference = reference;
    consumption.operation_kind = operation_kind;
    consumption.actual_r_t = record.transcript.r_t;
    consumption.actual_r_2t = record.transcript.r_2t;
    consumption.decomposition = record.transcript.r_decomposition;
    consumption.concrete_e_t_source = std::move(concrete_e_t_source);
    consumption.partial_mult_transcript_record_ordinal = record_ordinal;
    state.consumptions.push_back(std::move(consumption));
    return true;
}

template<class T>
bool AtlasGsz<T>::validate_tentative_concrete_e_t_source(
        const TentativeConcreteEtSource& source,
        size_t record_ordinal,
        OrdinaryDoubleRandOperationKind operation_kind) const
{
    if (record_ordinal >= partial_mult_transcripts.size())
        return false;
    const auto& record = partial_mult_transcripts.at(record_ordinal);
    const auto& transcript = record.transcript;
    const int t = ShamirMachine::s().threshold;
    if ((operation_kind
                    != OrdinaryDoubleRandOperationKind::scalar_multiplication
                && operation_kind
                    != OrdinaryDoubleRandOperationKind::dot_product)
            || record.operation_kind != operation_kind
            || source.king != 0 || transcript.king != source.king
            || source.special_sharing_support
                    != transcript.special_sharing_support
            || source.special_sharing_support.size() != size_t(t + 1)
            || source.local_share != transcript.e_t
            || record.offset >= z_verify.size()
            || record.length <= 0
            || z_verify.at(record.offset) != transcript.e_t - transcript.r_t)
        return false;

    vector<bool> seen(P.num_players(), false);
    bool contains_king = false;
    for (size_t i = 0; i < source.special_sharing_support.size(); i++)
    {
        const int party = source.special_sharing_support.at(i);
        if (party < 0 || party >= P.num_players()
                || party != int(i) || seen.at(party))
            return false;
        seen.at(party) = true;
        contains_king |= party == source.king;
    }
    if (not contains_king
            || (not seen.at(P.my_num()) && source.local_share != T{}))
        return false;

    const auto& reference = record.producer_reference;
    if (not reference.producer_provenance
            || reference.producer_output_ordinal
                    >= reference.producer_provenance->degree_t
                            .output_derivations.size()
            || reference.producer_output_ordinal
                    >= reference.producer_provenance->degree_2t
                            .output_derivations.size()
            || record.has_king_evidence != (P.my_num() == source.king))
        return false;

    if (record.has_king_evidence)
    {
        const auto& evidence = record.king_evidence;
        if (evidence.king != source.king
                || evidence.received_e_2t.size() != size_t(P.num_players())
                || evidence.distributed_e_t.size()
                        != size_t(P.num_players()))
            return false;
        for (int party = 0; party < P.num_players(); party++)
        {
            if (not seen.at(party)
                    && evidence.distributed_e_t.at(party)
                            != typename Atlas<T>::share_value_type{})
                return false;
            auto factors = Shamir<T>::get_rec_factors(
                    source.special_sharing_support, party);
            typename Atlas<T>::share_value_type expected{};
            for (size_t i = 0;
                    i < source.special_sharing_support.size(); i++)
                expected += evidence.distributed_e_t.at(
                        source.special_sharing_support.at(i))
                        * factors.at(i);
            if (expected != evidence.distributed_e_t.at(party))
                return false;
        }

        typename Atlas<T>::share_value_type received_secret{};
        for (int party = 0; party < 2 * t + 1; party++)
            received_secret += evidence.received_e_2t.at(party)
                    * Shamir<T>::get_rec_factor(party, 2 * t + 1);
        typename Atlas<T>::share_value_type distributed_secret{};
        const auto reconstruction = Shamir<T>::get_rec_factors(
                source.special_sharing_support);
        for (size_t i = 0;
                i < source.special_sharing_support.size(); i++)
            distributed_secret += evidence.distributed_e_t.at(
                    source.special_sharing_support.at(i))
                    * reconstruction.at(i);
        typename Atlas<T>::share_value_type local_e_t = source.local_share;
        if (received_secret != distributed_secret
                || evidence.distributed_e_t.at(source.king) != local_e_t)
            return false;
    }
    return true;
}

template<class T>
bool AtlasGsz<T>::validate_tentative_double_rand_candidate(
        const TentativeDoubleRandCaptureCandidate& candidate) const
{
    const size_t n = P.num_players();
    if (n == 0 || candidate.consumed_outputs.empty()
            || candidate.producer_records.empty()
            || candidate.source_groups.empty()
            || candidate.source_count != candidate.source_groups.size()
            || candidate.dealer_sources.size() != n)
        return false;

    unordered_map<const void*, size_t> producer_ordinals;
    producer_ordinals.reserve(candidate.producer_records.size());
    for (size_t i = 0; i < candidate.producer_records.size(); i++)
    {
        if (not candidate.producer_records.at(i)
                || not validate_tentative_paired_producer_record(
                        *candidate.producer_records.at(i)))
            return false;
        if (not producer_ordinals.emplace(
                candidate.producer_records.at(i).get(), i).second)
            return false;
    }

    auto group_less = [] (const TentativeSourceGroupReference& left,
            const TentativeSourceGroupReference& right) {
        if (left.producer_record_ordinal
                != right.producer_record_ordinal)
            return left.producer_record_ordinal
                    < right.producer_record_ordinal;
        return left.input_generation_group_ordinal
                < right.input_generation_group_ordinal;
    };
    vector<vector<size_t>> source_group_positions;
    source_group_positions.reserve(candidate.producer_records.size());
    for (const auto& producer : candidate.producer_records)
        source_group_positions.emplace_back(
                producer->degree_t.source_groups.size(),
                numeric_limits<size_t>::max());
    for (size_t i = 0; i < candidate.source_groups.size(); i++)
    {
        const auto& group = candidate.source_groups.at(i);
        if (group.producer_record_ordinal
                    >= candidate.producer_records.size()
                || group.input_generation_group_ordinal
                    >= candidate.producer_records.at(
                            group.producer_record_ordinal)
                            ->degree_t.source_groups.size()
                || (i > 0 && not group_less(
                        candidate.source_groups.at(i - 1), group)))
            return false;
        auto& position = source_group_positions.at(
                group.producer_record_ordinal).at(
                        group.input_generation_group_ordinal);
        if (position != numeric_limits<size_t>::max())
            return false;
        position = i;
    }

    // Validate the complete per-dealer table before resolving any temporary
    // derivation through it, so malformed candidates are rejected without
    // partial access or mutation.
    for (size_t dealer = 0; dealer < n; dealer++)
    {
        const auto& sequence = candidate.dealer_sources.at(dealer);
        if (sequence.dealer != int(dealer)
                || sequence.sources.size() != candidate.source_count)
            return false;
        for (size_t source_ordinal = 0;
                source_ordinal < candidate.source_count; source_ordinal++)
        {
            const auto& expected_group =
                    candidate.source_groups.at(source_ordinal);
            TentativeSourceReference expected_reference{};
            expected_reference.producer_record_ordinal =
                    expected_group.producer_record_ordinal;
            expected_reference.input_generation_group_ordinal =
                    expected_group.input_generation_group_ordinal;
            expected_reference.dealer = dealer;
            const auto& source = sequence.sources.at(source_ordinal);
            const auto& original = candidate.producer_records.at(
                    expected_group.producer_record_ordinal)
                    ->degree_t.source_groups.at(
                            expected_group.input_generation_group_ordinal)
                    .sources.at(dealer);
            if (source.tentative_source_ordinal != source_ordinal
                    || not (source.reference == expected_reference)
                    || original.dealer != int(dealer)
                    || original.input_batch_ordinal
                            != expected_group.input_generation_group_ordinal
                    || source.local_share != original.local_share)
                return false;
        }
    }

    vector<bool> seen_producer_records(candidate.producer_records.size(),
            false);
    size_t next_producer_record_ordinal = 0;
    vector<vector<bool>> expected_group_seen;
    vector<unordered_map<size_t, bool>> exact_outputs;
    expected_group_seen.reserve(candidate.producer_records.size());
    exact_outputs.resize(candidate.producer_records.size());
    for (const auto& producer : candidate.producer_records)
        expected_group_seen.emplace_back(
                producer->degree_t.source_groups.size(), false);
    for (size_t consumption_ordinal = 0;
            consumption_ordinal < candidate.consumed_outputs.size();
            consumption_ordinal++)
    {
        const auto& consumption =
                candidate.consumed_outputs.at(consumption_ordinal);
        if (consumption.capture_order_ordinal != consumption_ordinal
                || consumption.producer_record_ordinal
                        >= candidate.producer_records.size()
                || (consumption.operation_kind
                            != OrdinaryDoubleRandOperationKind::
                                    scalar_multiplication
                        && consumption.operation_kind
                            != OrdinaryDoubleRandOperationKind::dot_product))
            return false;
        if (consumption.partial_mult_transcript_record_ordinal
                    >= partial_mult_transcripts.size()
                || not validate_tentative_concrete_e_t_source(
                        consumption.concrete_e_t_source,
                        consumption.partial_mult_transcript_record_ordinal,
                        consumption.operation_kind))
            return false;
        const auto& wrapper = partial_mult_transcripts.at(
                consumption.partial_mult_transcript_record_ordinal);
        if (wrapper.producer_reference.producer_provenance
                    != candidate.producer_records.at(
                            consumption.producer_record_ordinal)
                || wrapper.producer_reference.producer_output_ordinal
                    != consumption.producer_output_ordinal
                || wrapper.transcript.r_t != consumption.actual_r_t
                || wrapper.transcript.r_2t != consumption.actual_r_2t)
            return false;
        if (not seen_producer_records.at(
                consumption.producer_record_ordinal))
        {
            if (consumption.producer_record_ordinal
                    != next_producer_record_ordinal)
                return false;
            seen_producer_records.at(consumption.producer_record_ordinal) =
                    true;
            next_producer_record_ordinal++;
        }

        if (not exact_outputs.at(
                consumption.producer_record_ordinal).emplace(
                        consumption.producer_output_ordinal, true).second)
            return false;

        const auto& producer = *candidate.producer_records.at(
                consumption.producer_record_ordinal);
        if (consumption.producer_output_ordinal
                    >= producer.degree_t.output_derivations.size()
                || consumption.producer_output_ordinal
                    >= producer.degree_2t.output_derivations.size())
            return false;
        const auto& t_derivation = producer.degree_t.output_derivations.at(
                consumption.producer_output_ordinal);
        const auto& two_t_derivation =
                producer.degree_2t.output_derivations.at(
                        consumption.producer_output_ordinal);
        if (consumption.input_generation_group_ordinal
                    != t_derivation.input_batch_ordinal
                || consumption.input_generation_group_ordinal
                    != two_t_derivation.input_batch_ordinal
                || consumption.input_generation_group_ordinal
                    >= producer.degree_t.source_groups.size()
                || consumption.input_generation_group_ordinal
                    >= producer.degree_2t.source_groups.size()
                || consumption.degree_t_derivation.terms.size() != n)
            return false;

        TentativeSourceGroupReference group_reference{};
        group_reference.producer_record_ordinal =
                consumption.producer_record_ordinal;
        group_reference.input_generation_group_ordinal =
                consumption.input_generation_group_ordinal;
        expected_group_seen.at(
                group_reference.producer_record_ordinal).at(
                        group_reference.input_generation_group_ordinal) =
                true;

        const auto& t_sources = producer.degree_t.source_groups.at(
                consumption.input_generation_group_ordinal).sources;
        const auto& two_t_sources =
                producer.degree_2t.source_groups.at(
                        consumption.input_generation_group_ordinal).sources;
        const auto& decomposition = consumption.decomposition;
        if (t_derivation.terms.size() != n
                || two_t_derivation.terms.size() != n
                || t_sources.size() != n || two_t_sources.size() != n
                || decomposition.dealer_components.size() != n
                || decomposition.own_dealer_evidence.r_t_shares.size() != n
                || decomposition.own_dealer_evidence.r_2t_shares.size() != n
                || decomposition.validated_residual.r_t != T{0}
                || decomposition.validated_residual.r_2t != T{0})
            return false;

        const size_t tentative_source_ordinal =
                source_group_positions.at(
                        group_reference.producer_record_ordinal).at(
                                group_reference
                                        .input_generation_group_ordinal);
        if (tentative_source_ordinal == numeric_limits<size_t>::max())
            return false;
        T evaluated_t{};
        T evaluated_2t{};
        for (size_t dealer = 0; dealer < n; dealer++)
        {
            const auto& t_term = t_derivation.terms.at(dealer);
            const auto& two_t_term = two_t_derivation.terms.at(dealer);
            const auto& temporary_term =
                    consumption.degree_t_derivation.terms.at(dealer);
            TentativeSourceReference expected_source{};
            expected_source.producer_record_ordinal =
                    consumption.producer_record_ordinal;
            expected_source.input_generation_group_ordinal =
                    consumption.input_generation_group_ordinal;
            expected_source.dealer = dealer;
            if (t_term.source_index != dealer
                    || two_t_term.source_index != dealer
                    || t_term.coefficient != two_t_term.coefficient
                    || not (temporary_term.source == expected_source)
                    || temporary_term.coefficient != t_term.coefficient)
                return false;
            const auto& tentative_source =
                    candidate.dealer_sources.at(dealer).sources.at(
                            tentative_source_ordinal);
            if (not (tentative_source.reference == expected_source))
                return false;
            T t_contribution = temporary_term.coefficient
                    * tentative_source.local_share;
            T two_t_contribution = two_t_term.coefficient
                    * two_t_sources.at(dealer).local_share;
            const auto& existing =
                    decomposition.dealer_components.at(dealer);
            if (t_contribution != existing.r_t
                    || two_t_contribution != existing.r_2t)
                return false;
            evaluated_t += t_contribution;
            evaluated_2t += two_t_contribution;
        }
        if (decomposition.own_dealer_evidence.r_t_shares.at(P.my_num())
                    != decomposition.dealer_components.at(P.my_num()).r_t
                || decomposition.own_dealer_evidence.r_2t_shares.at(
                        P.my_num())
                    != decomposition.dealer_components.at(P.my_num()).r_2t
                || evaluated_t != consumption.actual_r_t
                || evaluated_2t != consumption.actual_r_2t)
            return false;
    }
    if (next_producer_record_ordinal != candidate.producer_records.size())
        return false;

    size_t expected_group_count = 0;
    for (size_t producer = 0; producer < expected_group_seen.size();
            producer++)
        for (size_t group = 0;
                group < expected_group_seen.at(producer).size(); group++)
            if (expected_group_seen.at(producer).at(group))
            {
                if (expected_group_count >= candidate.source_groups.size()
                        || candidate.source_groups.at(expected_group_count)
                                    .producer_record_ordinal != producer
                        || candidate.source_groups.at(expected_group_count)
                                    .input_generation_group_ordinal != group)
                    return false;
                expected_group_count++;
            }
    if (expected_group_count != candidate.source_groups.size())
        return false;

    return true;
}

template<class T>
bool AtlasGsz<T>::validate_exact_ordinary_batch_correspondence(
        const TentativeDoubleRandCaptureCandidate& candidate) const
{
    if (x_verify.empty() || x_verify.size() != y_verify.size()
            || x_verify.size() != z_verify.size()
            || partial_mult_transcripts.empty()
            || candidate.consumed_outputs.size()
                    != partial_mult_transcripts.size()
            || integrated_ordinary_batch_state
                    .current_verification_batch_serial == 0)
        return false;

    size_t expected_offset = 0;
    for (size_t ordinal = 0;
            ordinal < partial_mult_transcripts.size(); ordinal++)
    {
        const auto& record = partial_mult_transcripts.at(ordinal);
        const auto& consumed = candidate.consumed_outputs.at(ordinal);
        if ((record.operation_kind
                        != OrdinaryDoubleRandOperationKind::
                                scalar_multiplication
                    && record.operation_kind
                        != OrdinaryDoubleRandOperationKind::dot_product)
                || record.verification_batch_serial
                        != integrated_ordinary_batch_state
                                .current_verification_batch_serial
                || record.offset != expected_offset || record.length <= 0
                || record.offset > x_verify.size()
                || size_t(record.length) > x_verify.size() - record.offset
                || consumed.capture_order_ordinal != ordinal
                || consumed.partial_mult_transcript_record_ordinal
                        != ordinal
                || consumed.operation_kind != record.operation_kind
                || consumed.producer_record_ordinal
                        >= candidate.producer_records.size()
                || record.producer_reference.producer_provenance
                        != candidate.producer_records.at(
                                consumed.producer_record_ordinal)
                || record.producer_reference.producer_output_ordinal
                        != consumed.producer_output_ordinal
                || record.transcript.r_t != consumed.actual_r_t
                || record.transcript.r_2t != consumed.actual_r_2t
                || record.transcript.e_t
                        != consumed.concrete_e_t_source.local_share
                || z_verify.at(record.offset)
                        != record.transcript.e_t - record.transcript.r_t)
            return false;
        if (record.operation_kind
                        == OrdinaryDoubleRandOperationKind::
                                scalar_multiplication
                && record.length != 1)
            return false;
        if (record.operation_kind
                == OrdinaryDoubleRandOperationKind::dot_product)
            for (size_t padding = 1;
                    padding < size_t(record.length); padding++)
                if (z_verify.at(record.offset + padding) != T{})
                    return false;

        T product{};
        for (size_t coordinate = 0;
                coordinate < size_t(record.length); coordinate++)
            product += x_verify.at(record.offset + coordinate)
                    * y_verify.at(record.offset + coordinate);
        if (record.transcript.e_2t
                != product + record.transcript.r_2t)
            return false;
        expected_offset += size_t(record.length);
    }
    return expected_offset == x_verify.size()
            && validate_tentative_double_rand_candidate(candidate);
}

template<class T>
unique_ptr<typename AtlasGsz<T>::FrozenOrdinaryBatch>
AtlasGsz<T>::freeze_finalized_tentative_double_rand_candidate()
{
    auto& capture = tentative_double_rand_capture_state;
    const auto* candidate = capture.finalized_candidate.get();
    if (capture.active || candidate == 0
            || optimistic_authentication_state.status
                    != OptimisticAuthenticationStatus::ready
            || not validate_exact_ordinary_batch_correspondence(*candidate))
        return nullptr;

    auto frozen = make_unique<FrozenOrdinaryBatch>();
    frozen->verification_batch_serial = integrated_ordinary_batch_state
            .current_verification_batch_serial;
    frozen->dealer_count = size_t(P.num_players());
    frozen->operation_count = candidate->consumed_outputs.size();
    frozen->x_verify_coordinate_count = x_verify.size();
    frozen->partial_transcript_count = partial_mult_transcripts.size();
    frozen->mapping_count = checked_size_product(frozen->dealer_count,
            candidate->source_count,
            "AtlasGsz: frozen ordinary mapping count overflow");
    frozen->combined_king_source_count = checked_size_sum(
            candidate->source_count, frozen->operation_count,
            "AtlasGsz: frozen ordinary king source count overflow");
    if (frozen->dealer_count == 0 || candidate->source_count == 0
            || frozen->combined_king_source_count
                    > uint64_t(numeric_limits<uint64_t>::max()))
        return nullptr;

    vector<vector<size_t>> source_group_positions;
    source_group_positions.reserve(candidate->producer_records.size());
    for (const auto& producer : candidate->producer_records)
        source_group_positions.emplace_back(
                producer->degree_t.source_groups.size(),
                numeric_limits<size_t>::max());
    for (size_t source_ordinal = 0;
            source_ordinal < candidate->source_groups.size();
            source_ordinal++)
    {
        const auto& group = candidate->source_groups.at(source_ordinal);
        auto& position = source_group_positions.at(
                group.producer_record_ordinal).at(
                        group.input_generation_group_ordinal);
        if (position != numeric_limits<size_t>::max())
            return nullptr;
        position = source_ordinal;
    }

    auto& receipt = frozen->receipt;
    frozen->prospective_batches.reserve(frozen->dealer_count);
    frozen->prospective_mappings.resize(frozen->mapping_count);
    frozen->converted_term_mapping_indices.resize(
            frozen->operation_count);
    frozen->e_t_source_ordinals.resize(frozen->operation_count);
    receipt.dealer_batches.resize(frozen->dealer_count);
    receipt.source_handles.reserve(frozen->mapping_count);
    receipt.converted_r_t_derivations.resize(frozen->operation_count);
    receipt.authenticated_e_t_sources.resize(frozen->operation_count);
    receipt.converted_z_t_derivations.resize(frozen->operation_count);

    for (size_t dealer = 0; dealer < frozen->dealer_count; dealer++)
    {
        DealerSourceBatchRecord batch{};
        batch.dealer = int(dealer);
        const size_t source_count = dealer == 0
                ? frozen->combined_king_source_count
                : candidate->source_count;
        batch.source_ordinals.reserve(source_count);
        batch.local_source_shares.reserve(source_count);
        for (size_t source_ordinal = 0;
                source_ordinal < candidate->source_count; source_ordinal++)
        {
            batch.source_ordinals.push_back(source_ordinal);
            batch.local_source_shares.push_back(
                    candidate->dealer_sources.at(dealer).sources.at(
                            source_ordinal).local_share);
            const size_t mapping_index = checked_size_sum(
                    checked_size_product(source_ordinal,
                            frozen->dealer_count,
                            "AtlasGsz: frozen mapping offset overflow"),
                    dealer, "AtlasGsz: frozen mapping index overflow");
            const auto& source = candidate->dealer_sources.at(dealer)
                    .sources.at(source_ordinal);
            auto& mapping = frozen->prospective_mappings.at(mapping_index);
            mapping.producer_record_ordinal =
                    source.reference.producer_record_ordinal;
            mapping.input_generation_group_ordinal =
                    source.reference.input_generation_group_ordinal;
            mapping.dealer = int(dealer);
            mapping.source_ordinal = source_ordinal;
        }
        if (dealer == 0)
            for (size_t operation = 0;
                    operation < frozen->operation_count; operation++)
            {
                const size_t source_ordinal = checked_size_sum(
                        candidate->source_count, operation,
                        "AtlasGsz: frozen e_t source ordinal overflow");
                batch.source_ordinals.push_back(source_ordinal);
                batch.local_source_shares.push_back(
                        candidate->consumed_outputs.at(operation)
                                .concrete_e_t_source.local_share);
            }
        if (batch.source_ordinals.size() != source_count
                || batch.local_source_shares.size() != source_count)
            return nullptr;
        frozen->prospective_batches.push_back(std::move(batch));
    }

    vector<bool> used_mappings(frozen->mapping_count, false);
    for (size_t operation = 0;
            operation < frozen->operation_count; operation++)
    {
        const auto& tentative = candidate->consumed_outputs.at(operation);
        auto& converted = receipt.converted_r_t_derivations.at(operation);
        auto& authenticated_e =
                receipt.authenticated_e_t_sources.at(operation);
        auto& converted_z = receipt.converted_z_t_derivations.at(operation);
        converted.capture_order_ordinal = tentative.capture_order_ordinal;
        converted.producer_record_ordinal = tentative.producer_record_ordinal;
        converted.producer_output_ordinal = tentative.producer_output_ordinal;
        converted.input_generation_group_ordinal =
                tentative.input_generation_group_ordinal;
        converted.operation_kind = tentative.operation_kind;
        authenticated_e.capture_order_ordinal =
                tentative.capture_order_ordinal;
        authenticated_e.producer_record_ordinal =
                tentative.producer_record_ordinal;
        authenticated_e.producer_output_ordinal =
                tentative.producer_output_ordinal;
        authenticated_e.input_generation_group_ordinal =
                tentative.input_generation_group_ordinal;
        authenticated_e.operation_kind = tentative.operation_kind;
        authenticated_e.king = tentative.concrete_e_t_source.king;
        authenticated_e.special_sharing_support =
                tentative.concrete_e_t_source.special_sharing_support;
        converted_z.capture_order_ordinal = tentative.capture_order_ordinal;
        converted_z.producer_record_ordinal =
                tentative.producer_record_ordinal;
        converted_z.producer_output_ordinal =
                tentative.producer_output_ordinal;
        converted_z.input_generation_group_ordinal =
                tentative.input_generation_group_ordinal;
        converted_z.operation_kind = tentative.operation_kind;

        const size_t term_count = tentative.degree_t_derivation.terms.size();
        if (term_count != frozen->dealer_count)
            return nullptr;
        converted.derivation.terms.resize(term_count);
        converted_z.derivation.terms.resize(checked_size_sum(term_count, 1,
                "AtlasGsz: frozen z_t term count overflow"));
        converted_z.derivation.terms.at(0).coefficient =
                typename T::open_type(1);
        auto& indices =
                frozen->converted_term_mapping_indices.at(operation);
        indices.resize(term_count);
        frozen->e_t_source_ordinals.at(operation) = checked_size_sum(
                candidate->source_count, tentative.capture_order_ordinal,
                "AtlasGsz: frozen e_t suffix ordinal overflow");
        for (size_t dealer = 0; dealer < term_count; dealer++)
        {
            const auto& term = tentative.degree_t_derivation.terms.at(dealer);
            if (term.source.dealer != int(dealer)
                    || term.source.producer_record_ordinal
                            >= source_group_positions.size()
                    || term.source.input_generation_group_ordinal
                            >= source_group_positions.at(
                                    term.source.producer_record_ordinal).size())
                return nullptr;
            const size_t source_ordinal = source_group_positions.at(
                    term.source.producer_record_ordinal).at(
                            term.source.input_generation_group_ordinal);
            if (source_ordinal == numeric_limits<size_t>::max())
                return nullptr;
            const size_t mapping_index = checked_size_sum(
                    checked_size_product(source_ordinal,
                            frozen->dealer_count,
                            "AtlasGsz: frozen derivation mapping offset overflow"),
                    dealer,
                    "AtlasGsz: frozen derivation mapping index overflow");
            if (mapping_index >= frozen->mapping_count)
                return nullptr;
            indices.at(dealer) = mapping_index;
            used_mappings.at(mapping_index) = true;
            converted.derivation.terms.at(dealer).coefficient =
                    term.coefficient;
            converted_z.derivation.terms.at(dealer + 1).coefficient =
                    typename T::open_type{} - term.coefficient;
        }
    }
    if (find(used_mappings.begin(), used_mappings.end(), false)
            != used_mappings.end())
        return nullptr;

    frozen->candidate = std::move(capture.finalized_candidate);
    if (not frozen->candidate || capture.active
            || not capture.producer_records.empty()
            || not capture.consumptions.empty())
        throw logic_error(
                "AtlasGsz: pure ordinary freeze did not claim exactly one finalized candidate");
    return frozen;
}

template<class T>
bool AtlasGsz<T>::finalize_tentative_double_rand_capture()
{
    auto& state = tentative_double_rand_capture_state;
    if (not state.active || state.finalized_candidate
            || state.consumptions.empty())
    {
        discard_tentative_double_rand_capture();
        return false;
    }

    TentativeDoubleRandCaptureCandidate candidate{};
    candidate.producer_records = state.producer_records;
    vector<vector<bool>> seen_source_groups;
    seen_source_groups.reserve(candidate.producer_records.size());
    for (const auto& producer : candidate.producer_records)
        if (not producer
                || not validate_tentative_paired_producer_record(*producer))
        {
            discard_tentative_double_rand_capture();
            return false;
        }
        else
            seen_source_groups.emplace_back(
                    producer->degree_t.source_groups.size(), false);

    for (const auto& captured : state.consumptions)
    {
        if (captured.producer_record_ordinal
                    >= candidate.producer_records.size()
                || captured.producer_reference.producer_provenance
                    != candidate.producer_records.at(
                            captured.producer_record_ordinal))
        {
            discard_tentative_double_rand_capture();
            return false;
        }
        const auto& producer = *candidate.producer_records.at(
                captured.producer_record_ordinal);
        const size_t output_ordinal =
                captured.producer_reference.producer_output_ordinal;
        if (output_ordinal >= producer.degree_t.output_derivations.size()
                || output_ordinal
                    >= producer.degree_2t.output_derivations.size())
        {
            discard_tentative_double_rand_capture();
            return false;
        }
        const auto& t_derivation =
                producer.degree_t.output_derivations.at(output_ordinal);
        const auto& two_t_derivation =
                producer.degree_2t.output_derivations.at(output_ordinal);
        if (t_derivation.input_batch_ordinal
                    != two_t_derivation.input_batch_ordinal
                || t_derivation.input_batch_ordinal
                    >= producer.degree_t.source_groups.size()
                || t_derivation.input_batch_ordinal
                    >= producer.degree_2t.source_groups.size())
        {
            discard_tentative_double_rand_capture();
            return false;
        }

        TentativeSourceGroupReference group_reference{};
        group_reference.producer_record_ordinal =
                captured.producer_record_ordinal;
        group_reference.input_generation_group_ordinal =
                t_derivation.input_batch_ordinal;
        if (not seen_source_groups.at(
                group_reference.producer_record_ordinal).at(
                        group_reference.input_generation_group_ordinal))
        {
            seen_source_groups.at(
                    group_reference.producer_record_ordinal).at(
                            group_reference.input_generation_group_ordinal) =
                    true;
            candidate.source_groups.push_back(group_reference);
        }

        TentativeConsumedOutputEvidence output{};
        output.capture_order_ordinal = captured.capture_order_ordinal;
        output.producer_record_ordinal = captured.producer_record_ordinal;
        output.producer_output_ordinal = output_ordinal;
        output.input_generation_group_ordinal =
                t_derivation.input_batch_ordinal;
        output.operation_kind = captured.operation_kind;
        output.actual_r_t = captured.actual_r_t;
        output.actual_r_2t = captured.actual_r_2t;
        output.decomposition = captured.decomposition;
        output.concrete_e_t_source = captured.concrete_e_t_source;
        output.partial_mult_transcript_record_ordinal =
                captured.partial_mult_transcript_record_ordinal;
        output.degree_t_derivation.terms.reserve(t_derivation.terms.size());
        for (size_t dealer = 0; dealer < t_derivation.terms.size(); dealer++)
        {
            TentativeLinearDerivationTerm term{};
            term.source.producer_record_ordinal =
                    captured.producer_record_ordinal;
            term.source.input_generation_group_ordinal =
                    t_derivation.input_batch_ordinal;
            term.source.dealer = dealer;
            term.coefficient = t_derivation.terms.at(dealer).coefficient;
            output.degree_t_derivation.terms.push_back(term);
        }
        candidate.consumed_outputs.push_back(std::move(output));
    }

    sort(candidate.source_groups.begin(), candidate.source_groups.end(),
            [] (const TentativeSourceGroupReference& left,
                    const TentativeSourceGroupReference& right) {
                if (left.producer_record_ordinal
                        != right.producer_record_ordinal)
                    return left.producer_record_ordinal
                            < right.producer_record_ordinal;
                return left.input_generation_group_ordinal
                        < right.input_generation_group_ordinal;
            });
    candidate.source_count = candidate.source_groups.size();
    candidate.dealer_sources.reserve(P.num_players());
    for (int dealer = 0; dealer < P.num_players(); dealer++)
    {
        TentativeDealerSourceSequence sequence{};
        sequence.dealer = dealer;
        sequence.sources.reserve(candidate.source_count);
        for (size_t source_ordinal = 0;
                source_ordinal < candidate.source_groups.size();
                source_ordinal++)
        {
            const auto& group = candidate.source_groups.at(source_ordinal);
            const auto& original = candidate.producer_records.at(
                    group.producer_record_ordinal)
                    ->degree_t.source_groups.at(
                            group.input_generation_group_ordinal)
                    .sources.at(dealer);
            TentativeDealerSource source{};
            source.reference.producer_record_ordinal =
                    group.producer_record_ordinal;
            source.reference.input_generation_group_ordinal =
                    group.input_generation_group_ordinal;
            source.reference.dealer = dealer;
            source.tentative_source_ordinal = source_ordinal;
            source.local_share = original.local_share;
            sequence.sources.push_back(source);
        }
        candidate.dealer_sources.push_back(std::move(sequence));
    }

    if (not validate_tentative_double_rand_candidate(candidate))
    {
        discard_tentative_double_rand_capture();
        return false;
    }

    state.finalized_candidate =
            make_unique<TentativeDoubleRandCaptureCandidate>(
                    std::move(candidate));
    state.active = false;
    state.producer_records.clear();
    state.consumptions.clear();
    state.producer_record_ordinals.clear();
    state.consumed_outputs_by_producer.clear();
    return true;
}

template<class T>
bool AtlasGsz<T>::no_authentication_or_checkpoint_artifacts() const
{
    const auto& state = optimistic_authentication_state;
    if (not state.keys.empty() || not state.dealer_batches.empty()
            || not state.nu_material.empty()
            || not state.holder_tags.empty()
            || not state.checkpoints.empty()
            || not state.global_invocations.empty()
            || state.key_establishment_runs != 0
            || state.total_ftag_chunks != 0
            || state.global_check_tag_challenges != 0
            || state.next_batch_id != 1
            || state.next_checkpoint_id != 1
            || state.next_global_invocation_id != 1
            || not verifiable_registry.sharings.empty()
            || not verifiable_registry.checkpoints.empty()
            || not authentication_plan_state.records.empty()
            || not authentication_material_state.records.empty()
            || not pending_analyze_sharing_state.requests.empty()
            || not segment_lifecycle.current_segment_input_sharings.empty()
            || not segment_lifecycle.current_segment_output_sharings.empty())
        return false;
    for (const auto& batch : state.dealer_batches)
        if (not batch.authenticated_handles.empty())
            return false;
    return true;
}

template<class T>
void AtlasGsz<T>::run_special_e_t_malformed_support_test()
{
    const int t = ShamirMachine::s().threshold;
    vector<int> valid_support;
    for (int party = 0; party < t + 1; party++)
        valid_support.push_back(party);

    vector<vector<int>> malformed_supports;
    auto wrong_size = valid_support;
    wrong_size.pop_back();
    malformed_supports.push_back(wrong_size);

    auto duplicate = valid_support;
    duplicate.back() = duplicate.front();
    malformed_supports.push_back(duplicate);

    auto out_of_range = valid_support;
    out_of_range.back() = P.num_players();
    malformed_supports.push_back(out_of_range);

    vector<int> omits_king;
    for (int party = 1; party < t + 2; party++)
        omits_king.push_back(party);
    malformed_supports.push_back(omits_king);

    const size_t communication_before = P.total_comm().sent;
    for (const auto& support : malformed_supports)
    {
        bool rejected = false;
        try
        {
            honest.set_fixed_king_special_sharing_support(support);
        }
        catch (const invalid_argument&)
        {
            rejected = true;
        }
        if (not rejected || P.total_comm().sent != communication_before)
            throw logic_error(
                    "AtlasGsz: malformed special-e_t support was not rejected before operation communication");
    }
    if (not no_authentication_or_checkpoint_artifacts())
        throw logic_error(
                "AtlasGsz: malformed special-e_t support test created an authentication or checkpoint artifact");
}

template<class T>
void AtlasGsz<T>::maybe_run_special_e_t_test(
        const PartialMultTranscriptRecord& record,
        OrdinaryDoubleRandOperationKind operation_kind,
        const T& result)
{
    if (not special_e_t_test_enabled || special_e_t_test_hook_ran)
        return;

    auto fail = [] (const string& reason) {
        throw logic_error("AtlasGsz: special-e-t test failed: " + reason);
    };
    if (not no_authentication_or_checkpoint_artifacts())
        fail("ordinary execution created authentication or checkpoint artifacts");

    const size_t ordinal = special_e_t_test_completed_records;
    const auto expected_kind = ordinal % 2 == 0
            ? OrdinaryDoubleRandOperationKind::scalar_multiplication
            : OrdinaryDoubleRandOperationKind::dot_product;
    if (operation_kind != expected_kind)
        fail("scalar/dot operation order is not alternating");

    const auto& transcript = record.transcript;
    const int t = ShamirMachine::s().threshold;
    if (transcript.king != 0
            || transcript.special_sharing_support.size() != size_t(t + 1))
        fail("king or support width is incorrect");
    for (size_t i = 0; i < transcript.special_sharing_support.size(); i++)
        if (transcript.special_sharing_support.at(i) != int(i))
            fail("support is not the canonical ascending no-dispute set");
    if (result != transcript.e_t - transcript.r_t)
        fail("returned result does not equal e_t - r_t");

    const bool local_in_support = find(
            transcript.special_sharing_support.begin(),
            transcript.special_sharing_support.end(), P.my_num())
            != transcript.special_sharing_support.end();
    if (not local_in_support && transcript.e_t != T{0})
        fail("local e_t is nonzero outside support");
    if (record.has_king_evidence != (P.my_num() == transcript.king))
        fail("king-evidence ownership is incorrect");

    if (record.has_king_evidence)
    {
        const auto& evidence = record.king_evidence;
        if (evidence.king != transcript.king
                || evidence.received_e_2t.size() != size_t(P.num_players())
                || evidence.distributed_e_t.size()
                        != size_t(P.num_players()))
            fail("king evidence has incorrect shape or ownership");

        for (int party = 0; party < P.num_players(); party++)
        {
            const bool in_support = find(
                    transcript.special_sharing_support.begin(),
                    transcript.special_sharing_support.end(), party)
                    != transcript.special_sharing_support.end();
            if (not in_support
                    && evidence.distributed_e_t.at(party)
                            != typename Atlas<T>::share_value_type{})
                fail("king evidence is nonzero outside support");

            auto factors = Shamir<T>::get_rec_factors(
                    transcript.special_sharing_support, party);
            typename Atlas<T>::share_value_type expected{};
            for (size_t i = 0;
                    i < transcript.special_sharing_support.size(); i++)
                expected += evidence.distributed_e_t.at(
                        transcript.special_sharing_support.at(i))
                        * factors.at(i);
            if (expected != evidence.distributed_e_t.at(party))
                fail("king evidence is not degree at most t");
        }

        typename Atlas<T>::share_value_type received_secret{};
        for (int party = 0; party < 2 * t + 1; party++)
            received_secret += evidence.received_e_2t.at(party)
                    * Shamir<T>::get_rec_factor(party, 2 * t + 1);
        typename Atlas<T>::share_value_type distributed_secret{};
        auto reconstruction = Shamir<T>::get_rec_factors(
                transcript.special_sharing_support);
        for (size_t i = 0;
                i < transcript.special_sharing_support.size(); i++)
            distributed_secret += evidence.distributed_e_t.at(
                    transcript.special_sharing_support.at(i))
                    * reconstruction.at(i);
        typename Atlas<T>::share_value_type local_e_t = transcript.e_t;
        if (received_secret != distributed_secret
                || evidence.distributed_e_t.at(transcript.king) != local_e_t)
            fail("king evidence has the wrong secret or king component");
    }

    special_e_t_test_completed_records++;
    const size_t expected_records = 6;
    if (special_e_t_test_completed_records < expected_records)
        return;
    if (special_e_t_test_completed_records != expected_records)
        fail("dedicated workload produced an unexpected record count");
    special_e_t_test_hook_ran = true;
    if (P.my_num() == 0)
        cout << "ATLAS_GSZ_AUTH_TEST special-e-t"
             << " PASS records=6 operation_order=scalar-dot-alternating"
             << " e_t_sharings=6 king=0 support=canonical-ascending"
             << " support_size=t+1 outside_support=zero"
             << " king_evidence=exact degree=at-most-t secret=exact"
             << " result=e_t-minus-r_t malformed_supports=rejected-pre-communication"
             << " dealer_batches=0 handles=0 ftag_chunks=0"
             << " checkpoints=0 authentication_invocations=0"
             << endl;
}

template<class T>
void AtlasGsz<T>::maybe_complete_tentative_double_rand_capture_test()
{
    if (not tentative_double_rand_capture_test_enabled
            || tentative_double_rand_capture_test_hook_ran)
        return;

    auto fail = [&] (const string& reason) {
        discard_tentative_double_rand_capture();
        throw logic_error(
                "AtlasGsz: tentative-double-rand-capture test failed: "
                + reason);
    };
    auto& state = tentative_double_rand_capture_state;
    if (not state.active || state.consumptions.empty())
        fail("completed ordinary output was not retained in the active round");
    if (not no_authentication_or_checkpoint_artifacts())
        fail("capture created an authentication or checkpoint artifact");

    if (not tentative_double_rand_capture_test_checked_first_output)
    {
        if (state.consumptions.size() != 1
                || state.producer_records.size() != 1)
            fail("first completed output was not the sole consumption");
        const auto& first = state.consumptions.front();
        const auto& producer = first.producer_reference.producer_provenance;
        if (not producer
                || not validate_tentative_paired_producer_record(*producer)
                || first.producer_reference.producer_output_ordinal
                    >= producer->degree_t.output_derivations.size())
            fail("first completed output has malformed producer evidence");
        const size_t group_ordinal =
                producer->degree_t.output_derivations.at(
                        first.producer_reference.producer_output_ordinal)
                        .input_batch_ordinal;
        if (group_ordinal >= producer->degree_t.source_groups.size()
                || producer->degree_t.source_groups.at(group_ordinal)
                        .sources.size() != size_t(P.num_players()))
            fail("first output does not represent one whole dealer group");
        tentative_double_rand_capture_test_checked_first_output = true;
    }

    // The dedicated program has six concrete ordinary operations. Finalize
    // only after all six are captured so both three- and five-party focused
    // runs exercise the same operation-record sequence.
    const size_t focused_operation_count = 6;
    if (state.consumptions.size() < focused_operation_count)
        return;
    if (state.consumptions.size() != focused_operation_count)
        fail("dedicated workload captured an unexpected operation count");

    vector<TentativeSourceGroupReference> observed_groups;
    bool observed_two_outputs_from_one_group = false;
    bool observed_scalar_multiplication = false;
    bool observed_dot_product = false;
    for (size_t i = 0; i < state.consumptions.size(); i++)
    {
        const auto& left = state.consumptions.at(i);
        observed_scalar_multiplication |= left.operation_kind
                == OrdinaryDoubleRandOperationKind::scalar_multiplication;
        observed_dot_product |= left.operation_kind
                == OrdinaryDoubleRandOperationKind::dot_product;
        const auto& left_producer =
                left.producer_reference.producer_provenance;
        if (not left_producer
                || not validate_tentative_paired_producer_record(
                        *left_producer)
                || left.producer_reference.producer_output_ordinal
                    >= left_producer->degree_t.output_derivations.size())
            fail("captured producer evidence became malformed");
        TentativeSourceGroupReference left_group{};
        left_group.producer_record_ordinal = left.producer_record_ordinal;
        left_group.input_generation_group_ordinal =
                left_producer->degree_t.output_derivations.at(
                        left.producer_reference.producer_output_ordinal)
                        .input_batch_ordinal;
        if (find(observed_groups.begin(), observed_groups.end(), left_group)
                == observed_groups.end())
            observed_groups.push_back(left_group);
        for (size_t j = 0; j < i; j++)
        {
            const auto& right = state.consumptions.at(j);
            const auto& right_producer =
                    right.producer_reference.producer_provenance;
            TentativeSourceGroupReference right_group{};
            right_group.producer_record_ordinal =
                    right.producer_record_ordinal;
            right_group.input_generation_group_ordinal =
                    right_producer->degree_t.output_derivations.at(
                            right.producer_reference.producer_output_ordinal)
                            .input_batch_ordinal;
            if (left_group == right_group
                    && left.producer_reference.producer_output_ordinal
                        != right.producer_reference.producer_output_ordinal)
                observed_two_outputs_from_one_group = true;
        }
    }
    if (not observed_two_outputs_from_one_group
            || observed_groups.size() < 2
            || not observed_scalar_multiplication
            || not observed_dot_product)
        return;

    const size_t expected_consumption_count = state.consumptions.size();
    if (expected_consumption_count != focused_operation_count
            || observed_groups.size() != 2)
        fail("dedicated workload crossed the source-group boundary at an unexpected position");
    if (not finalize_tentative_double_rand_capture())
        fail("complete positive candidate was rejected");
    const auto* candidate = inspect_tentative_double_rand_capture();
    if (candidate == 0
            || candidate->consumed_outputs.size()
                    != expected_consumption_count
            || candidate->source_count != observed_groups.size()
            || candidate->source_count != 2
            || candidate->dealer_sources.size()
                    != size_t(P.num_players())
            || not validate_tentative_double_rand_candidate(*candidate)
            || not no_authentication_or_checkpoint_artifacts())
        fail("finalized positive candidate failed focused inspection");
    if (not tentative_double_rand_adapter_test_mode.empty())
    {
        run_tentative_double_rand_adapter_test_hook(
                tentative_double_rand_adapter_test_mode);
        return;
    }
    if (begin_tentative_double_rand_capture())
        fail("begin accepted while a finalized candidate was retained");

    const size_t finalized_source_count = candidate->source_count;
    const size_t finalized_consumption_count =
            candidate->consumed_outputs.size();
    const size_t finalized_producer_count = candidate->producer_records.size();
    const auto& replay_output = candidate->consumed_outputs.back();
    const size_t replay_record_ordinal =
            replay_output.partial_mult_transcript_record_ordinal;
    const auto& replay =
            partial_mult_transcripts.at(replay_record_ordinal);
    const auto replay_kind = replay_output.operation_kind;

    // Test-only isolation: temporarily retain the valid finalized state on
    // this call's stack while the sole member state executes a fresh failed
    // duplicate round. No second live AtlasGsz capture state is published.
    TentativeDoubleRandCaptureState retained_valid_state =
            std::move(tentative_double_rand_capture_state);
    tentative_double_rand_capture_state =
            TentativeDoubleRandCaptureState{};
    if (not begin_tentative_double_rand_capture()
            || not capture_completed_ordinary_double_rand(
                    replay, replay_record_ordinal, replay_kind)
            || capture_completed_ordinary_double_rand(
                    replay, replay_record_ordinal, replay_kind))
        fail("duplicate exact-output replay was not rejected");
    if (tentative_double_rand_capture_state.active
            || tentative_double_rand_capture_state.finalized_candidate
            || not tentative_double_rand_capture_state.producer_records.empty()
            || not tentative_double_rand_capture_state.consumptions.empty())
        fail("failed duplicate round retained tentative state");
    tentative_double_rand_capture_state = std::move(retained_valid_state);
    candidate = inspect_tentative_double_rand_capture();
    if (candidate == 0
            || not validate_tentative_double_rand_candidate(*candidate))
        fail("duplicate negative test altered the valid candidate");

    TentativeDoubleRandCaptureCandidate malformed = *candidate;
    malformed.dealer_sources.front().sources.pop_back();
    if (validate_tentative_double_rand_candidate(malformed)
            || not validate_tentative_double_rand_candidate(*candidate))
        fail("malformed candidate validation was not isolated and atomic");

    discard_tentative_double_rand_capture();
    if (tentative_double_rand_capture_state.active
            || tentative_double_rand_capture_state.finalized_candidate
            || not tentative_double_rand_capture_state.producer_records.empty()
            || not tentative_double_rand_capture_state.consumptions.empty()
            || not no_authentication_or_checkpoint_artifacts())
        fail("discard did not leave all tentative state empty");

    tentative_double_rand_capture_test_hook_ran = true;
    if (P.my_num() == 0)
        cout << "ATLAS_GSZ_AUTH_TEST tentative-double-rand-capture"
             << " PASS consumptions=" << finalized_consumption_count
             << " producer_records=" << finalized_producer_count
             << " unique_source_groups=" << finalized_source_count
             << " dealers=" << P.num_players()
             << " source_order=producer-then-group"
             << " dealer_order=ascending"
             << " exact_output_dedup=rejected"
             << " source_group_dedup=exact"
             << " operation_kinds=scalar-and-dot"
             << " concrete_e_t_sources=" << finalized_consumption_count
             << " e_t_binding=exact-real-wrapper"
             << " degree_t_derivations=exact"
             << " degree_2t=evidence-only"
             << " malformed_candidate=atomically-rejected"
             << " dealer_batches=0 handles=0 ftag_chunks=0"
             << " checkpoints=0 authentication_invocations=0"
             << endl;
}

template<class T>
bool AtlasGsz<T>::agree_base_field_ftag_chunk_width()
{
    static_assert(sizeof(uint64_t) == 8,
            "AtlasGsz requires an eight-byte uint64_t");
    auto& state = optimistic_authentication_state;
    if (state.base_field_ftag_chunk_width_agreed)
        return true;

    SentCommunicationAccumulator communication(
            P, state.base_field_ftag_chunk_width_agreement_communication);
    vector<octetStream> width_streams(P.num_players());
    const uint64_t selected_width = base_field_ftag_chunk_width_;
    width_streams.at(P.my_num()).store(selected_width);
    P.Broadcast_Receive(width_streams);
    P.Check_Broadcast();

    bool agreed = true;
    for (int player = 0; player < P.num_players(); player++)
    {
        uint64_t received_width = 0;
        width_streams.at(player).get(received_width);
        if (not width_streams.at(player).done())
            throw invalid_argument(
                    "AtlasGsz: malformed base-field FTag chunk-width agreement message");
        if (received_width != base_field_ftag_chunk_width_)
            agreed = false;
    }
    if (not agreed)
        throw invalid_argument(
                "AtlasGsz: parties selected different base-field FTag chunk widths");

    state.base_field_ftag_chunk_width_agreed = true;
    return true;
}

template<class T>
AtlasGsz<T>::~AtlasGsz()
{
    if (not x_verify.empty())
        request_check(VerificationBatchFlushReason::destructor);
    else
        check();
    check_opened_values();
    print_communication_audit_summary();
}

template<class T>
size_t AtlasGsz<T>::effective_max_before_check() const
{
    if (not honest_batch_integration_test_mode.empty())
        return 4;
    return AtlasConfig::max_before_check;
}

template<class T>
bool AtlasGsz<T>::automatic_ordinary_integration_enabled() const
{
    // The pre-existing tentative-capture/one-shot-adapter modes remain
    // isolated characterization hooks. Their adapter still uses the same
    // freeze and authenticate phases consecutively.
    return not tentative_double_rand_capture_test_enabled;
}

template<class T>
bool AtlasGsz<T>::communication_audit_enabled() const
{
    const char* audit = getenv("ATLAS_GSZ_COMM_AUDIT");
    return audit != 0 && string(audit) == "1";
}

template<class T>
bool AtlasGsz<T>::replace_empty_preprocessing_initialization_wrapper()
{
    auto& integrated = integrated_ordinary_batch_state;
    if (not integrated.wrapper_operation_active
            || integrated.wrapper_operation_kind
                    != OrdinaryDoubleRandOperationKind::
                            scalar_multiplication
            || integrated.wrapper_pending_results != 0
            || integrated.wrapper_operation_coordinate_start != 0
            || not x_verify.empty() || not y_verify.empty()
            || not z_verify.empty() || not partial_mult_transcripts.empty()
            || integrated.frozen_batch)
        return false;

    // BitPrep::set_protocol() initializes its independently owned protocol
    // branch with init_mul() but does not prepare an operation. AtlasPrep's
    // later mul-public callback is therefore allowed to replace only this
    // exact empty prelude. A real prepared operation can never take this
    // path. The callback then enters the normal noneligible record/check
    // lifecycle on that same independently checked branch.
    if (tentative_double_rand_capture_state.active)
        discard_tentative_double_rand_capture();
    if (tentative_double_rand_capture_state.active
            || tentative_double_rand_capture_state.finalized_candidate
            || not tentative_double_rand_capture_state
                    .producer_records.empty()
            || not tentative_double_rand_capture_state
                    .consumptions.empty())
        throw logic_error(
                "AtlasGsz: empty preprocessing initialization wrapper retained capture evidence");

    integrated.wrapper_operation_active = false;
    integrated.wrapper_operation_kind =
            OrdinaryDoubleRandOperationKind::noneligible;
    integrated.wrapper_operation_coordinate_start = 0;
    integrated.wrapper_pending_results = 0;
    integrated.lifecycle = OrdinaryBatchLifecycle::idle;
    integrated.current_verification_batch_serial = 0;
    integrated.pending_flush_reason = VerificationBatchFlushReason::none;
    integrated.preprocessing_initialization_wrappers_replaced++;
    return true;
}

template<class T>
void AtlasGsz<T>::ensure_wrapper_entry_allowed(const char* operation)
{
    auto& integrated = integrated_ordinary_batch_state;
    if (integrated.lifecycle == OrdinaryBatchLifecycle::checking_gs20
            || integrated.lifecycle
                    == OrdinaryBatchLifecycle::authenticating_sources
            || integrated.lifecycle == OrdinaryBatchLifecycle::failed)
        throw logic_error(string("AtlasGsz: wrapper entry during fatal or internal phase: ")
                + operation);
}

template<class T>
void AtlasGsz<T>::enter_verification_operation(
        OrdinaryDoubleRandOperationKind operation_kind)
{
    ensure_wrapper_entry_allowed("verification operation");
    maybe_check();
    auto& integrated = integrated_ordinary_batch_state;
    if (integrated.wrapper_operation_active)
        throw logic_error(
                "AtlasGsz: overlapping verification wrapper operations");
    const bool eligible = operation_kind
                    == OrdinaryDoubleRandOperationKind::scalar_multiplication
            || operation_kind
                    == OrdinaryDoubleRandOperationKind::dot_product;

    if (automatic_ordinary_integration_enabled())
    {
        if (eligible && not x_verify.empty()
                && integrated.lifecycle !=
                        OrdinaryBatchLifecycle::capturing_ordinary)
            request_check(VerificationBatchFlushReason::eligibility_boundary);
        else if (not eligible && not x_verify.empty()
                && integrated.lifecycle ==
                        OrdinaryBatchLifecycle::capturing_ordinary)
            request_check(VerificationBatchFlushReason::eligibility_boundary);
    }

    if (x_verify.empty())
    {
        if (integrated.next_verification_batch_serial == 0)
            throw overflow_error(
                    "AtlasGsz: verification-batch serial exhausted");
        integrated.current_verification_batch_serial =
                integrated.next_verification_batch_serial++;
        integrated.pending_flush_reason =
                VerificationBatchFlushReason::none;
        if (eligible && automatic_ordinary_integration_enabled())
        {
            if (not begin_tentative_double_rand_capture())
                throw logic_error(
                        "AtlasGsz: automatic ordinary capture could not begin");
            integrated.lifecycle =
                    OrdinaryBatchLifecycle::capturing_ordinary;
        }
        else if (automatic_ordinary_integration_enabled())
            integrated.lifecycle = OrdinaryBatchLifecycle::idle;
    }
    else if (eligible && automatic_ordinary_integration_enabled()
            && (integrated.lifecycle
                            != OrdinaryBatchLifecycle::capturing_ordinary
                    || not tentative_double_rand_capture_state.active))
        throw logic_error(
                "AtlasGsz: eligible operation entered without active capture");

    integrated.wrapper_operation_active = true;
    integrated.wrapper_operation_kind = operation_kind;
    integrated.wrapper_operation_coordinate_start = x_verify.size();
    integrated.wrapper_pending_results = 0;
}

template<class T>
void AtlasGsz<T>::finish_verification_operation(
        OrdinaryDoubleRandOperationKind operation_kind,
        size_t coordinate_count)
{
    auto& integrated = integrated_ordinary_batch_state;
    if (not integrated.wrapper_operation_active
            || integrated.wrapper_operation_kind != operation_kind
            || coordinate_count == 0
            || integrated.wrapper_pending_results == 0)
        throw logic_error(
                "AtlasGsz: wrapper operation completed with inconsistent coordinate coverage");
    if (automatic_ordinary_integration_enabled()
            && (operation_kind
                        == OrdinaryDoubleRandOperationKind::
                                scalar_multiplication
                    || operation_kind
                        == OrdinaryDoubleRandOperationKind::dot_product))
    {
        if (operation_kind
                == OrdinaryDoubleRandOperationKind::scalar_multiplication)
            integrated.ordinary_scalar_operations++;
        else
            integrated.ordinary_dot_operations++;
        integrated.ordinary_operations++;
        integrated.x_verify_coordinates += coordinate_count;
        integrated.partial_transcripts++;
    }
    integrated.wrapper_pending_results--;
    if (integrated.wrapper_pending_results == 0)
    {
        integrated.wrapper_operation_active = false;
        integrated.wrapper_operation_kind =
                OrdinaryDoubleRandOperationKind::noneligible;
        integrated.wrapper_operation_coordinate_start = 0;
    }
}

template<class T>
bool AtlasGsz<T>::verification_batch_is_eligible_ordinary() const
{
    if (partial_mult_transcripts.empty())
        return false;
    for (const auto& record : partial_mult_transcripts)
        if ((record.operation_kind
                        != OrdinaryDoubleRandOperationKind::
                                scalar_multiplication
                    && record.operation_kind
                        != OrdinaryDoubleRandOperationKind::dot_product)
                || record.verification_batch_serial
                        != integrated_ordinary_batch_state
                                .current_verification_batch_serial)
            return false;
    return true;
}

template<class T>
void AtlasGsz<T>::request_check(VerificationBatchFlushReason reason)
{
    if (x_verify.empty())
        return;
    integrated_ordinary_batch_state.pending_flush_reason = reason;
    check();
}

template <class T>
inline void AtlasGsz<T>::maybe_check()
{
    if (x_verify.size() >= effective_max_before_check()) {
        request_check(VerificationBatchFlushReason::threshold);
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
        if (not record.transcript.special_sharing_support.empty())
        {
            const auto& support =
                    record.transcript.special_sharing_support;
            assert(support.size()
                    == size_t(ShamirMachine::s().threshold + 1));
            assert(is_sorted(support.begin(), support.end()));
            assert(adjacent_find(support.begin(), support.end())
                    == support.end());
            assert(find(support.begin(), support.end(), batch_king)
                    != support.end());
            assert(support.front() >= 0);
            assert(support.back() < P.num_players());
            if (find(support.begin(), support.end(), P.my_num())
                    == support.end())
                assert(record.transcript.e_t == T{0});
        }
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

        vector<int> reconstruction_support =
                current_virtual_transcript.special_sharing_support;
        if (reconstruction_support.empty())
            for (int i = 0; i < t + 1; i++)
                reconstruction_support.push_back(i);
        auto distributed_factors = Shamir<T>::get_rec_factors(
                reconstruction_support);
        for (size_t i = 0; i < reconstruction_support.size(); i++)
            distributed_secret += current_virtual_king_evidence
                    .distributed_e_t.at(reconstruction_support.at(i))
                    * distributed_factors.at(i);

        assert(received_secret == distributed_secret);

        if (not current_virtual_transcript
                .special_sharing_support.empty())
            for (int party = 0; party < P.num_players(); party++)
                if (find(reconstruction_support.begin(),
                        reconstruction_support.end(), party)
                        == reconstruction_support.end())
                    assert(current_virtual_king_evidence
                            .distributed_e_t.at(party)
                            == typename Atlas<T>::share_value_type{});
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
typename T::open_type AtlasGsz<T>::sample_nonzero_agreed_challenge()
{
    typename T::open_type challenge{};
    do
        challenge = sample_agreed_challenge();
    while (challenge == typename T::open_type{});
    return challenge;
}

template<class T>
vector<typename T::open_type> AtlasGsz<T>::make_twisted_sharing(
        const typename T::open_type& value,
        int degree,
        int holder)
{
    assert(0 <= holder && holder < P.num_players());
    assert(degree > 0);

    // f(0)=0 and f(alpha_holder)=value.  Coefficients of X^2,...,
    // X^degree are random and the coefficient of X is solved from the
    // second constraint.
    vector<typename T::open_type> coefficients(degree + 1);
    coefficients.at(0) = typename T::open_type{};
    for (int k = 2; k <= degree; k++)
        coefficients.at(k).randomize(optimistic_authentication_prng);

    typename T::open_type holder_point(holder + 1);
    typename T::open_type power = holder_point * holder_point;
    typename T::open_type remainder{};
    for (int k = 2; k <= degree; k++)
    {
        remainder += coefficients.at(k) * power;
        power *= holder_point;
    }
    coefficients.at(1) =
            (value - remainder) * holder_point.invert();

    vector<typename T::open_type> shares(P.num_players());
    for (int player = 0; player < P.num_players(); player++)
    {
        typename T::open_type point(player + 1);
        typename T::open_type point_power(1);
        for (int k = 1; k <= degree; k++)
        {
            point_power *= point;
            shares.at(player) += coefficients.at(k) * point_power;
        }
    }
    assert(shares.at(holder) == value);
    return shares;
}

template<class T>
typename T::open_type AtlasGsz<T>::reconstruct_twisted_at_holder(
        const vector<typename T::open_type>& shares,
        int holder) const
{
    assert(shares.size() == size_t(P.num_players()));
    assert(0 <= holder && holder < P.num_players());

    vector<int> points;
    vector<typename T::open_type> values;
    points.reserve(P.num_players());
    values.reserve(P.num_players());
    points.push_back(-1); // x=0, where every twisted sharing is zero
    values.push_back(typename T::open_type{});
    for (int player = 0; player < P.num_players(); player++)
        if (player != holder)
        {
            points.push_back(player);
            values.push_back(shares.at(player));
        }

    auto factors = Shamir<T>::get_rec_factors(points, holder);
    typename T::open_type result{};
    for (size_t i = 0; i < values.size(); i++)
        result += values.at(i) * factors.at(i);
    return result;
}

template<class T>
bool AtlasGsz<T>::twisted_sharing_is_degree_at_most(
        const vector<typename T::open_type>& shares,
        int holder,
        int degree) const
{
    assert(shares.size() == size_t(P.num_players()));
    assert(0 <= holder && holder < P.num_players());
    assert(degree > 0);

    vector<int> base_points;
    vector<typename T::open_type> base_values;
    base_points.push_back(-1);
    base_values.push_back(typename T::open_type{});
    for (int player = 0;
            player < P.num_players()
                    && base_points.size() < size_t(degree + 1);
            player++)
        if (player != holder)
        {
            base_points.push_back(player);
            base_values.push_back(shares.at(player));
        }
    if (base_points.size() != size_t(degree + 1))
        return false;

    for (int player = 0; player < P.num_players(); player++)
        if (player != holder)
        {
            auto factors = Shamir<T>::get_rec_factors(
                    base_points, player);
            typename T::open_type expected{};
            for (size_t k = 0; k < base_values.size(); k++)
                expected += base_values.at(k) * factors.at(k);
            if (expected != shares.at(player))
                return false;
        }
    return true;
}

template<class T>
typename AtlasGsz<T>::LongTermMuKeyRecord*
AtlasGsz<T>::find_long_term_mu_key(int verifier, int holder)
{
    for (auto& key : optimistic_authentication_state.keys)
        if (key.verifier == verifier && key.holder == holder)
            return &key;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::LongTermMuKeyRecord*
AtlasGsz<T>::find_long_term_mu_key(int verifier, int holder) const
{
    for (const auto& key : optimistic_authentication_state.keys)
        if (key.verifier == verifier && key.holder == holder)
            return &key;
    return 0;
}

template<class T>
typename AtlasGsz<T>::BatchNuMaterialRecord*
AtlasGsz<T>::find_batch_nu_material(uint64_t batch_id,
        size_t chunk_ordinal, bool check_mask, uint64_t key_epoch,
        int verifier, int holder)
{
    for (auto& material : optimistic_authentication_state.nu_material)
        if (material.batch_id == batch_id
                && material.chunk_ordinal == chunk_ordinal
                && material.check_mask == check_mask
                && material.key_epoch == key_epoch
                && material.verifier == verifier
                && material.holder == holder)
            return &material;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::BatchNuMaterialRecord*
AtlasGsz<T>::find_batch_nu_material(uint64_t batch_id,
        size_t chunk_ordinal, bool check_mask, uint64_t key_epoch,
        int verifier, int holder) const
{
    for (const auto& material : optimistic_authentication_state.nu_material)
        if (material.batch_id == batch_id
                && material.chunk_ordinal == chunk_ordinal
                && material.check_mask == check_mask
                && material.key_epoch == key_epoch
                && material.verifier == verifier
                && material.holder == holder)
            return &material;
    return 0;
}

template<class T>
typename AtlasGsz<T>::HolderTagRecord*
AtlasGsz<T>::find_holder_tag(uint64_t batch_id, size_t chunk_ordinal,
        bool check_mask, uint64_t key_epoch, int verifier, int holder)
{
    for (auto& tag : optimistic_authentication_state.holder_tags)
        if (tag.batch_id == batch_id
                && tag.chunk_ordinal == chunk_ordinal
                && tag.check_mask == check_mask
                && tag.key_epoch == key_epoch
                && tag.verifier == verifier
                && tag.holder == holder)
            return &tag;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::HolderTagRecord*
AtlasGsz<T>::find_holder_tag(uint64_t batch_id, size_t chunk_ordinal,
        bool check_mask, uint64_t key_epoch, int verifier,
        int holder) const
{
    for (const auto& tag : optimistic_authentication_state.holder_tags)
        if (tag.batch_id == batch_id
                && tag.chunk_ordinal == chunk_ordinal
                && tag.check_mask == check_mask
                && tag.key_epoch == key_epoch
                && tag.verifier == verifier
                && tag.holder == holder)
            return &tag;
    return 0;
}

template<class T>
typename AtlasGsz<T>::DealerSourceBatchRecord*
AtlasGsz<T>::find_dealer_source_batch(uint64_t batch_id)
{
    for (auto& batch : optimistic_authentication_state.dealer_batches)
        if (batch.batch_id == batch_id)
            return &batch;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::DealerSourceBatchRecord*
AtlasGsz<T>::find_dealer_source_batch(uint64_t batch_id) const
{
    for (const auto& batch : optimistic_authentication_state.dealer_batches)
        if (batch.batch_id == batch_id)
            return &batch;
    return 0;
}

template<class T>
typename AtlasGsz<T>::OptimisticCheckpointRecord*
AtlasGsz<T>::find_optimistic_checkpoint(uint64_t checkpoint_id)
{
    for (auto& checkpoint : optimistic_authentication_state.checkpoints)
        if (checkpoint.checkpoint_id == checkpoint_id)
            return &checkpoint;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::OptimisticCheckpointRecord*
AtlasGsz<T>::find_optimistic_checkpoint(uint64_t checkpoint_id) const
{
    for (const auto& checkpoint : optimistic_authentication_state.checkpoints)
        if (checkpoint.checkpoint_id == checkpoint_id)
            return &checkpoint;
    return 0;
}

template<class T>
bool AtlasGsz<T>::establish_optimistic_authentication_keys()
{
    auto& state = optimistic_authentication_state;
    agree_base_field_ftag_chunk_width();
    if (state.keys_established)
        return state.keys_checked;

    SentCommunicationAccumulator communication(
            P, state.key_establishment_communication);
    const size_t width = base_field_ftag_chunk_width();
    state.keys.clear();
    const size_t player_count = size_t(P.num_players());
    const size_t key_count = checked_size_product(player_count,
            player_count - 1,
            "AtlasGsz: verifier-holder key count overflow");
    if (key_count > state.keys.max_size())
        throw length_error(
                "AtlasGsz: verifier-holder key count exceeds vector capacity");
    state.keys.reserve(key_count);
    for (int verifier = 0; verifier < P.num_players(); verifier++)
        for (int holder = 0; holder < P.num_players(); holder++)
            if (verifier != holder)
            {
                LongTermMuKeyRecord key{};
                key.key_id = state.next_key_id++;
                key.epoch = state.key_epoch;
                key.verifier = verifier;
                key.holder = holder;
                key.owns_clear_mu = P.my_num() == verifier;
                key.has_local_twisted_share = P.my_num() != holder;
                if (key.owns_clear_mu)
                {
                    if (width > key.clear_mu.max_size())
                        throw length_error(
                                "AtlasGsz: base-field FTag mu width exceeds vector capacity");
                    key.clear_mu.resize(width);
                }
                if (key.has_local_twisted_share)
                {
                    if (width > key.local_twisted_share.max_size())
                        throw length_error(
                                "AtlasGsz: twisted mu width exceeds vector capacity");
                    key.local_twisted_share.resize(width);
                }
                state.keys.push_back(key);
            }
    assert(state.keys.size() == key_count);

    vector<octetStream> outgoing(P.num_players());
    for (auto& key : state.keys)
        if (P.my_num() == key.verifier)
            for (size_t k = 0; k < width; k++)
            {
                key.clear_mu.at(k).randomize(
                        optimistic_authentication_prng);
                auto sharing = make_twisted_sharing(
                        key.clear_mu.at(k),
                        ShamirMachine::s().threshold,
                        key.holder);
                key.local_twisted_share.at(k) =
                        sharing.at(P.my_num());
                for (int recipient = 0;
                        recipient < P.num_players(); recipient++)
                    if (recipient != P.my_num()
                            && recipient != key.holder)
                        sharing.at(recipient).pack(
                                outgoing.at(recipient));
            }

    vector<octetStream> incoming;
    P.send_receive_all(outgoing, incoming);
    assert(incoming.size() == size_t(P.num_players()));
    for (auto& key : state.keys)
        if (P.my_num() != key.verifier
                && P.my_num() != key.holder)
            for (size_t k = 0; k < width; k++)
                key.local_twisted_share.at(k).unpack(
                        incoming.at(key.verifier));
    for (int sender = 0; sender < P.num_players(); sender++)
        if (sender != P.my_num())
            assert(not incoming.at(sender).left());
    for (const auto& key : state.keys)
    {
        assert(not key.owns_clear_mu || key.clear_mu.size() == width);
        assert(not key.has_local_twisted_share
                || key.local_twisted_share.size() == width);
    }

    state.keys_established = true;
    state.key_establishment_runs++;
    if (not check_optimistic_authentication_keys())
    {
        state.status = OptimisticAuthenticationStatus::
                RecoveryNotImplemented;
        state.failure_class =
                OptimisticAuthenticationFailureClass::key_check;
        return false;
    }
    return true;
}

template<class T>
bool AtlasGsz<T>::check_optimistic_authentication_keys()
{
    auto& state = optimistic_authentication_state;
    assert(state.keys_established);
    assert(state.base_field_ftag_chunk_width_agreed);
    const int t = ShamirMachine::s().threshold;
    const size_t width = base_field_ftag_chunk_width();
    state.check_key_runs++;

    // Restricted e=1 Check-Key: a fresh twisted sharing of random rho masks
    // every public reusable-key combination. The clear rho values exist only
    // transiently on their verifier processes during this execution.
    vector<typename T::open_type> local_mask_shares(state.keys.size());
    vector<typename T::open_type> verifier_mask_values(state.keys.size());
    vector<octetStream> outgoing(P.num_players());
    for (size_t index = 0; index < state.keys.size(); index++)
    {
        const auto& key = state.keys.at(index);
        assert(not key.has_local_twisted_share
                || key.local_twisted_share.size() == width);
        assert(not key.owns_clear_mu || key.clear_mu.size() == width);
        if (P.my_num() == key.verifier)
        {
            verifier_mask_values.at(index).randomize(
                    optimistic_authentication_prng);
            auto mask_sharing = make_twisted_sharing(
                    verifier_mask_values.at(index), t, key.holder);
            local_mask_shares.at(index) =
                    mask_sharing.at(P.my_num());
            for (int recipient = 0;
                    recipient < P.num_players(); recipient++)
                if (recipient != P.my_num()
                        && recipient != key.holder)
                    mask_sharing.at(recipient).pack(
                            outgoing.at(recipient));
        }
    }

    vector<octetStream> incoming;
    P.send_receive_all(outgoing, incoming);
    for (size_t index = 0; index < state.keys.size(); index++)
    {
        const auto& key = state.keys.at(index);
        if (P.my_num() != key.verifier
                && P.my_num() != key.holder)
            local_mask_shares.at(index).unpack(
                    incoming.at(key.verifier));
    }
    for (int sender = 0; sender < P.num_players(); sender++)
        if (sender != P.my_num())
            assert(not incoming.at(sender).left());

    typename T::open_type challenge =
            sample_nonzero_agreed_challenge();
    vector<octetStream> combined_streams(P.num_players());
    for (size_t index = 0; index < state.keys.size(); index++)
    {
        const auto& key = state.keys.at(index);
        if (P.my_num() == key.holder)
            continue;
        assert(key.has_local_twisted_share);
        typename T::open_type combined = local_mask_shares.at(index);
        typename T::open_type power = challenge;
        for (size_t k = 0; k < width; k++)
        {
            combined += power * key.local_twisted_share.at(k);
            power *= challenge;
        }
        combined.pack(combined_streams.at(P.my_num()));
    }
    P.Broadcast_Receive(combined_streams);
    P.Check_Broadcast();

    vector<vector<typename T::open_type>> combined(
            state.keys.size(),
            vector<typename T::open_type>(P.num_players()));
    for (int sender = 0; sender < P.num_players(); sender++)
        for (size_t index = 0; index < state.keys.size(); index++)
            if (sender != state.keys.at(index).holder)
                combined.at(index).at(sender).unpack(
                        combined_streams.at(sender));
    for (const auto& stream : combined_streams)
        assert(not stream.left());

    bool local_pass = true;
    for (size_t index = 0; index < state.keys.size(); index++)
    {
        const auto& key = state.keys.at(index);
        if (not twisted_sharing_is_degree_at_most(
                combined.at(index), key.holder, t))
            local_pass = false;
        if (P.my_num() == key.verifier)
        {
            assert(key.owns_clear_mu);
            typename T::open_type unmasked_key_combination{};
            typename T::open_type power = challenge;
            for (size_t k = 0; k < width; k++)
            {
                unmasked_key_combination += power * key.clear_mu.at(k);
                power *= challenge;
            }
            auto reconstructed = reconstruct_twisted_at_holder(
                    combined.at(index), key.holder);
            bool masking_equation = reconstructed
                    == verifier_mask_values.at(index)
                            + unmasked_key_combination;
            if (not masking_equation)
                local_pass = false;
            else
                state.check_key_masking_equation_checks++;
        }
    }

    vector<octetStream> vote_streams(P.num_players());
    typename T::open_type(local_pass ? 1 : 0).pack(
            vote_streams.at(P.my_num()));
    P.Broadcast_Receive(vote_streams);
    P.Check_Broadcast();
    bool all_pass = true;
    for (int player = 0; player < P.num_players(); player++)
    {
        typename T::open_type vote;
        vote.unpack(vote_streams.at(player));
        assert(not vote_streams.at(player).left());
        if (vote != typename T::open_type(1))
            all_pass = false;
    }

    state.keys_checked = all_pass;
    for (auto& key : state.keys)
        key.checked = all_pass;
    return all_pass;
}

template<class T>
vector<T> AtlasGsz<T>::deal_optimistic_source_values(
        int dealer,
        const vector<typename T::open_type>& dealer_values,
        size_t count)
{
    assert(0 <= dealer && dealer < P.num_players());
    assert(P.my_num() != dealer || dealer_values.size() == count);

    optimistic_authentication_input.reset_all(P);
    for (size_t i = 0; i < count; i++)
        if (P.my_num() == dealer)
            optimistic_authentication_input.add_mine(
                    dealer_values.at(i));
        else
            optimistic_authentication_input.add_other(dealer);
    optimistic_authentication_input.exchange();

    vector<T> result;
    result.reserve(count);
    for (size_t i = 0; i < count; i++)
        result.push_back(
                optimistic_authentication_input.finalize(dealer));
    return result;
}

template<class T>
uint64_t AtlasGsz<T>::register_dealer_source_batch(
        int dealer, const vector<T>& local_source_shares)
{
    assert(0 <= dealer && dealer < P.num_players());
    assert(not local_source_shares.empty());
    auto& state = optimistic_authentication_state;

    DealerSourceBatchRecord batch{};
    const uint64_t batch_id = state.next_batch_id;
    batch.batch_id = batch_id;
    batch.dealer = dealer;
    batch.local_source_shares = local_source_shares;
    batch.source_ordinals.reserve(local_source_shares.size());
    for (size_t ordinal = 0; ordinal < local_source_shares.size(); ordinal++)
        batch.source_ordinals.push_back(ordinal);
    assert(batch.source_ordinals.size()
            == batch.local_source_shares.size());
    state.dealer_batches.push_back(std::move(batch));
    state.next_batch_id = batch_id + 1;
    return batch_id;
}

template<class T>
void AtlasGsz<T>::register_tentative_double_rand_batches_atomically(
        vector<DealerSourceBatchRecord>& prospective_batches,
        uint64_t next_batch_id_after)
{
    auto& state = optimistic_authentication_state;
    assert(prospective_batches.size() == size_t(P.num_players()));
    assert(state.dealer_batches.capacity()
            >= state.dealer_batches.size() + prospective_batches.size());
    assert(next_batch_id_after > state.next_batch_id);
    for (size_t dealer = 0; dealer < prospective_batches.size(); dealer++)
    {
        const auto& batch = prospective_batches.at(dealer);
        assert(batch.dealer == int(dealer));
        assert(batch.batch_id == state.next_batch_id + dealer);
        assert(not batch.local_source_shares.empty());
        assert(batch.source_ordinals.size()
                == batch.local_source_shares.size());
    }

    // Capacity and every complete record were prepared before the candidate
    // was claimed. Moving the vector-backed records cannot allocate, so the
    // authoritative registry receives the whole dealer set without a prefix.
    static_assert(
            std::is_nothrow_move_constructible<
                    DealerSourceBatchRecord>::value,
            "DealerSourceBatchRecord must be nothrow move constructible for prefix-free atomic registration");
    state.dealer_batches.insert(state.dealer_batches.end(),
            make_move_iterator(prospective_batches.begin()),
            make_move_iterator(prospective_batches.end()));
    state.next_batch_id = next_batch_id_after;
}

template<class T>
bool AtlasGsz<T>::masked_degree_t_consistency_check(
        const vector<T>& local_shares,
        bool inject_bad_published_share,
        typename T::open_type& challenge,
        vector<typename T::open_type>& published_shares)
{
    assert(not local_shares.empty());

    // The random mask and complete input vector are fixed before sampling the
    // public compression challenge. Zero is valid in this base-field e=1
    // realization.
    T compressed_sharing = get_random();
    challenge = sample_agreed_challenge();
    typename T::open_type power = challenge;
    for (const auto& local_share : local_shares)
    {
        compressed_sharing += local_share * power;
        power *= challenge;
    }

    // Focused deterministic test-only injection. It corrupts one party's
    // published compressed share independently of the challenge value.
    if (inject_bad_published_share && P.my_num() == 0)
        compressed_sharing += typename T::open_type(1);

    auto published = broadcast_local_shares(
            vector<T>(1, compressed_sharing));
    assert(published.size() == 1);
    published_shares = published.at(0);
    return classify_degree_t_sharing(published_shares).consistent;
}

template<class T>
bool AtlasGsz<T>::verify_dealer_source_batch(
        DealerSourceBatchRecord& batch,
        bool inject_bad_published_share)
{
    assert(batch.authentication_state
            == DealerBatchAuthenticationState::pending);
    assert(not batch.local_source_shares.empty());
    assert(not batch.verify_sharing_completed);
    assert(not batch.verify_sharing_failure_evidence);

    SentCommunicationAccumulator communication(
            P, optimistic_authentication_state
                    .verify_sharing_communication);
    optimistic_authentication_state.verify_sharing_invocations++;
    typename T::open_type challenge{};
    vector<typename T::open_type> published_shares;
    bool consistent = masked_degree_t_consistency_check(
            batch.local_source_shares, inject_bad_published_share,
            challenge, published_shares);
    batch.verify_sharing_completed = true;
    batch.verify_sharing_passed = consistent;
    if (consistent)
        return true;

    auto evidence = make_unique<DealerBatchFailureEvidence>();
    evidence->challenge = challenge;
    evidence->published_shares = std::move(published_shares);
    batch.verify_sharing_failure_evidence = std::move(evidence);
    return false;
}

template<class T>
bool AtlasGsz<T>::prepare_and_verify_base_sharing(
        DealerSourceBatchRecord& batch,
        vector<T>& base_sharing,
        bool inject_bad_published_share)
{
    assert(batch.authentication_state
            == DealerBatchAuthenticationState::pending);
    assert(not batch.base_sharing_check_completed);
    assert(not batch.base_sharing_failure_evidence);
    assert(base_sharing.empty());

    SentCommunicationAccumulator communication(
            P, optimistic_authentication_state
                    .base_sharing_communication);
    optimistic_authentication_state.base_sharing_checks++;
    const size_t width = base_field_ftag_chunk_width();
    vector<typename T::open_type> dealer_values;
    if (P.my_num() == batch.dealer)
    {
        if (width > dealer_values.max_size())
            throw length_error(
                    "AtlasGsz: BaseSharing width exceeds vector capacity");
        dealer_values.resize(width);
        for (auto& value : dealer_values)
            value.randomize(optimistic_authentication_prng);
    }
    base_sharing = deal_optimistic_source_values(
            batch.dealer, dealer_values, width);
    if (base_sharing.size() != width)
        throw logic_error(
                "AtlasGsz: BaseSharing does not have the configured base-field FTag chunk width");

    typename T::open_type challenge{};
    vector<typename T::open_type> published_shares;
    bool consistent = masked_degree_t_consistency_check(
            base_sharing, inject_bad_published_share,
            challenge, published_shares);
    batch.base_sharing_check_completed = true;
    batch.base_sharing_check_passed = consistent;
    if (consistent)
        return true;

    auto evidence = make_unique<DealerBatchFailureEvidence>();
    evidence->challenge = challenge;
    evidence->published_shares = std::move(published_shares);
    batch.base_sharing_failure_evidence = std::move(evidence);
    base_sharing.clear();
    return false;
}

template<class T>
vector<typename AtlasGsz<T>::BaseFieldFTagSourceChunk>
AtlasGsz<T>::source_chunks_for_batch(
        const DealerSourceBatchRecord& batch) const
{
    if (batch.source_ordinals.size()
            != batch.local_source_shares.size())
        throw logic_error(
                "AtlasGsz: dealer source ordinals and local shares have different dimensions");

    const size_t width = base_field_ftag_chunk_width();
    const size_t original_source_count =
            batch.local_source_shares.size();
    const size_t chunk_count =
            base_field_ftag_chunk_count(original_source_count);
    vector<BaseFieldFTagSourceChunk> chunks;
    if (chunk_count > chunks.max_size())
        throw length_error(
                "AtlasGsz: FTag chunk count exceeds vector capacity");
    chunks.reserve(chunk_count);
    for (size_t chunk_ordinal = 0;
            chunk_ordinal < chunk_count; chunk_ordinal++)
    {
        const size_t offset = checked_size_product(chunk_ordinal, width,
                "AtlasGsz: FTag source-chunk offset overflow");
        if (offset >= original_source_count)
            throw logic_error(
                    "AtlasGsz: invalid FTag source-chunk offset");
        const size_t count = min(width,
                original_source_count - offset);
        const size_t end = checked_size_sum(offset, count,
                "AtlasGsz: FTag source-chunk end overflow");
        if (count == 0 || count > width || end > original_source_count)
            throw logic_error(
                    "AtlasGsz: invalid FTag source-chunk source range");

        BaseFieldFTagSourceChunk chunk{};
        chunk.chunk_ordinal = chunk_ordinal;
        chunk.original_source_offset = offset;
        chunk.original_source_count = count;
        if (width > chunk.components.max_size())
            throw length_error(
                    "AtlasGsz: FTag chunk width exceeds vector capacity");
        chunk.components.assign(width, T{});
        for (size_t k = 0; k < count; k++)
            chunk.components.at(k) =
                    batch.local_source_shares.at(offset + k);
        chunks.push_back(chunk);
    }
    assert(chunks.size() == chunk_count);
    return chunks;
}

template<class T>
bool AtlasGsz<T>::compute_and_deliver_batch_tags(
        DealerSourceBatchRecord& batch,
        const vector<BaseFieldFTagSourceChunk>& source_chunks,
        bool check_mask,
        size_t& nu_begin,
        size_t& tag_begin)
{
    auto& state = optimistic_authentication_state;
    const int degree_2t = 2 * ShamirMachine::s().threshold;
    const size_t width = base_field_ftag_chunk_width();
    if (not state.keys_checked || source_chunks.empty())
        return false;
    for (size_t chunk_index = 0;
            chunk_index < source_chunks.size(); chunk_index++)
    {
        const auto& chunk = source_chunks.at(chunk_index);
        if (chunk.chunk_ordinal != chunk_index
                || chunk.components.size() != width
                || chunk.original_source_count == 0
                || chunk.original_source_count > width)
            return false;
    }
    for (const auto& key : state.keys)
        if ((key.owns_clear_mu && key.clear_mu.size() != width)
                || (key.has_local_twisted_share
                        && key.local_twisted_share.size() != width))
            return false;

    struct LocalTagMaterial
    {
        typename T::open_type nu_share{};
        typename T::open_type zero_share{};
        bool has_nu_share = false;
        bool has_zero_share = false;
    };
    const size_t n_instances = checked_size_product(
            state.keys.size(), source_chunks.size(),
            "AtlasGsz: FTag key/chunk record count overflow");
    vector<LocalTagMaterial> local_material;
    if (n_instances > local_material.max_size())
        throw length_error(
                "AtlasGsz: transient FTag material count exceeds vector capacity");
    local_material.resize(n_instances);
    const size_t expected_nu_records = checked_size_sum(
            state.nu_material.size(), n_instances,
            "AtlasGsz: FTag nu record count overflow");
    const size_t expected_tag_records = checked_size_sum(
            state.holder_tags.size(), n_instances,
            "AtlasGsz: FTag holder-tag record count overflow");
    if (expected_nu_records > state.nu_material.max_size()
            || expected_tag_records > state.holder_tags.max_size())
        throw length_error(
                "AtlasGsz: FTag record count exceeds vector capacity");
    state.nu_material.reserve(expected_nu_records);
    state.holder_tags.reserve(expected_tag_records);
    nu_begin = state.nu_material.size();
    tag_begin = state.holder_tags.size();
    vector<octetStream> outgoing(P.num_players());

    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        assert(key.checked);
        for (size_t chunk = 0; chunk < source_chunks.size(); chunk++)
        {
            const size_t index = checked_size_sum(
                    checked_size_product(key_index,
                            source_chunks.size(),
                            "AtlasGsz: FTag record index overflow"),
                    chunk, "AtlasGsz: FTag record index overflow");
            BatchNuMaterialRecord nu_record{};
            nu_record.batch_id = batch.batch_id;
            nu_record.chunk_ordinal = chunk;
            nu_record.check_mask = check_mask;
            nu_record.key_epoch = state.key_epoch;
            nu_record.verifier = key.verifier;
            nu_record.holder = key.holder;
            nu_record.owns_nu = P.my_num() == key.verifier;

            if (nu_record.owns_nu)
            {
                nu_record.nu.randomize(
                        optimistic_authentication_prng);

                auto nu_sharing = make_twisted_sharing(
                        nu_record.nu, degree_2t, key.holder);
                local_material.at(index).nu_share =
                        nu_sharing.at(P.my_num());
                local_material.at(index).has_nu_share = true;
                for (int recipient = 0;
                        recipient < P.num_players(); recipient++)
                    if (recipient != P.my_num()
                            && recipient != key.holder)
                        nu_sharing.at(recipient).pack(
                                outgoing.at(recipient));
            }
            state.nu_material.push_back(nu_record);

            HolderTagRecord tag_record{};
            tag_record.batch_id = batch.batch_id;
            tag_record.chunk_ordinal = chunk;
            tag_record.check_mask = check_mask;
            tag_record.key_epoch = state.key_epoch;
            tag_record.verifier = key.verifier;
            tag_record.holder = key.holder;
            tag_record.owns_tag = P.my_num() == key.holder;
            state.holder_tags.push_back(tag_record);

            if (P.my_num() == batch.dealer)
            {
                auto zero_sharing = make_twisted_sharing(
                        typename T::open_type{}, degree_2t,
                        key.holder);
                if (P.my_num() != key.holder)
                {
                    local_material.at(index).zero_share =
                            zero_sharing.at(P.my_num());
                    local_material.at(index).has_zero_share = true;
                }
                for (int recipient = 0;
                        recipient < P.num_players(); recipient++)
                    if (recipient != P.my_num()
                            && recipient != key.holder)
                        zero_sharing.at(recipient).pack(
                                outgoing.at(recipient));
            }
        }
    }
    assert(state.nu_material.size() == expected_nu_records);
    assert(state.holder_tags.size() == expected_tag_records);

    vector<octetStream> incoming;
    P.send_receive_all(outgoing, incoming);
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        for (size_t chunk = 0; chunk < source_chunks.size(); chunk++)
        {
            const size_t index = checked_size_sum(
                    checked_size_product(key_index,
                            source_chunks.size(),
                            "AtlasGsz: FTag record index overflow"),
                    chunk, "AtlasGsz: FTag record index overflow");
            if (P.my_num() == key.holder)
                continue;
            if (P.my_num() != key.verifier)
            {
                local_material.at(index).nu_share.unpack(
                        incoming.at(key.verifier));
                local_material.at(index).has_nu_share = true;
            }
            if (P.my_num() != batch.dealer)
            {
                local_material.at(index).zero_share.unpack(
                        incoming.at(batch.dealer));
                local_material.at(index).has_zero_share = true;
            }
        }
    }
    for (int sender = 0; sender < P.num_players(); sender++)
        if (sender != P.my_num())
            assert(not incoming.at(sender).left());

    vector<octetStream> tag_outgoing(P.num_players());
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        if (P.my_num() == key.holder)
            continue;
        assert(key.has_local_twisted_share);
        for (size_t chunk = 0; chunk < source_chunks.size(); chunk++)
        {
            const size_t index = checked_size_sum(
                    checked_size_product(key_index,
                            source_chunks.size(),
                            "AtlasGsz: FTag record index overflow"),
                    chunk, "AtlasGsz: FTag record index overflow");
            assert(local_material.at(index).has_nu_share);
            assert(local_material.at(index).has_zero_share);
            typename T::open_type tag_share =
                    local_material.at(index).nu_share
                    + local_material.at(index).zero_share;
            for (size_t k = 0; k < width; k++)
            {
                typename T::open_type source_share =
                        source_chunks.at(chunk).components.at(k);
                tag_share += key.local_twisted_share.at(k)
                        * source_share;
            }
            tag_share.pack(tag_outgoing.at(key.holder));
        }
    }

    vector<octetStream> tag_incoming;
    P.send_receive_all(tag_outgoing, tag_incoming);
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        if (P.my_num() != key.holder)
            continue;
        for (size_t chunk = 0; chunk < source_chunks.size(); chunk++)
        {
            vector<typename T::open_type> tag_shares(P.num_players());
            for (int sender = 0; sender < P.num_players(); sender++)
                if (sender != key.holder)
                    tag_shares.at(sender).unpack(
                            tag_incoming.at(sender));
            auto& tag = state.holder_tags.at(tag_begin
                    + key_index * source_chunks.size() + chunk);
            assert(tag.batch_id == batch.batch_id
                    && tag.chunk_ordinal == chunk
                    && tag.check_mask == check_mask
                    && tag.key_epoch == state.key_epoch
                    && tag.verifier == key.verifier
                    && tag.holder == key.holder && tag.owns_tag);
            tag.tag = reconstruct_twisted_at_holder(
                    tag_shares, key.holder);
        }
    }
    for (int sender = 0; sender < P.num_players(); sender++)
        if (sender != P.my_num())
            assert(not tag_incoming.at(sender).left());
    return true;
}

template<class T>
void AtlasGsz<T>::fail_global_authentication(
        GlobalAuthenticationInvocationRecord* invocation,
        DealerSourceBatchRecord* batch,
        OptimisticAuthenticationFailureClass failure_class,
        int verifier,
        int holder)
{
    auto& state = optimistic_authentication_state;
    state.status = OptimisticAuthenticationStatus::
            RecoveryNotImplemented;
    state.failure_class = failure_class;
    state.failed_batch_id = batch == 0 ? 0 : batch->batch_id;
    state.failed_verifier = verifier;
    state.failed_holder = holder;

    if (invocation != 0)
    {
        invocation->completed = true;
        invocation->passed = false;
        invocation->failure_class = failure_class;
        invocation->failed_verifier = verifier;
        invocation->failed_holder = holder;
        unordered_map<uint64_t, size_t> batch_indices;
        batch_indices.reserve(state.dealer_batches.size());
        for (size_t index = 0; index < state.dealer_batches.size(); index++)
            batch_indices.emplace(
                    state.dealer_batches.at(index).batch_id, index);
        for (const auto& member : invocation->members)
        {
            auto position = batch_indices.find(member.batch_id);
            auto* participating_batch =
                    position == batch_indices.end() ? nullptr
                    : &state.dealer_batches.at(position->second);
            if (participating_batch
                    && participating_batch->authentication_state
                            == DealerBatchAuthenticationState::pending)
            {
                participating_batch->authentication_state =
                        DealerBatchAuthenticationState::rejected;
                participating_batch->failure_class = failure_class;
                participating_batch->authenticated_handles.clear();
            }
        }
    }
    if (batch != 0
            && batch->authentication_state
                    == DealerBatchAuthenticationState::pending)
    {
        batch->authentication_state =
                DealerBatchAuthenticationState::rejected;
        batch->failure_class = failure_class;
        batch->authenticated_handles.clear();
    }
}

template<class T>
bool AtlasGsz<T>::prepare_global_authentication(
        GlobalAuthenticationInvocationRecord& invocation,
        const vector<uint64_t>& requested_batch_ids,
        GlobalAuthenticationWorkingSet& working,
        int inject_bad_verify_sharing_dealer,
        int inject_bad_base_sharing_dealer,
        GlobalAuthenticationTestFault test_fault)
{
    auto& state = optimistic_authentication_state;
    const size_t width = base_field_ftag_chunk_width();
    working.members.clear();
    invocation.members.clear();
    invocation.max_ftag_chunk_count = 0;

    const bool source_only = invocation.checkpoint_id == 0;
    const auto* checkpoint = source_only ? 0 :
            find_optimistic_checkpoint(invocation.checkpoint_id);
    if (requested_batch_ids.empty()
            || (not source_only && (checkpoint == 0
                    || checkpoint->sealed || checkpoint->promoted
                    || checkpoint->output_derivations.empty())))
    {
        fail_global_authentication(&invocation, 0,
                OptimisticAuthenticationFailureClass::
                    invocation_validation);
        return false;
    }

    unordered_map<uint64_t, size_t> batch_indices;
    batch_indices.reserve(state.dealer_batches.size());
    for (size_t index = 0; index < state.dealer_batches.size(); index++)
        if (not batch_indices.emplace(
                state.dealer_batches.at(index).batch_id, index).second)
        {
            fail_global_authentication(&invocation, 0,
                    OptimisticAuthenticationFailureClass::
                        invocation_validation);
            return false;
        }

    for (auto batch_id : requested_batch_ids)
    {
        auto position = batch_indices.find(batch_id);
        const auto* batch = position == batch_indices.end() ? nullptr
                : &state.dealer_batches.at(position->second);
        GlobalAuthenticationInvocationMember member{};
        member.batch_id = batch_id;
        member.dealer = batch == 0 ? -1 : batch->dealer;
        invocation.members.push_back(member);
    }
    sort(invocation.members.begin(), invocation.members.end(),
            [](const GlobalAuthenticationInvocationMember& left,
                    const GlobalAuthenticationInvocationMember& right)
            {
                if (left.dealer != right.dealer)
                    return left.dealer < right.dealer;
                return left.batch_id < right.batch_id;
            });

    for (size_t i = 0; i < invocation.members.size(); i++)
    {
        const auto& member = invocation.members.at(i);
        if (member.dealer < 0 || member.dealer >= P.num_players())
        {
            fail_global_authentication(&invocation, 0,
                    OptimisticAuthenticationFailureClass::
                        invocation_validation);
            return false;
        }
        if (i > 0
                && (member.batch_id
                            == invocation.members.at(i - 1).batch_id
                        || member.dealer
                            == invocation.members.at(i - 1).dealer))
        {
            fail_global_authentication(&invocation, 0,
                    OptimisticAuthenticationFailureClass::
                        invocation_validation);
            return false;
        }
    }

    if (not source_only)
    {
        vector<uint64_t> required_pending_batch_ids;
        for (const auto& derivation : checkpoint->output_derivations)
        {
            if (derivation.terms.empty())
            {
                fail_global_authentication(&invocation, 0,
                        OptimisticAuthenticationFailureClass::
                            invocation_validation);
                return false;
            }
            for (const auto& term : derivation.terms)
            {
                const auto* batch =
                        find_dealer_source_batch(term.handle.batch_id);
                if (batch == 0 || batch->dealer != term.handle.dealer
                        || batch->source_ordinals.size()
                                != batch->local_source_shares.size()
                        || term.handle.source_ordinal
                                >= batch->source_ordinals.size()
                        || batch->source_ordinals.at(
                                term.handle.source_ordinal)
                                != term.handle.source_ordinal)
                {
                    fail_global_authentication(&invocation, 0,
                            OptimisticAuthenticationFailureClass::
                                invocation_validation);
                    return false;
                }
                if (batch->authentication_state
                        == DealerBatchAuthenticationState::pending)
                {
                    if (find(required_pending_batch_ids.begin(),
                            required_pending_batch_ids.end(),
                            batch->batch_id)
                            == required_pending_batch_ids.end())
                        required_pending_batch_ids.push_back(
                                batch->batch_id);
                }
                else if (batch->authentication_state
                                != DealerBatchAuthenticationState::
                                    authenticated
                        || not authenticated_handle_exists(term.handle))
                {
                    fail_global_authentication(&invocation, 0,
                            OptimisticAuthenticationFailureClass::
                                invocation_validation);
                    return false;
                }
            }
        }
        vector<uint64_t> requested_unique = requested_batch_ids;
        sort(requested_unique.begin(), requested_unique.end());
        sort(required_pending_batch_ids.begin(),
                required_pending_batch_ids.end());
        if (requested_unique != required_pending_batch_ids)
        {
            fail_global_authentication(&invocation, 0,
                    OptimisticAuthenticationFailureClass::
                        invocation_validation);
            return false;
        }
    }

    for (size_t member_index = 0;
            member_index < invocation.members.size(); member_index++)
    {
        auto& member = invocation.members.at(member_index);
        auto position = batch_indices.find(member.batch_id);
        auto* batch = position == batch_indices.end() ? nullptr
                : &state.dealer_batches.at(position->second);
        if (batch == 0
                || batch->authentication_state
                        != DealerBatchAuthenticationState::pending
                || batch->local_source_shares.empty()
                || batch->source_ordinals.size()
                        != batch->local_source_shares.size()
                || batch->verify_sharing_completed
                || batch->base_sharing_check_completed
                || not batch->authenticated_handles.empty())
        {
            fail_global_authentication(&invocation, 0,
                    OptimisticAuthenticationFailureClass::
                        invocation_validation);
            return false;
        }
        for (size_t ordinal = 0;
                ordinal < batch->source_ordinals.size(); ordinal++)
            if (batch->source_ordinals.at(ordinal) != ordinal)
            {
                fail_global_authentication(&invocation, batch,
                        OptimisticAuthenticationFailureClass::
                            invocation_validation);
                return false;
            }

        if (not verify_dealer_source_batch(*batch,
                batch->dealer == inject_bad_verify_sharing_dealer))
        {
            fail_global_authentication(&invocation, batch,
                    OptimisticAuthenticationFailureClass::verify_sharing);
            return false;
        }
    }

    if (not establish_optimistic_authentication_keys())
    {
        fail_global_authentication(&invocation, 0,
                OptimisticAuthenticationFailureClass::key_check);
        return false;
    }
    invocation.key_epoch = state.key_epoch;

    for (const auto& invocation_member : invocation.members)
    {
        auto position = batch_indices.find(invocation_member.batch_id);
        assert(position != batch_indices.end());
        const auto* batch = &state.dealer_batches.at(position->second);
        GlobalAuthenticationWorkingMember working_member{};
        working_member.batch_id = batch->batch_id;
        working_member.dealer_batch_index = position->second;
        working_member.source_chunks = source_chunks_for_batch(*batch);
        working.members.push_back(working_member);
    }
    if (test_fault == GlobalAuthenticationTestFault::missing_chunk
            && not working.members.empty()
            && not working.members.front().source_chunks.empty())
        working.members.front().source_chunks.pop_back();
    else if (test_fault
                    == GlobalAuthenticationTestFault::duplicate_chunk
            && not working.members.empty()
            && not working.members.front().source_chunks.empty())
        working.members.front().source_chunks.push_back(
                working.members.front().source_chunks.front());

    size_t invocation_chunk_count = 0;
    for (size_t member_index = 0;
            member_index < working.members.size(); member_index++)
    {
        auto& working_member = working.members.at(member_index);
        auto& invocation_member = invocation.members.at(member_index);
        auto* batch = &state.dealer_batches.at(
                working_member.dealer_batch_index);
        assert(batch->batch_id == working_member.batch_id);
        const size_t expected_chunk_count =
                base_field_ftag_chunk_count(
                        batch->local_source_shares.size());
        if (working_member.source_chunks.size()
                != expected_chunk_count)
        {
            fail_global_authentication(&invocation, batch,
                    OptimisticAuthenticationFailureClass::
                        invocation_validation);
            return false;
        }
        for (size_t chunk_ordinal = 0;
                chunk_ordinal < expected_chunk_count; chunk_ordinal++)
        {
            const auto& chunk =
                    working_member.source_chunks.at(chunk_ordinal);
            const size_t expected_offset = checked_size_product(
                    chunk_ordinal, width,
                    "AtlasGsz: global FTag source-chunk offset overflow");
            const size_t expected_count = min(width,
                    batch->local_source_shares.size() - expected_offset);
            if (chunk.chunk_ordinal != chunk_ordinal
                    || chunk.original_source_offset != expected_offset
                    || chunk.original_source_count != expected_count
                    || chunk.components.size() != width)
            {
                fail_global_authentication(&invocation, batch,
                        OptimisticAuthenticationFailureClass::
                            invocation_validation);
                return false;
            }
        }
        batch->ftag_chunk_count = expected_chunk_count;
        invocation_member.ftag_chunk_count = expected_chunk_count;
        invocation.max_ftag_chunk_count = max(
                invocation.max_ftag_chunk_count, expected_chunk_count);
        invocation_chunk_count = checked_size_sum(
                invocation_chunk_count, expected_chunk_count,
                "AtlasGsz: invocation FTag chunk count overflow");
    }
    if (invocation.max_ftag_chunk_count == 0)
    {
        fail_global_authentication(&invocation, 0,
                OptimisticAuthenticationFailureClass::
                    invocation_validation);
        return false;
    }
    state.total_ftag_chunks = checked_size_sum(state.total_ftag_chunks,
            invocation_chunk_count,
            "AtlasGsz: total FTag chunk count overflow");

    {
        SentCommunicationAccumulator communication(P,
                state.tag_generation_communication,
                &state.ordinary_tag_generation_communication);
        for (auto& working_member : working.members)
        {
            auto* batch = &state.dealer_batches.at(
                    working_member.dealer_batch_index);
            assert(batch->batch_id == working_member.batch_id);
            if (not compute_and_deliver_batch_tags(*batch,
                    working_member.source_chunks, false,
                    working_member.ordinary_nu_begin,
                    working_member.ordinary_tag_begin))
            {
                fail_global_authentication(&invocation, batch,
                        OptimisticAuthenticationFailureClass::tag_generation);
                return false;
            }
        }
    }

    for (auto& working_member : working.members)
    {
        auto* batch = &state.dealer_batches.at(
                working_member.dealer_batch_index);
        assert(batch->batch_id == working_member.batch_id);
        if (not prepare_and_verify_base_sharing(*batch,
                working_member.base_sharing,
                batch->dealer == inject_bad_base_sharing_dealer))
        {
            fail_global_authentication(&invocation, batch,
                    OptimisticAuthenticationFailureClass::base_sharing);
            return false;
        }
    }

    {
        SentCommunicationAccumulator communication(P,
                state.tag_generation_communication,
                &state.base_tag_generation_communication);
        for (auto& working_member : working.members)
        {
            auto* batch = &state.dealer_batches.at(
                    working_member.dealer_batch_index);
            assert(batch->batch_id == working_member.batch_id);
            if (working_member.base_sharing.size() != width)
            {
                fail_global_authentication(&invocation, batch,
                        OptimisticAuthenticationFailureClass::
                            invocation_validation);
                return false;
            }
            BaseFieldFTagSourceChunk base_chunk{};
            base_chunk.chunk_ordinal = 0;
            base_chunk.original_source_offset = 0;
            base_chunk.original_source_count = width;
            base_chunk.components = working_member.base_sharing;
            if (not compute_and_deliver_batch_tags(*batch,
                    vector<BaseFieldFTagSourceChunk>(1, base_chunk), true,
                    working_member.base_nu_begin,
                    working_member.base_tag_begin))
            {
                fail_global_authentication(&invocation, batch,
                        OptimisticAuthenticationFailureClass::tag_generation);
                return false;
            }
        }
    }

    if (test_fault == GlobalAuthenticationTestFault::key_epoch_mismatch
            && not state.holder_tags.empty())
        state.holder_tags.back().key_epoch =
                checked_size_sum(state.holder_tags.back().key_epoch, 1,
                        "AtlasGsz: test key epoch overflow");

    if (not validate_global_authentication_material(invocation, working))
    {
        fail_global_authentication(&invocation, 0,
                OptimisticAuthenticationFailureClass::
                    invocation_validation);
        return false;
    }
    return true;
}

template<class T>
bool AtlasGsz<T>::validate_global_authentication_material(
        const GlobalAuthenticationInvocationRecord& invocation,
        const GlobalAuthenticationWorkingSet& working) const
{
    const auto& state = optimistic_authentication_state;
    const size_t width = base_field_ftag_chunk_width();
    const size_t player_count = size_t(P.num_players());
    const size_t expected_key_count = checked_size_product(player_count,
            player_count - 1,
            "AtlasGsz: global key count overflow");
    if (not state.keys_checked || invocation.key_epoch != state.key_epoch
            || invocation.members.size() != working.members.size()
            || state.keys.size() != expected_key_count)
        return false;

    vector<bool> seen_key_pairs(checked_size_product(player_count,
            player_count, "AtlasGsz: key-pair table overflow"), false);
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        if (key.epoch != invocation.key_epoch || not key.checked
                || key.verifier < 0 || key.verifier >= P.num_players()
                || key.holder < 0 || key.holder >= P.num_players()
                || key.verifier == key.holder
                || key.owns_clear_mu != (P.my_num() == key.verifier)
                || key.has_local_twisted_share
                        != (P.my_num() != key.holder)
                || (key.owns_clear_mu && key.clear_mu.size() != width)
                || (key.has_local_twisted_share
                        && key.local_twisted_share.size() != width))
            return false;
        const size_t pair_index = size_t(key.verifier) * player_count
                + size_t(key.holder);
        if (seen_key_pairs.at(pair_index))
            return false;
        seen_key_pairs.at(pair_index) = true;
    }

    for (size_t member_index = 0;
            member_index < invocation.members.size(); member_index++)
    {
        const auto& member = invocation.members.at(member_index);
        const auto& working_member = working.members.at(member_index);
        if (member.batch_id != working_member.batch_id
                || working_member.dealer_batch_index
                        >= state.dealer_batches.size()
                || state.dealer_batches.at(
                        working_member.dealer_batch_index).batch_id
                        != member.batch_id
                || member.ftag_chunk_count
                        != working_member.source_chunks.size()
                || working_member.base_sharing.size() != width)
            return false;
        const size_t ordinary_count = checked_size_product(
                state.keys.size(), member.ftag_chunk_count,
                "AtlasGsz: ordinary material range overflow");
        const size_t ordinary_nu_end = checked_size_sum(
                working_member.ordinary_nu_begin, ordinary_count,
                "AtlasGsz: ordinary nu range overflow");
        const size_t ordinary_tag_end = checked_size_sum(
                working_member.ordinary_tag_begin, ordinary_count,
                "AtlasGsz: ordinary tag range overflow");
        const size_t base_nu_end = checked_size_sum(
                working_member.base_nu_begin, state.keys.size(),
                "AtlasGsz: base nu range overflow");
        const size_t base_tag_end = checked_size_sum(
                working_member.base_tag_begin, state.keys.size(),
                "AtlasGsz: base tag range overflow");
        if (ordinary_nu_end > state.nu_material.size()
                || ordinary_tag_end > state.holder_tags.size()
                || base_nu_end > state.nu_material.size()
                || base_tag_end > state.holder_tags.size())
            return false;

        auto valid_nu = [&] (const BatchNuMaterialRecord& material,
                const LongTermMuKeyRecord& key, size_t chunk,
                bool check_mask) {
            return material.batch_id == member.batch_id
                    && material.chunk_ordinal == chunk
                    && material.check_mask == check_mask
                    && material.key_epoch == invocation.key_epoch
                    && material.verifier == key.verifier
                    && material.holder == key.holder
                    && material.owns_nu
                            == (P.my_num() == material.verifier);
        };
        auto valid_tag = [&] (const HolderTagRecord& tag,
                const LongTermMuKeyRecord& key, size_t chunk,
                bool check_mask) {
            return tag.batch_id == member.batch_id
                    && tag.chunk_ordinal == chunk
                    && tag.check_mask == check_mask
                    && tag.key_epoch == invocation.key_epoch
                    && tag.verifier == key.verifier
                    && tag.holder == key.holder
                    && tag.owns_tag == (P.my_num() == tag.holder);
        };
        for (size_t key_index = 0;
                key_index < state.keys.size(); key_index++)
        {
            const auto& key = state.keys.at(key_index);
            for (size_t chunk = 0;
                    chunk < member.ftag_chunk_count; chunk++)
            {
                const size_t offset =
                        key_index * member.ftag_chunk_count + chunk;
                if (not valid_nu(state.nu_material.at(
                                working_member.ordinary_nu_begin + offset),
                            key, chunk, false)
                        || not valid_tag(state.holder_tags.at(
                                working_member.ordinary_tag_begin + offset),
                            key, chunk, false))
                    return false;
            }
            if (not valid_nu(state.nu_material.at(
                            working_member.base_nu_begin + key_index),
                        key, 0, true)
                    || not valid_tag(state.holder_tags.at(
                            working_member.base_tag_begin + key_index),
                        key, 0, true))
                return false;
        }
    }
    return true;
}
template<class T>
bool AtlasGsz<T>::check_global_authentication(
        GlobalAuthenticationInvocationRecord& invocation,
        const GlobalAuthenticationWorkingSet& working,
    GlobalAuthenticationTestFault test_fault)
{
    auto& state = optimistic_authentication_state;
    SentCommunicationAccumulator communication(
            P, state.tag_checking_communication);
    const size_t width = base_field_ftag_chunk_width();
    const size_t dealer_block_width = checked_size_sum(
            invocation.max_ftag_chunk_count, 1,
            "AtlasGsz: global Check-Tag dealer-block width overflow");
    const size_t total_positions = checked_size_product(
            invocation.members.size(), dealer_block_width,
            "AtlasGsz: global Check-Tag position count overflow");

    // The uniform layout has maximum degree total_positions - 1, even when
    // some dealer-block positions are implicit zero coefficients. Concrete
    // soundness is over p=2^61-1 and must be union-bounded over every
    // verifier-holder relation and invocation; it is not an arbitrary
    // kappa-bit claim.

    invocation.challenge = sample_agreed_challenge();
    // Focused negative-test override only: a literal ordinary-chunk error is
    // multiplied by a positive power of lambda, so lambda=0 would erase it.
    // Honest and production invocations retain the sampled zero-permitted
    // challenge unchanged.
    if (test_fault
                    == GlobalAuthenticationTestFault::
                        ordinary_source_presentation
            && invocation.challenge == typename T::open_type{})
        invocation.challenge = typename T::open_type(1);
    invocation.challenge_sampled = true;
    state.global_check_tag_challenges++;
    vector<typename T::open_type> powers(total_positions);
    typename T::open_type power(1);
    for (size_t position = 0; position < total_positions; position++)
    {
        powers.at(position) = power;
        power *= invocation.challenge;
    }

    vector<octetStream> presentations(P.num_players());
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        if (P.my_num() == key.holder)
        {
            vector<typename T::open_type> sigma(width);
            typename T::open_type aggregate_tag{};
            bool injected_ordinary_sigma = false;
            bool injected_base_sigma = false;
            bool injected_aggregate_tag = false;
            for (size_t member_index = 0;
                    member_index < invocation.members.size(); member_index++)
            {
                const auto& member = invocation.members.at(member_index);
                const auto& working_member =
                        working.members.at(member_index);
                const size_t block_start = checked_size_product(
                        member_index, dealer_block_width,
                        "AtlasGsz: global Check-Tag block offset overflow");
                const auto base_coefficient = powers.at(block_start);
                for (size_t component = 0; component < width; component++)
                    sigma.at(component) += base_coefficient
                            * typename T::open_type(
                                    working_member.base_sharing.at(component));
                if (key.verifier == 0 && key.holder == 1
                        && member_index == 0
                        && test_fault
                                == GlobalAuthenticationTestFault::
                                    base_sharing_presentation)
                {
                    const auto sigma_before = sigma.at(0);
                    const auto tag_before = aggregate_tag;
                    sigma.at(0) += base_coefficient;
                    assert(sigma.at(0) != sigma_before);
                    assert(aggregate_tag == tag_before);
                    injected_base_sigma = true;
                }
                const auto& base_tag = state.holder_tags.at(
                        working_member.base_tag_begin + key_index);
                assert(base_tag.batch_id == member.batch_id
                        && base_tag.chunk_ordinal == 0
                        && base_tag.check_mask
                        && base_tag.key_epoch == invocation.key_epoch
                        && base_tag.verifier == key.verifier
                        && base_tag.holder == key.holder
                        && base_tag.owns_tag);
                aggregate_tag += base_coefficient * base_tag.tag;

                for (size_t chunk = 0;
                        chunk < member.ftag_chunk_count; chunk++)
                {
                    const auto coefficient =
                            powers.at(block_start + chunk + 1);
                    for (size_t component = 0;
                            component < width; component++)
                        sigma.at(component) += coefficient
                                * typename T::open_type(
                                        working_member.source_chunks.at(chunk)
                                                .components.at(component));
                    if (key.verifier == 0 && key.holder == 1
                            && member_index == 0 && chunk == 0
                            && test_fault
                                    == GlobalAuthenticationTestFault::
                                        ordinary_source_presentation)
                    {
                        assert(coefficient
                                != typename T::open_type{});
                        const auto sigma_before = sigma.at(0);
                        const auto tag_before = aggregate_tag;
                        sigma.at(0) += coefficient;
                        assert(sigma.at(0) != sigma_before);
                        assert(aggregate_tag == tag_before);
                        injected_ordinary_sigma = true;
                    }
                    const auto& tag = state.holder_tags.at(
                            working_member.ordinary_tag_begin
                                    + key_index * member.ftag_chunk_count
                                    + chunk);
                    assert(tag.batch_id == member.batch_id
                            && tag.chunk_ordinal == chunk
                            && not tag.check_mask
                            && tag.key_epoch == invocation.key_epoch
                            && tag.verifier == key.verifier
                            && tag.holder == key.holder && tag.owns_tag);
                    aggregate_tag += coefficient * tag.tag;
                }
            }

            if (key.verifier == 0 && key.holder == 1)
            {
                if (test_fault
                        == GlobalAuthenticationTestFault::
                            aggregate_holder_tag)
                {
                    const auto sigma_before = sigma;
                    const auto tag_before = aggregate_tag;
                    aggregate_tag += typename T::open_type(1);
                    assert(sigma == sigma_before);
                    assert(aggregate_tag != tag_before);
                    injected_aggregate_tag = true;
                }
                assert(injected_ordinary_sigma
                        == (test_fault
                                == GlobalAuthenticationTestFault::
                                    ordinary_source_presentation));
                assert(injected_base_sigma
                        == (test_fault
                                == GlobalAuthenticationTestFault::
                                    base_sharing_presentation));
                assert(injected_aggregate_tag
                        == (test_fault
                                == GlobalAuthenticationTestFault::
                                    aggregate_holder_tag));
            }

            for (const auto& component : sigma)
                component.pack(presentations.at(key.verifier));
            aggregate_tag.pack(presentations.at(key.verifier));
        }
    }

    vector<octetStream> received_presentations;
    P.send_receive_all(presentations, received_presentations);
    vector<bool> relation_passes(state.keys.size(), false);
    vector<vector<typename T::open_type>> received_sigma(
            state.keys.size());
    vector<typename T::open_type> received_tags(state.keys.size());
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        if (P.my_num() != key.verifier)
            continue;
        received_sigma.at(key_index).resize(width);
        for (auto& component : received_sigma.at(key_index))
            component.unpack(received_presentations.at(key.holder));
        received_tags.at(key_index).unpack(
                received_presentations.at(key.holder));

        typename T::open_type aggregate_nu{};
        for (size_t member_index = 0;
                member_index < invocation.members.size(); member_index++)
        {
            const auto& member = invocation.members.at(member_index);
            const size_t block_start = checked_size_product(
                    member_index, dealer_block_width,
                    "AtlasGsz: global Check-Tag block offset overflow");
            const auto& working_member = working.members.at(member_index);
            const auto& base_nu = state.nu_material.at(
                    working_member.base_nu_begin + key_index);
            assert(base_nu.batch_id == member.batch_id
                    && base_nu.chunk_ordinal == 0 && base_nu.check_mask
                    && base_nu.key_epoch == invocation.key_epoch
                    && base_nu.verifier == key.verifier
                    && base_nu.holder == key.holder && base_nu.owns_nu);
            aggregate_nu += powers.at(block_start) * base_nu.nu;
            for (size_t chunk = 0;
                    chunk < member.ftag_chunk_count; chunk++)
            {
                const auto& nu = state.nu_material.at(
                        working_member.ordinary_nu_begin
                                + key_index * member.ftag_chunk_count
                                + chunk);
                assert(nu.batch_id == member.batch_id
                        && nu.chunk_ordinal == chunk && not nu.check_mask
                        && nu.key_epoch == invocation.key_epoch
                        && nu.verifier == key.verifier
                        && nu.holder == key.holder && nu.owns_nu);
                aggregate_nu += powers.at(block_start + chunk + 1)
                        * nu.nu;
            }
        }
        typename T::open_type expected = aggregate_nu;
        for (size_t component = 0; component < width; component++)
            expected += key.clear_mu.at(component)
                    * received_sigma.at(key_index).at(component);
        relation_passes.at(key_index) =
                expected == received_tags.at(key_index);
    }
    for (int sender = 0; sender < P.num_players(); sender++)
        if (sender != P.my_num())
            assert(not received_presentations.at(sender).left());

    // Protocol 27 Step 5: every verifier broadcasts exactly one compact
    // invocation decision, not one Boolean per verifier-holder relation.
    // Encoding: 0 means ok; holder+1 means fault(holder).
    int local_smallest_failed_holder = -1;
    for (size_t key_index = 0; key_index < state.keys.size(); key_index++)
    {
        const auto& key = state.keys.at(key_index);
        if (P.my_num() == key.verifier
                && not relation_passes.at(key_index)
                && (local_smallest_failed_holder < 0
                        || key.holder < local_smallest_failed_holder))
            local_smallest_failed_holder = key.holder;
    }
    vector<octetStream> decision_streams(P.num_players());
    typename T::open_type(local_smallest_failed_holder + 1).pack(
            decision_streams.at(P.my_num()));
    P.Broadcast_Receive(decision_streams);
    P.Check_Broadcast();

    vector<int> decoded_failed_holders(P.num_players(), -1);
    int first_malformed_verifier = -1;
    for (int verifier = 0; verifier < P.num_players(); verifier++)
    {
        typename T::open_type encoded_decision;
        encoded_decision.unpack(decision_streams.at(verifier));
        bool valid_encoding = not decision_streams.at(verifier).left();
        if (encoded_decision != typename T::open_type{})
        {
            int decoded_holder = -1;
            for (int holder = 0; holder < P.num_players(); holder++)
                if (holder != verifier
                        && encoded_decision
                                == typename T::open_type(holder + 1))
                {
                    decoded_holder = holder;
                    break;
                }
            if (decoded_holder < 0)
                valid_encoding = false;
            else
                decoded_failed_holders.at(verifier) = decoded_holder;
        }
        if (not valid_encoding && first_malformed_verifier < 0)
            first_malformed_verifier = verifier;
    }
    if (first_malformed_verifier >= 0)
    {
        invocation.completed = true;
        invocation.passed = false;
        fail_global_authentication(&invocation, 0,
                OptimisticAuthenticationFailureClass::
                    invocation_validation,
                first_malformed_verifier, -1);
        return false;
    }

    int failed_verifier = -1;
    int failed_holder = -1;
    for (int verifier = 0; verifier < P.num_players(); verifier++)
        if (decoded_failed_holders.at(verifier) >= 0)
        {
            failed_verifier = verifier;
            failed_holder = decoded_failed_holders.at(verifier);
            break;
        }

    const bool all_pass = failed_verifier < 0;
    invocation.completed = true;
    invocation.passed = all_pass;
    if (all_pass)
        return true;

    if (P.my_num() == failed_verifier)
        for (size_t key_index = 0;
                key_index < state.keys.size(); key_index++)
        {
            const auto& key = state.keys.at(key_index);
            if (key.verifier == failed_verifier
                    && key.holder == failed_holder)
            {
                invocation.owns_failure_presentation = true;
                invocation.failure_sigma = received_sigma.at(key_index);
                invocation.failure_tag = received_tags.at(key_index);
                break;
            }
        }
    fail_global_authentication(&invocation, 0,
            OptimisticAuthenticationFailureClass::tag_check,
            failed_verifier, failed_holder);
    return false;
}

template<class T>
bool AtlasGsz<T>::commit_global_authentication(
        GlobalAuthenticationInvocationRecord& invocation,
        const GlobalAuthenticationWorkingSet& working)
{
    if (not invocation.completed || not invocation.passed)
        return false;
    const bool source_only = invocation.checkpoint_id == 0;
    auto* checkpoint = source_only ? 0 :
            find_optimistic_checkpoint(invocation.checkpoint_id);
    if ((!source_only && (checkpoint == 0 || checkpoint->sealed
                    || checkpoint->promoted))
            || invocation.members.size() != working.members.size())
        return false;

    vector<vector<AuthenticatedSourceHandle>> candidate_handles(
            invocation.members.size());
    for (size_t member_index = 0;
            member_index < invocation.members.size(); member_index++)
    {
        const auto& member = invocation.members.at(member_index);
        const auto& working_member = working.members.at(member_index);
        if (working_member.dealer_batch_index
                    >= optimistic_authentication_state.dealer_batches.size())
            return false;
        auto* batch = &optimistic_authentication_state.dealer_batches.at(
                working_member.dealer_batch_index);
        if (batch->batch_id != member.batch_id
                || batch->dealer != member.dealer
                || batch->authentication_state
                        != DealerBatchAuthenticationState::pending
                || batch->source_ordinals.size()
                        != batch->local_source_shares.size()
                || not batch->authenticated_handles.empty())
            return false;
        auto& handles = candidate_handles.at(member_index);
        if (batch->source_ordinals.size() > handles.max_size())
            throw length_error(
                    "AtlasGsz: candidate authenticated handle count exceeds vector capacity");
        handles.reserve(batch->source_ordinals.size());
        for (size_t ordinal = 0;
                ordinal < batch->source_ordinals.size(); ordinal++)
        {
            if (batch->source_ordinals.at(ordinal) != ordinal)
                return false;
            AuthenticatedSourceHandle handle{};
            handle.batch_id = batch->batch_id;
            handle.dealer = batch->dealer;
            handle.source_ordinal = ordinal;
            handles.push_back(handle);
        }
    }

    if (not source_only)
    {
        auto candidate_handle_exists =
                [&](const AuthenticatedSourceHandle& handle)
        {
            for (size_t member_index = 0;
                    member_index < invocation.members.size(); member_index++)
                if (invocation.members.at(member_index).batch_id
                        == handle.batch_id)
                    return find(candidate_handles.at(member_index).begin(),
                            candidate_handles.at(member_index).end(), handle)
                            != candidate_handles.at(member_index).end();
            return authenticated_handle_exists(handle);
        };
        for (const auto& derivation : checkpoint->output_derivations)
        {
            if (derivation.terms.empty())
                return false;
            for (const auto& term : derivation.terms)
                if (not candidate_handle_exists(term.handle))
                    return false;
        }
    }

    // Every allocation and provenance validation above completes before the
    // first authoritative mutation. No batch prefix can be committed.
    for (size_t member_index = 0;
            member_index < invocation.members.size(); member_index++)
    {
        const auto& working_member = working.members.at(member_index);
        auto* batch = &optimistic_authentication_state.dealer_batches.at(
                working_member.dealer_batch_index);
        assert(batch->batch_id
                == invocation.members.at(member_index).batch_id);
        batch->authenticated_handles =
                std::move(candidate_handles.at(member_index));
        batch->authentication_state =
                DealerBatchAuthenticationState::authenticated;
        batch->failure_class =
                OptimisticAuthenticationFailureClass::none;
    }
    if (not source_only)
    {
        checkpoint->sealed = true;
        checkpoint->promoted = true;
    }
    return true;
}

template<class T>
bool AtlasGsz<T>::authenticate_source_batches(
        const vector<uint64_t>& requested_batch_ids,
        GlobalAuthenticationTestFault test_fault,
        int inject_bad_verify_sharing_dealer,
        int inject_bad_base_sharing_dealer)
{
    auto& state = optimistic_authentication_state;
    GlobalAuthenticationInvocationRecord invocation{};
    invocation.invocation_id = state.next_global_invocation_id++;
    invocation.key_epoch = state.key_epoch;
    invocation.checkpoint_id = 0;
    state.global_invocations.push_back(invocation);
    auto& retained_invocation = state.global_invocations.back();
    GlobalAuthenticationWorkingSet working{};

    if (not prepare_global_authentication(retained_invocation,
            requested_batch_ids, working,
            inject_bad_verify_sharing_dealer,
            inject_bad_base_sharing_dealer, test_fault))
        return false;
    if (not check_global_authentication(
            retained_invocation, working, test_fault))
        return false;
    if (not commit_global_authentication(retained_invocation, working))
    {
        fail_global_authentication(&retained_invocation, 0,
                OptimisticAuthenticationFailureClass::
                    invocation_validation);
        return false;
    }
    return true;
}

template<class T>
typename AtlasGsz<T>::TentativeDoubleRandAuthenticationReceipt
AtlasGsz<T>::authenticate_frozen_tentative_double_rand_candidate(
        FrozenOrdinaryBatch& frozen,
        GlobalAuthenticationTestFault test_fault,
        int inject_bad_verify_sharing_dealer)
{
    TentativeDoubleRandAuthenticationReceipt empty{};
    auto& auth = optimistic_authentication_state;
    const auto* candidate = frozen.candidate.get();
    if (candidate == 0 || frozen.dealer_count != size_t(P.num_players())
            || frozen.operation_count != candidate->consumed_outputs.size()
            || frozen.mapping_count
                    != frozen.dealer_count * candidate->source_count
            || frozen.prospective_batches.size() != frozen.dealer_count
            || frozen.prospective_mappings.size() != frozen.mapping_count
            || frozen.converted_term_mapping_indices.size()
                    != frozen.operation_count
            || frozen.e_t_source_ordinals.size()
                    != frozen.operation_count
            || auth.status != OptimisticAuthenticationStatus::ready)
        return empty;

    auto& receipt = frozen.receipt;
    const size_t batch_start_index = auth.dealer_batches.size();
    const size_t invocation_count_before = auth.global_invocations.size();
    const size_t checkpoint_count_before = auth.checkpoints.size();
    const uint64_t next_checkpoint_id_before = auth.next_checkpoint_id;
    auth.dealer_batches.reserve(checked_size_sum(
            batch_start_index, frozen.dealer_count,
            "AtlasGsz: frozen adapter registered batch count overflow"));
    auth.global_invocations.reserve(checked_size_sum(
            invocation_count_before, 1,
            "AtlasGsz: frozen adapter invocation count overflow"));

    const uint64_t first_batch_id = auth.next_batch_id;
    if (first_batch_id == 0
            || frozen.dealer_count
                    > numeric_limits<uint64_t>::max() - first_batch_id)
        return empty;
    const uint64_t next_batch_id_after =
            first_batch_id + uint64_t(frozen.dealer_count);
    unordered_map<uint64_t, bool> existing_batch_ids;
    existing_batch_ids.reserve(auth.dealer_batches.size());
    for (const auto& existing : auth.dealer_batches)
        if (not existing_batch_ids.emplace(
                existing.batch_id, true).second)
            return empty;
    vector<uint64_t> requested_batch_ids(frozen.dealer_count);
    for (size_t dealer = 0; dealer < frozen.dealer_count; dealer++)
    {
        const uint64_t batch_id = first_batch_id + uint64_t(dealer);
        if (existing_batch_ids.find(batch_id)
                != existing_batch_ids.end())
            return empty;
        auto& batch = frozen.prospective_batches.at(dealer);
        const size_t expected_source_count = dealer == 0
                ? frozen.combined_king_source_count
                : candidate->source_count;
        if (batch.dealer != int(dealer) || batch.batch_id != 0
                || batch.source_ordinals.size() != expected_source_count
                || batch.local_source_shares.size()
                        != expected_source_count)
            return empty;
        batch.batch_id = batch_id;
        requested_batch_ids.at(dealer) = batch_id;
        auto& summary = receipt.dealer_batches.at(dealer);
        summary.dealer = int(dealer);
        summary.batch_id = batch_id;
        summary.source_count = expected_source_count;
    }

    register_tentative_double_rand_batches_atomically(
            frozen.prospective_batches, next_batch_id_after);
    const bool accepted = authenticate_source_batches(requested_batch_ids,
            test_fault, inject_bad_verify_sharing_dealer, -1);
    if (auth.global_invocations.size() != invocation_count_before + 1
            || auth.checkpoints.size() != checkpoint_count_before
            || auth.next_checkpoint_id != next_checkpoint_id_before)
        throw logic_error(
                "AtlasGsz: frozen adapter authentication boundary changed unexpectedly");
    const auto& invocation = auth.global_invocations.back();
    receipt.authentication_invocation_id = invocation.invocation_id;
    if (invocation.checkpoint_id != 0
            || invocation.members.size() != frozen.dealer_count)
        throw logic_error(
                "AtlasGsz: frozen adapter did not retain one source-only all-dealer invocation");

    for (size_t dealer = 0; dealer < frozen.dealer_count; dealer++)
    {
        const auto& member = invocation.members.at(dealer);
        const auto& batch = auth.dealer_batches.at(
                batch_start_index + dealer);
        if (member.dealer != int(dealer)
                || member.batch_id != first_batch_id + uint64_t(dealer)
                || batch.batch_id != member.batch_id
                || batch.dealer != int(dealer))
            throw logic_error(
                    "AtlasGsz: frozen adapter lost canonical dealer order");
        if (not accepted)
        {
            if (batch.authentication_state
                            != DealerBatchAuthenticationState::rejected
                    || not batch.authenticated_handles.empty())
                throw logic_error(
                        "AtlasGsz: rejected frozen adapter batch retained handles");
        }
    }
    if (not accepted)
    {
        receipt.converted_r_t_derivations.clear();
        receipt.authenticated_e_t_sources.clear();
        receipt.converted_z_t_derivations.clear();
        return std::move(receipt);
    }
    if (not invocation.completed || not invocation.passed)
        throw logic_error(
                "AtlasGsz: accepted frozen adapter invocation is incomplete");

    receipt.source_handles.clear();
    for (size_t mapping_index = 0;
            mapping_index < frozen.prospective_mappings.size();
            mapping_index++)
    {
        const size_t source_ordinal = mapping_index / frozen.dealer_count;
        const size_t dealer = mapping_index % frozen.dealer_count;
        const auto& prospective =
                frozen.prospective_mappings.at(mapping_index);
        const auto& expected_group =
                candidate->source_groups.at(source_ordinal);
        const auto& batch = auth.dealer_batches.at(
                batch_start_index + dealer);
        if (batch.authentication_state
                        != DealerBatchAuthenticationState::authenticated
                || batch.source_ordinals.size()
                        != batch.local_source_shares.size()
                || batch.authenticated_handles.size()
                        != batch.source_ordinals.size()
                || prospective.producer_record_ordinal
                        != expected_group.producer_record_ordinal
                || prospective.input_generation_group_ordinal
                        != expected_group.input_generation_group_ordinal
                || prospective.dealer != int(dealer)
                || prospective.source_ordinal != source_ordinal
                || batch.source_ordinals.at(source_ordinal)
                        != source_ordinal)
            throw logic_error(
                    "AtlasGsz: frozen source mapping is not authoritative");
        const auto& handle =
                batch.authenticated_handles.at(source_ordinal);
        if (handle.batch_id != batch.batch_id
                || handle.dealer != int(dealer)
                || handle.source_ordinal != source_ordinal)
            throw logic_error(
                    "AtlasGsz: frozen source mapping resolved the wrong handle");
        TentativeDoubleRandSourceHandleMapping mapping{};
        mapping.producer_record_ordinal =
                prospective.producer_record_ordinal;
        mapping.input_generation_group_ordinal =
                prospective.input_generation_group_ordinal;
        mapping.dealer = prospective.dealer;
        mapping.handle = handle;
        receipt.source_handles.push_back(mapping);
    }
    if (receipt.source_handles.size() != frozen.mapping_count)
        throw logic_error(
                "AtlasGsz: frozen receipt does not cover every source");

    for (size_t operation = 0;
            operation < frozen.operation_count; operation++)
    {
        const auto& tentative = candidate->consumed_outputs.at(operation);
        auto& converted = receipt.converted_r_t_derivations.at(operation);
        const auto& indices =
                frozen.converted_term_mapping_indices.at(operation);
        T local_r{};
        for (size_t term = 0; term < indices.size(); term++)
        {
            const size_t mapping_index = indices.at(term);
            if (mapping_index >= receipt.source_handles.size())
                throw logic_error(
                        "AtlasGsz: frozen r_t term lost its mapping");
            const auto& mapping = receipt.source_handles.at(mapping_index);
            const size_t dealer = mapping_index % frozen.dealer_count;
            const size_t source_ordinal =
                    mapping_index / frozen.dealer_count;
            const auto& batch = auth.dealer_batches.at(
                    batch_start_index + dealer);
            auto& term_result = converted.derivation.terms.at(term);
            term_result.handle = mapping.handle;
            if (mapping.dealer != int(dealer)
                    || term_result.coefficient
                            != tentative.degree_t_derivation.terms.at(term)
                                    .coefficient
                    || source_ordinal >= batch.local_source_shares.size())
                throw logic_error(
                        "AtlasGsz: frozen r_t coefficient or source changed");
            local_r += term_result.coefficient
                    * batch.local_source_shares.at(source_ordinal);
        }
        if (local_r != tentative.actual_r_t)
            throw logic_error(
                    "AtlasGsz: frozen r_t derivation failed local evaluation");

        auto& authenticated_e =
                receipt.authenticated_e_t_sources.at(operation);
        const auto& king_batch = auth.dealer_batches.at(batch_start_index);
        const size_t e_t_ordinal = frozen.e_t_source_ordinals.at(operation);
        if (authenticated_e.king != 0
                || e_t_ordinal != candidate->source_count + operation
                || e_t_ordinal >= king_batch.authenticated_handles.size()
                || king_batch.local_source_shares.at(e_t_ordinal)
                        != tentative.concrete_e_t_source.local_share)
            throw logic_error(
                    "AtlasGsz: frozen e_t suffix binding changed");
        authenticated_e.handle =
                king_batch.authenticated_handles.at(e_t_ordinal);

        auto& converted_z = receipt.converted_z_t_derivations.at(operation);
        if (converted_z.derivation.terms.size()
                    != converted.derivation.terms.size() + 1
                || converted_z.derivation.terms.at(0).coefficient
                        != typename T::open_type(1))
            throw logic_error(
                    "AtlasGsz: frozen z_t derivation has the wrong shape");
        converted_z.derivation.terms.at(0).handle =
                authenticated_e.handle;
        T local_z = king_batch.local_source_shares.at(e_t_ordinal);
        for (size_t term = 0;
                term < converted.derivation.terms.size(); term++)
        {
            const auto& r_term = converted.derivation.terms.at(term);
            auto& z_term = converted_z.derivation.terms.at(term + 1);
            z_term.handle = r_term.handle;
            if (z_term.coefficient
                    != typename T::open_type{} - r_term.coefficient)
                throw logic_error(
                        "AtlasGsz: frozen z_t coefficient changed");
            const size_t dealer = size_t(r_term.handle.dealer);
            const auto& batch = auth.dealer_batches.at(
                    batch_start_index + dealer);
            local_z += z_term.coefficient
                    * batch.local_source_shares.at(
                            r_term.handle.source_ordinal);
        }
        if (local_z != tentative.concrete_e_t_source.local_share
                            - tentative.actual_r_t)
            throw logic_error(
                    "AtlasGsz: frozen z_t derivation failed local evaluation");
    }
    receipt.authenticated = true;
    return std::move(receipt);
}

template<class T>
typename AtlasGsz<T>::TentativeDoubleRandAuthenticationReceipt
AtlasGsz<T>::adapt_finalized_tentative_double_rand_candidate(
        GlobalAuthenticationTestFault test_fault,
        int inject_bad_verify_sharing_dealer)
{
    auto frozen = freeze_finalized_tentative_double_rand_candidate();
    if (not frozen)
    {
        if (not tentative_double_rand_capture_state.active
                && tentative_double_rand_capture_state.finalized_candidate)
            discard_tentative_double_rand_capture();
        return TentativeDoubleRandAuthenticationReceipt{};
    }
    return authenticate_frozen_tentative_double_rand_candidate(
            *frozen, test_fault, inject_bad_verify_sharing_dealer);
}
template<class T>
void AtlasGsz<T>::run_tentative_double_rand_adapter_test_hook(
        const string& mode)
{
    auto fail = [&] (const string& reason) {
        throw logic_error("AtlasGsz: " + mode + " test failed: " + reason);
    };
    auto& auth = optimistic_authentication_state;
    const auto* candidate = inspect_tentative_double_rand_capture();
    const size_t dealer_count = size_t(P.num_players());
    if (candidate == 0
            || not validate_tentative_double_rand_candidate(*candidate)
            || candidate->source_count != 2
            || candidate->consumed_outputs.size() != 6
            || candidate->dealer_sources.size() != dealer_count)
        fail("finalized six-operation two-source all-dealer candidate is absent");

    // Deterministic local checks for the exact native field negation used by
    // Delta_z. These consume neither protocol randomness nor communication.
    const typename T::open_type zero{};
    const typename T::open_type one(1);
    const typename T::open_type minus_one = zero - one;
    const typename T::open_type general(17);
    const typename T::open_type negated_general = zero - general;
    if (zero - zero != zero || zero - one != minus_one
            || zero - minus_one != one
            || general == zero || general == one || general == minus_one
            || general + negated_general != zero)
        fail("native field coefficient negation failed deterministic edge cases");

    const size_t source_count = candidate->source_count;
    const auto expected_producer_records = candidate->producer_records;
    const auto expected_groups = candidate->source_groups;
    const auto expected_consumed_outputs = candidate->consumed_outputs;
    vector<vector<bool>> seen_outputs;
    seen_outputs.reserve(candidate->producer_records.size());
    for (const auto& producer : candidate->producer_records)
    {
        if (not producer
                || producer->degree_t.output_derivations.size()
                        > vector<bool>{}.max_size())
            fail("captured producer output table cannot be indexed");
        seen_outputs.emplace_back(
                producer->degree_t.output_derivations.size(), false);
    }
    for (size_t output_index = 0;
            output_index < expected_consumed_outputs.size(); output_index++)
    {
        const auto& expected_output =
                expected_consumed_outputs.at(output_index);
        const auto expected_kind = output_index % 2 == 0
                ? OrdinaryDoubleRandOperationKind::scalar_multiplication
                : OrdinaryDoubleRandOperationKind::dot_product;
        if (expected_output.capture_order_ordinal != output_index
                || expected_output.operation_kind != expected_kind
                || expected_output.producer_record_ordinal
                        >= seen_outputs.size()
                || expected_output.producer_output_ordinal
                        >= seen_outputs.at(
                                expected_output.producer_record_ordinal)
                                .size())
            fail("captured operation identity/order is not scalar-dot alternating");
        auto& producer_seen = seen_outputs.at(
                expected_output.producer_record_ordinal);
        if (producer_seen.at(expected_output.producer_output_ordinal))
            fail("captured consumed-output key is not unique");
        producer_seen.at(expected_output.producer_output_ordinal) = true;
    }
    vector<vector<T>> expected_local_sources(dealer_count);
    for (size_t dealer = 0; dealer < dealer_count; dealer++)
    {
        const auto& sequence = candidate->dealer_sources.at(dealer);
        if (sequence.dealer != int(dealer)
                || sequence.sources.size() != source_count)
            fail("candidate dealer sequence is not canonical");
        expected_local_sources.at(dealer).reserve(source_count);
        for (size_t source_ordinal = 0;
                source_ordinal < source_count; source_ordinal++)
            expected_local_sources.at(dealer).push_back(
                    sequence.sources.at(source_ordinal).local_share);
    }

    const size_t communication_before = P.total_comm().sent;
    const uint64_t next_batch_id_before = auth.next_batch_id;
    const size_t batch_count_before = auth.dealer_batches.size();
    const size_t invocation_count_before = auth.global_invocations.size();
    const uint64_t next_invocation_id_before =
            auth.next_global_invocation_id;
    const size_t challenge_count_before =
            auth.global_check_tag_challenges;
    const size_t checkpoint_count_before = auth.checkpoints.size();
    const uint64_t next_checkpoint_id_before = auth.next_checkpoint_id;

    if (mode == "tentative-double-rand-adapter-malformed"
            || mode == "tentative-double-rand-adapter-e-t-malformed")
    {
        auto* malformed = tentative_double_rand_capture_state
                .finalized_candidate.get();
        if (mode == "tentative-double-rand-adapter-malformed")
            malformed->consumed_outputs.front().degree_t_derivation.terms
                    .front().source.producer_record_ordinal =
                    malformed->producer_records.size();
        else
            malformed->consumed_outputs.front().concrete_e_t_source
                    .special_sharing_support.front() = 1;
        SeededPRNG expected_prng = optimistic_authentication_prng;
        const auto receipt =
                adapt_finalized_tentative_double_rand_candidate();
        const auto duplicate =
                adapt_finalized_tentative_double_rand_candidate();
        SeededPRNG actual_prng = optimistic_authentication_prng;
        for (size_t i = 0; i < 4; i++)
            if (expected_prng.get_word() != actual_prng.get_word())
                fail("malformed preflight advanced authentication randomness");
        if (receipt.authenticated
                || receipt.authentication_invocation_id != 0
                || not receipt.dealer_batches.empty()
                || not receipt.source_handles.empty()
                || not receipt.converted_r_t_derivations.empty()
                || not receipt.authenticated_e_t_sources.empty()
                || not receipt.converted_z_t_derivations.empty()
                || duplicate.authenticated
                || duplicate.authentication_invocation_id != 0
                || not duplicate.converted_r_t_derivations.empty()
                || not duplicate.authenticated_e_t_sources.empty()
                || not duplicate.converted_z_t_derivations.empty()
                || inspect_tentative_double_rand_capture() != 0
                || auth.next_batch_id != next_batch_id_before
                || auth.dealer_batches.size() != batch_count_before
                || auth.global_invocations.size() != invocation_count_before
                || auth.next_global_invocation_id
                        != next_invocation_id_before
                || auth.global_check_tag_challenges
                        != challenge_count_before
                || auth.checkpoints.size() != checkpoint_count_before
                || auth.next_checkpoint_id != next_checkpoint_id_before
                || P.total_comm().sent != communication_before
                || not auth.keys.empty() || not auth.nu_material.empty()
                || not auth.holder_tags.empty())
            fail("malformed candidate was not discarded before all protocol mutation");

        tentative_double_rand_capture_test_hook_ran = true;
        if (P.my_num() == 0)
            cout << "ATLAS_GSZ_AUTH_TEST " << mode
                 << " PASS candidate=discarded retry=unsupported"
                 << " dealer_batches=0 handles=0 authentication_invocations=0"
                 << " communication=0 authentication_randomness=0"
                 << " checkpoints=0 converted_r_t_derivations=0"
                 << " authenticated_e_t_handles=0"
                 << " converted_z_t_derivations=0" << endl;
        return;
    }

    GlobalAuthenticationTestFault test_fault =
            GlobalAuthenticationTestFault::none;
    int bad_verify_sharing_dealer = -1;
    if (mode == "tentative-double-rand-adapter-verify-failure")
        bad_verify_sharing_dealer = 0;
    else if (mode == "tentative-double-rand-adapter-tag-failure")
        test_fault = GlobalAuthenticationTestFault::aggregate_holder_tag;
    else if (mode != "tentative-double-rand-adapter-honest")
        fail("unknown adapter mode reached focused hook");

    const auto receipt = adapt_finalized_tentative_double_rand_candidate(
            test_fault, bad_verify_sharing_dealer);
    const bool expected_success =
            mode == "tentative-double-rand-adapter-honest";
    if (receipt.authenticated != expected_success
            || receipt.authentication_invocation_id == 0
            || receipt.dealer_batches.size() != dealer_count
            || (expected_success
                    ? receipt.converted_r_t_derivations.size()
                            != expected_consumed_outputs.size()
                    : not receipt.converted_r_t_derivations.empty())
            || (expected_success
                    ? receipt.authenticated_e_t_sources.size()
                            != expected_consumed_outputs.size()
                    : not receipt.authenticated_e_t_sources.empty())
            || (expected_success
                    ? receipt.converted_z_t_derivations.size()
                            != expected_consumed_outputs.size()
                    : not receipt.converted_z_t_derivations.empty())
            || auth.next_batch_id
                    != next_batch_id_before + uint64_t(dealer_count)
            || auth.dealer_batches.size()
                    != batch_count_before + dealer_count
            || auth.global_invocations.size()
                    != invocation_count_before + 1
            || auth.next_global_invocation_id
                    != next_invocation_id_before + 1
            || auth.checkpoints.size() != checkpoint_count_before
            || auth.next_checkpoint_id != next_checkpoint_id_before
            || inspect_tentative_double_rand_capture() != 0)
        fail("adapter did not consume exactly one candidate into one all-dealer invocation");

    const auto& invocation = auth.global_invocations.back();
    if (invocation.invocation_id != receipt.authentication_invocation_id
            || invocation.checkpoint_id != 0
            || invocation.members.size() != dealer_count)
        fail("retained invocation is not the exact source-only invocation");

    for (size_t dealer = 0; dealer < dealer_count; dealer++)
    {
        const auto& summary = receipt.dealer_batches.at(dealer);
        const auto& member = invocation.members.at(dealer);
        const auto& batch = auth.dealer_batches.at(batch_count_before + dealer);
        const uint64_t expected_batch_id =
                next_batch_id_before + uint64_t(dealer);
        const size_t expected_dealer_source_count = dealer == 0
                ? source_count + expected_consumed_outputs.size()
                : source_count;
        if (summary.dealer != int(dealer)
                || summary.batch_id != expected_batch_id
                || summary.source_count != expected_dealer_source_count
                || member.dealer != int(dealer)
                || member.batch_id != expected_batch_id
                || batch.dealer != int(dealer)
                || batch.batch_id != expected_batch_id
                || batch.source_ordinals.size()
                        != expected_dealer_source_count
                || batch.local_source_shares.size()
                        != expected_dealer_source_count)
            fail("dealer batch identity/order/count is not exact");
        for (size_t source_ordinal = 0;
                source_ordinal < source_count; source_ordinal++)
            if (batch.source_ordinals.at(source_ordinal) != source_ordinal
                    || batch.local_source_shares.at(source_ordinal)
                            != expected_local_sources.at(dealer).at(
                                    source_ordinal))
                fail("source ordinal or copied local source share changed");
        if (dealer == 0)
            for (size_t output_index = 0;
                    output_index < expected_consumed_outputs.size();
                    output_index++)
            {
                const size_t source_ordinal = source_count + output_index;
                if (batch.source_ordinals.at(source_ordinal)
                                != source_ordinal
                        || batch.local_source_shares.at(source_ordinal)
                                != expected_consumed_outputs.at(output_index)
                                        .concrete_e_t_source.local_share)
                    fail("king e_t suffix ordinal or local source share changed");
            }
    }

    const size_t expected_mapping_count = checked_size_product(
            dealer_count, source_count,
            "AtlasGsz test: tentative adapter mapping count overflow");
    const size_t width = base_field_ftag_chunk_width();
    const size_t old_king_chunks = base_field_ftag_chunk_count(source_count);
    const size_t new_king_source_count =
            source_count + expected_consumed_outputs.size();
    const size_t new_king_chunks =
            base_field_ftag_chunk_count(new_king_source_count);
    const size_t non_king_chunks =
            base_field_ftag_chunk_count(source_count);
    const size_t expected_total_chunks = new_king_chunks
            + (dealer_count - 1) * non_king_chunks;
    const size_t expected_total_handles = new_king_source_count
            + (dealer_count - 1) * source_count;
    const size_t key_relation_count = dealer_count * (dealer_count - 1);
    const size_t ordinary_relation_count =
            expected_total_chunks * key_relation_count;
    const size_t base_relation_count = dealer_count * key_relation_count;
    size_t full_identity_match_count = 0;
    size_t local_z_t_evaluation_count = 0;
    size_t dot_product_z_t_count = 0;
    size_t z_t_term_count = 0;
    if (expected_success)
    {
        if (not invocation.completed || not invocation.passed
                || not invocation.challenge_sampled
                || auth.global_check_tag_challenges
                        != challenge_count_before + 1
                || receipt.source_handles.size() != expected_mapping_count
                || receipt.authenticated_e_t_sources.size()
                        != expected_consumed_outputs.size()
                || invocation.members.front().ftag_chunk_count
                        != new_king_chunks
                || invocation.max_ftag_chunk_count != new_king_chunks
                || auth.total_ftag_chunks != expected_total_chunks
                || auth.key_establishment_runs != 1
                || auth.keys.size() != key_relation_count
                || auth.check_key_masking_equation_checks
                        != dealer_count - 1
                || auth.nu_material.size()
                        != ordinary_relation_count + base_relation_count
                || auth.holder_tags.size()
                        != ordinary_relation_count + base_relation_count
                || auth.status != OptimisticAuthenticationStatus::ready)
            fail("successful adapter authentication state is incomplete");
        for (size_t dealer = 1; dealer < dealer_count; dealer++)
            if (invocation.members.at(dealer).ftag_chunk_count
                    != non_king_chunks)
                fail("non-king FTag chunk count changed");
        for (size_t index = 0;
                index < receipt.source_handles.size(); index++)
        {
            const size_t source_ordinal = index / dealer_count;
            const size_t dealer = index % dealer_count;
            const auto& expected_group = expected_groups.at(source_ordinal);
            const auto& mapping = receipt.source_handles.at(index);
            const auto& batch = auth.dealer_batches.at(
                    batch_count_before + dealer);
            const auto& exact_handle =
                    batch.authenticated_handles.at(source_ordinal);
            if (mapping.producer_record_ordinal
                            != expected_group.producer_record_ordinal
                    || mapping.input_generation_group_ordinal
                            != expected_group.input_generation_group_ordinal
                    || mapping.dealer != int(dealer)
                    || mapping.handle.batch_id
                            != next_batch_id_before + uint64_t(dealer)
                    || mapping.handle.dealer != int(dealer)
                    || mapping.handle.source_ordinal != source_ordinal
                    || not (mapping.handle == exact_handle))
                fail("receipt mapping is incomplete, non-canonical, or inexact");
        }
        for (size_t dealer = 0; dealer < dealer_count; dealer++)
        {
            const auto& batch = auth.dealer_batches.at(
                    batch_count_before + dealer);
            const size_t expected_dealer_source_count = dealer == 0
                    ? source_count + expected_consumed_outputs.size()
                    : source_count;
            if (batch.authentication_state
                            != DealerBatchAuthenticationState::authenticated
                    || batch.authenticated_handles.size()
                            != expected_dealer_source_count
                    || batch.verify_sharing_failure_evidence
                    || batch.base_sharing_failure_evidence)
                fail("successful batch did not receive every exact handle");
        }
        size_t committed_handle_count = 0;
        for (size_t dealer = 0; dealer < dealer_count; dealer++)
            committed_handle_count += auth.dealer_batches.at(
                    batch_count_before + dealer)
                    .authenticated_handles.size();
        if (committed_handle_count != expected_total_handles)
            fail("total committed handle count is incorrect");

        vector<bool> used_source_mappings(expected_mapping_count, false);
        for (size_t output_index = 0;
                output_index < expected_consumed_outputs.size();
                output_index++)
        {
            const auto& expected =
                    expected_consumed_outputs.at(output_index);
            const auto& converted =
                    receipt.converted_r_t_derivations.at(output_index);
            if (converted.capture_order_ordinal
                                != expected.capture_order_ordinal
                    || converted.producer_record_ordinal
                                != expected.producer_record_ordinal
                    || converted.producer_output_ordinal
                                != expected.producer_output_ordinal
                    || converted.input_generation_group_ordinal
                                != expected.input_generation_group_ordinal
                    || converted.operation_kind != expected.operation_kind
                    || converted.derivation.terms.size() != dealer_count
                    || expected.degree_t_derivation.terms.size()
                                != dealer_count)
                fail("converted r_t derivation lost its captured operation identity");

            T evaluated{};
            for (size_t dealer = 0; dealer < dealer_count; dealer++)
            {
                const auto& temporary_term =
                        expected.degree_t_derivation.terms.at(dealer);
                auto source_group_position = find(expected_groups.begin(),
                        expected_groups.end(),
                        TentativeSourceGroupReference{
                                temporary_term.source
                                        .producer_record_ordinal,
                                temporary_term.source
                                        .input_generation_group_ordinal});
                if (source_group_position == expected_groups.end())
                    fail("tentative term did not resolve through the source mapping");
                const size_t source_ordinal =
                        source_group_position - expected_groups.begin();
                const size_t mapping_index = checked_size_sum(
                        checked_size_product(source_ordinal, dealer_count,
                                "AtlasGsz test: converted mapping offset overflow"),
                        dealer,
                        "AtlasGsz test: converted mapping index overflow");
                if (mapping_index >= receipt.source_handles.size())
                    fail("converted term mapping index is out of range");
                const auto& mapping =
                        receipt.source_handles.at(mapping_index);
                const auto& final_term =
                        converted.derivation.terms.at(dealer);
                const auto& batch = auth.dealer_batches.at(
                        batch_count_before + dealer);
                const auto& exact_handle =
                        batch.authenticated_handles.at(source_ordinal);
                if (temporary_term.source.dealer != int(dealer)
                        || mapping.producer_record_ordinal
                                != temporary_term.source
                                        .producer_record_ordinal
                        || mapping.input_generation_group_ordinal
                                != temporary_term.source
                                        .input_generation_group_ordinal
                        || mapping.dealer != int(dealer)
                        || final_term.coefficient
                                != temporary_term.coefficient
                        || not (final_term.handle == mapping.handle)
                        || not (final_term.handle == exact_handle)
                        || batch.dealer != int(dealer)
                        || batch.source_ordinals.at(source_ordinal)
                                != source_ordinal)
                    fail("converted term changed order, coefficient, dealer, or committed handle");
                used_source_mappings.at(mapping_index) = true;
                evaluated += final_term.coefficient
                        * batch.local_source_shares.at(source_ordinal);
            }
            if (evaluated != expected.actual_r_t)
                fail("converted derivation does not evaluate to captured actual_r_t");
        }
        if (find(used_source_mappings.begin(),
                    used_source_mappings.end(), false)
                        != used_source_mappings.end())
            fail("an expected authenticated source mapping is unused");

        const auto& king_batch = auth.dealer_batches.at(batch_count_before);
        for (size_t output_index = 0;
                output_index < expected_consumed_outputs.size();
                output_index++)
        {
            const auto& expected =
                    expected_consumed_outputs.at(output_index);
            const auto& result =
                    receipt.authenticated_e_t_sources.at(output_index);
            const size_t source_ordinal = source_count + output_index;
            const auto& exact_handle =
                    king_batch.authenticated_handles.at(source_ordinal);
            if (result.capture_order_ordinal
                                != expected.capture_order_ordinal
                    || result.producer_record_ordinal
                                != expected.producer_record_ordinal
                    || result.producer_output_ordinal
                                != expected.producer_output_ordinal
                    || result.input_generation_group_ordinal
                                != expected.input_generation_group_ordinal
                    || result.operation_kind != expected.operation_kind
                    || result.king != 0
                    || result.special_sharing_support
                                != expected.concrete_e_t_source
                                        .special_sharing_support
                    || result.handle.batch_id != king_batch.batch_id
                    || result.handle.dealer != 0
                    || result.handle.source_ordinal != source_ordinal
                    || not (result.handle == exact_handle))
                fail("authenticated e_t result lost its exact operation or king suffix binding");
        }

        for (size_t output_index = 0;
                output_index < expected_consumed_outputs.size();
                output_index++)
        {
            const auto& expected =
                    expected_consumed_outputs.at(output_index);
            const auto& converted_r =
                    receipt.converted_r_t_derivations.at(output_index);
            const auto& authenticated_e =
                    receipt.authenticated_e_t_sources.at(output_index);
            const auto& converted_z =
                    receipt.converted_z_t_derivations.at(output_index);
            const bool full_identity_matches =
                    converted_r.capture_order_ordinal
                            == expected.capture_order_ordinal
                    && converted_r.producer_record_ordinal
                            == expected.producer_record_ordinal
                    && converted_r.producer_output_ordinal
                            == expected.producer_output_ordinal
                    && converted_r.input_generation_group_ordinal
                            == expected.input_generation_group_ordinal
                    && converted_r.operation_kind
                            == expected.operation_kind
                    && authenticated_e.capture_order_ordinal
                            == expected.capture_order_ordinal
                    && authenticated_e.producer_record_ordinal
                            == expected.producer_record_ordinal
                    && authenticated_e.producer_output_ordinal
                            == expected.producer_output_ordinal
                    && authenticated_e.input_generation_group_ordinal
                            == expected.input_generation_group_ordinal
                    && authenticated_e.operation_kind
                            == expected.operation_kind
                    && converted_z.capture_order_ordinal
                            == expected.capture_order_ordinal
                    && converted_z.producer_record_ordinal
                            == expected.producer_record_ordinal
                    && converted_z.producer_output_ordinal
                            == expected.producer_output_ordinal
                    && converted_z.input_generation_group_ordinal
                            == expected.input_generation_group_ordinal
                    && converted_z.operation_kind
                            == expected.operation_kind;
            if (not full_identity_matches)
                fail("r_t/e_t/z_t full operation identity does not match captured evidence");
            full_identity_match_count++;

            if (expected.partial_mult_transcript_record_ordinal
                        >= partial_mult_transcripts.size())
                fail("z_t result lost its concrete transcript record");
            const auto& record = partial_mult_transcripts.at(
                    expected.partial_mult_transcript_record_ordinal);
            const auto& transcript = record.transcript;
            if (record.operation_kind != expected.operation_kind
                    || record.producer_reference.producer_provenance
                            != expected_producer_records.at(
                                    expected.producer_record_ordinal)
                    || record.producer_reference.producer_output_ordinal
                            != expected.producer_output_ordinal
                    || record.offset >= z_verify.size()
                    || record.length <= 0
                    || size_t(record.length)
                            > z_verify.size() - record.offset
                    || transcript.r_t != expected.actual_r_t
                    || transcript.e_t
                            != expected.concrete_e_t_source.local_share
                    || z_verify.at(record.offset)
                            != transcript.e_t - transcript.r_t)
                fail("z_t result does not bind to the exact real transcript and z_verify entry");
            if (expected.operation_kind
                    == OrdinaryDoubleRandOperationKind::dot_product)
            {
                dot_product_z_t_count++;
                for (size_t padding = 1;
                        padding < size_t(record.length); padding++)
                    if (z_verify.at(record.offset + padding) != T{})
                        fail("dot-product z_verify padding is nonzero");
            }
            else if (record.length != 1)
                fail("scalar z_t transcript length is not one");

            const size_t e_t_source_ordinal = source_count
                    + expected.capture_order_ordinal;
            if (converted_z.derivation.terms.size() != dealer_count + 1
                    || converted_z.derivation.terms.at(0).coefficient
                            != one
                    || not (converted_z.derivation.terms.at(0).handle
                            == authenticated_e.handle)
                    || authenticated_e.handle.dealer != 0
                    || authenticated_e.handle.batch_id
                            != king_batch.batch_id
                    || authenticated_e.handle.source_ordinal
                            != e_t_source_ordinal
                    || not (authenticated_e.handle
                            == king_batch.authenticated_handles.at(
                                    e_t_source_ordinal)))
                fail("z_t derivation does not start with exact (1,h_e)");

            T local_r{};
            const T& local_e = king_batch.local_source_shares.at(
                    e_t_source_ordinal);
            T local_z = local_e;
            for (size_t r_term_index = 0;
                    r_term_index < converted_r.derivation.terms.size();
                    r_term_index++)
            {
                const auto& r_term = converted_r.derivation.terms.at(
                        r_term_index);
                const auto& z_term = converted_z.derivation.terms.at(
                        r_term_index + 1);
                if (r_term.handle.dealer < 0
                        || size_t(r_term.handle.dealer) >= dealer_count)
                    fail("z_t r_t term dealer is invalid");
                const auto& batch = auth.dealer_batches.at(
                        batch_count_before
                        + size_t(r_term.handle.dealer));
                const size_t source_ordinal = r_term.handle.source_ordinal;
                if (z_term.coefficient
                                != typename T::open_type{}
                                        - r_term.coefficient
                        || not (z_term.handle == r_term.handle)
                        || z_term.handle == authenticated_e.handle
                        || batch.batch_id != r_term.handle.batch_id
                        || batch.dealer != r_term.handle.dealer
                        || source_ordinal >= batch.source_ordinals.size()
                        || batch.source_ordinals.at(source_ordinal)
                                != source_ordinal
                        || source_ordinal
                                >= batch.authenticated_handles.size()
                        || not (r_term.handle
                                == batch.authenticated_handles.at(
                                        source_ordinal)))
                    fail("z_t negated term changed r_t coefficient, handle, or authoritative source");
                local_r += r_term.coefficient
                        * batch.local_source_shares.at(source_ordinal);
                local_z += z_term.coefficient
                        * batch.local_source_shares.at(source_ordinal);
            }
            for (size_t left = 0;
                    left < converted_z.derivation.terms.size(); left++)
                for (size_t right = 0; right < left; right++)
                    if (converted_z.derivation.terms.at(left).handle
                            == converted_z.derivation.terms.at(right).handle)
                        fail("one z_t derivation contains duplicate handles");
            for (size_t previous = 0; previous < output_index; previous++)
                if (authenticated_e.handle
                        == receipt.authenticated_e_t_sources.at(
                                previous).handle)
                    fail("e_t handle was reused by another z_t operation");
            if (local_r != expected.actual_r_t
                    || local_r != transcript.r_t
                    || local_e
                            != expected.concrete_e_t_source.local_share
                    || local_e != transcript.e_t
                    || local_z != local_e - local_r
                    || local_z != transcript.e_t - transcript.r_t
                    || local_z != z_verify.at(record.offset))
                fail("local authoritative r_t/e_t/z_t evaluation is not exact");
            local_z_t_evaluation_count++;
            z_t_term_count = converted_z.derivation.terms.size();
        }
        if (full_identity_match_count != expected_consumed_outputs.size()
                || local_z_t_evaluation_count
                        != expected_consumed_outputs.size()
                || dot_product_z_t_count != 3
                || z_t_term_count != dealer_count + 1)
            fail("z_t focused coverage count is incomplete");
    }
    else
    {
        if (not invocation.completed || invocation.passed
                || not receipt.source_handles.empty()
                || not receipt.converted_r_t_derivations.empty()
                || not receipt.authenticated_e_t_sources.empty()
                || not receipt.converted_z_t_derivations.empty()
                || auth.status != OptimisticAuthenticationStatus::
                        RecoveryNotImplemented)
            fail("failed adapter authentication did not retain fail-stop state");
        const bool verify_failure = bad_verify_sharing_dealer >= 0;
        if (verify_failure
                ? (invocation.failure_class
                                != OptimisticAuthenticationFailureClass::
                                        verify_sharing
                        || invocation.challenge_sampled
                        || auth.global_check_tag_challenges
                                != challenge_count_before)
                : (invocation.failure_class
                                != OptimisticAuthenticationFailureClass::
                                        tag_check
                        || not invocation.challenge_sampled
                        || auth.global_check_tag_challenges
                                != challenge_count_before + 1))
            fail("failure occurred at the wrong authentication boundary");
        for (size_t dealer = 0; dealer < dealer_count; dealer++)
        {
            const auto& batch = auth.dealer_batches.at(
                    batch_count_before + dealer);
            if (batch.authentication_state
                            != DealerBatchAuthenticationState::rejected
                    || not batch.authenticated_handles.empty())
                fail("a rejected participating batch retained a handle");
            if (verify_failure)
            {
                const bool failed_dealer = dealer == 0;
                if (bool(batch.verify_sharing_failure_evidence)
                                != failed_dealer
                        || batch.base_sharing_failure_evidence
                        || (failed_dealer
                            && batch.verify_sharing_failure_evidence
                                    ->published_shares.size()
                                    != dealer_count))
                    fail("Verify-Sharing failure evidence ownership is incorrect");
            }
            else if (batch.verify_sharing_failure_evidence
                    || batch.base_sharing_failure_evidence)
                fail("Check-Tag rejection retained unrelated sharing evidence");
        }
    }

    if (not auth.checkpoints.empty()
            || not verifiable_registry.checkpoints.empty())
        fail("adapter created a checkpoint");

    // The candidate is already absent. A duplicate call must return before
    // every ID, retained record, communication counter, and PRNG transition.
    const uint64_t duplicate_next_batch_id = auth.next_batch_id;
    const size_t duplicate_batch_count = auth.dealer_batches.size();
    const uint64_t duplicate_next_invocation_id =
            auth.next_global_invocation_id;
    const size_t duplicate_invocation_count = auth.global_invocations.size();
    const size_t duplicate_challenge_count =
            auth.global_check_tag_challenges;
    const size_t duplicate_key_count = auth.keys.size();
    const size_t duplicate_nu_count = auth.nu_material.size();
    const size_t duplicate_tag_count = auth.holder_tags.size();
    const size_t duplicate_key_runs = auth.key_establishment_runs;
    const size_t duplicate_total_chunks = auth.total_ftag_chunks;
    const size_t duplicate_verify_comm = auth.verify_sharing_communication;
    const size_t duplicate_base_comm = auth.base_sharing_communication;
    const size_t duplicate_tag_comm = auth.tag_generation_communication;
    const size_t duplicate_check_comm = auth.tag_checking_communication;
    const size_t duplicate_communication = P.total_comm().sent;
    SeededPRNG expected_prng = optimistic_authentication_prng;
    const auto duplicate = adapt_finalized_tentative_double_rand_candidate();
    SeededPRNG actual_prng = optimistic_authentication_prng;
    for (size_t i = 0; i < 4; i++)
        if (expected_prng.get_word() != actual_prng.get_word())
            fail("duplicate adaptation advanced authentication randomness");
    if (duplicate.authenticated
            || duplicate.authentication_invocation_id != 0
            || not duplicate.dealer_batches.empty()
            || not duplicate.source_handles.empty()
            || not duplicate.converted_r_t_derivations.empty()
            || not duplicate.authenticated_e_t_sources.empty()
            || not duplicate.converted_z_t_derivations.empty()
            || auth.next_batch_id != duplicate_next_batch_id
            || auth.dealer_batches.size() != duplicate_batch_count
            || auth.next_global_invocation_id
                    != duplicate_next_invocation_id
            || auth.global_invocations.size() != duplicate_invocation_count
            || auth.global_check_tag_challenges != duplicate_challenge_count
            || auth.keys.size() != duplicate_key_count
            || auth.nu_material.size() != duplicate_nu_count
            || auth.holder_tags.size() != duplicate_tag_count
            || auth.key_establishment_runs != duplicate_key_runs
            || auth.total_ftag_chunks != duplicate_total_chunks
            || auth.verify_sharing_communication != duplicate_verify_comm
            || auth.base_sharing_communication != duplicate_base_comm
            || auth.tag_generation_communication != duplicate_tag_comm
            || auth.tag_checking_communication != duplicate_check_comm
            || P.total_comm().sent != duplicate_communication)
        fail("duplicate adaptation changed authoritative or communication state");

    tentative_double_rand_capture_test_hook_ran = true;
    if (P.my_num() == 0)
    {
        size_t verified_sharings = 0;
        size_t checked_base_sharings = 0;
        size_t committed_handles = 0;
        for (size_t dealer = 0; dealer < dealer_count; dealer++)
        {
            const auto& batch = auth.dealer_batches.at(
                    batch_count_before + dealer);
            verified_sharings += batch.verify_sharing_completed;
            checked_base_sharings += batch.base_sharing_check_completed;
            committed_handles += batch.authenticated_handles.size();
        }
        cout << "ATLAS_GSZ_AUTH_TEST " << mode
             << " PASS operations=6 operation_order=scalar-dot-alternating"
             << " one_to_one_operation_binding=exact dealers="
             << dealer_count << " dealer_batches=" << dealer_count
             << " invocation_count=1 invocation=source-only checkpoint_id=0"
             << " checkpoints=0 double_rand_source_count=" << source_count
             << " source_counts=[";
        for (size_t dealer = 0; dealer < dealer_count; dealer++)
            cout << (dealer == 0 ? "" : ",")
                 << (dealer == 0 ? new_king_source_count : source_count);
        cout << "] chunk_width=" << width << " chunk_counts=[";
        for (size_t dealer = 0; dealer < dealer_count; dealer++)
            cout << (dealer == 0 ? "" : ",")
                 << invocation.members.at(dealer).ftag_chunk_count;
        cout << "] old_king_chunks=" << old_king_chunks
             << " new_king_chunks=" << new_king_chunks
             << " total_ordinary_chunks=" << auth.total_ftag_chunks
             << " max_ftag_chunk_count="
             << invocation.max_ftag_chunk_count
             << " total_committed_handles=" << committed_handles
             << " double_rand_mappings="
             << (expected_success ? receipt.source_handles.size() : 0)
             << " authenticated_e_t_handles="
             << (expected_success
                    ? receipt.authenticated_e_t_sources.size() : 0)
             << " converted_r_t_derivations="
             << (expected_success
                    ? receipt.converted_r_t_derivations.size() : 0)
             << " converted_z_t_derivations="
             << (expected_success
                    ? receipt.converted_z_t_derivations.size() : 0)
             << " full_identity_matches="
             << (expected_success ? full_identity_match_count : 0)
             << " z_t_terms_per_operation="
             << (expected_success ? z_t_term_count : 0)
             << " double_rand_mapping_formula=source-ordinal-times-dealers-plus-dealer"
             << " king_e_t_ordinals=2..7"
             << " key_establishment_runs=" << auth.key_establishment_runs
             << " chunk_width_agreement_comm="
             << auth.base_field_ftag_chunk_width_agreement_communication
             << " key_establishment_and_check_key_comm="
             << auth.key_establishment_communication
             << " check_key_runs=" << auth.key_establishment_runs
             << " check_key_relations=" << auth.keys.size()
             << " check_key_local_equations="
             << auth.check_key_masking_equation_checks
             << " verify_sharings=" << verified_sharings
             << " base_sharings=" << checked_base_sharings
             << " ordinary_tag_nu_relations="
             << (auth.total_ftag_chunks * auth.keys.size())
             << " base_sharing_tag_nu_relations="
             << (dealer_count * auth.keys.size())
             << " king_tag_nu_relation_increase="
             << ((new_king_chunks - old_king_chunks) * auth.keys.size())
             << " nu_records=" << auth.nu_material.size()
             << " holder_tag_records=" << auth.holder_tags.size()
             << " global_check_tag_challenges="
             << (auth.global_check_tag_challenges - challenge_count_before)
             << " verify_sharing_comm="
             << auth.verify_sharing_communication
             << " base_sharing_comm=" << auth.base_sharing_communication
             << " tag_generation_comm="
             << auth.tag_generation_communication
             << " check_tag_comm=" << auth.tag_checking_communication
             << " focused_invocation_comm="
             << (P.total_comm().sent - communication_before)
             << " candidate=consumed duplicate_adaptation=rejected"
             << " derivation_order=capture-order"
             << " z_t_term_order=e_t-then-negated-r_t"
             << " coefficient_negation=field-native-edge-cases-exact"
             << " duplicate_handles=none"
             << " local_r_t_evaluation=exact"
             << " local_e_t_binding=exact"
             << " local_z_t_evaluation="
             << (expected_success ? "exact" : "not-published")
             << " transcript_z_t_binding="
             << (expected_success ? "exact" : "not-published")
             << " dot_product_z_t_results="
             << (expected_success ? dot_product_z_t_count : 0)
             << " excluded_operation_classes=absent"
             << " certification=consistent-dealer-generated-source-sharings"
             << " randomness_prescription=not-certified"
             << (expected_success
                    ? " status=authenticated"
                    : " status=RecoveryNotImplemented") << endl;
    }

    if (not expected_success)
        throw mac_fail(
                "AtlasGsz: RecoveryNotImplemented after tentative DoubleRand adapter authentication failure");
}

template<class T>
bool AtlasGsz<T>::authenticate_checkpoint_source_batches(
        uint64_t checkpoint_id,
        const vector<uint64_t>& requested_batch_ids,
        GlobalAuthenticationTestFault test_fault,
        int inject_bad_verify_sharing_dealer,
        int inject_bad_base_sharing_dealer)
{
    // Zero is reserved exclusively for source-only authentication.
    if (checkpoint_id == 0)
        return false;

    auto& state = optimistic_authentication_state;
    GlobalAuthenticationInvocationRecord invocation{};
    invocation.invocation_id = state.next_global_invocation_id++;
    invocation.key_epoch = state.key_epoch;
    invocation.checkpoint_id = checkpoint_id;
    state.global_invocations.push_back(invocation);
    auto& retained_invocation = state.global_invocations.back();
    GlobalAuthenticationWorkingSet working{};

    if (not prepare_global_authentication(retained_invocation,
            requested_batch_ids, working,
            inject_bad_verify_sharing_dealer,
            inject_bad_base_sharing_dealer, test_fault))
        return false;
    if (not check_global_authentication(
            retained_invocation, working, test_fault))
        return false;
    if (not commit_global_authentication(retained_invocation, working))
    {
        fail_global_authentication(&retained_invocation, 0,
                OptimisticAuthenticationFailureClass::
                    invocation_validation);
        return false;
    }
    return true;
}

template<class T>
bool AtlasGsz<T>::authenticate_dealer_source_batch(
        uint64_t batch_id, bool inject_bad_presentation,
        bool inject_bad_verify_sharing,
        bool inject_bad_base_sharing)
{
    // Compatibility-only singleton adapter. The global invocation remains
    // the sole checker and the sole handle/checkpoint commit path.
    const auto* batch = find_dealer_source_batch(batch_id);
    if (batch == 0)
        return false;
    uint64_t checkpoint_id = 0;
    for (const auto& checkpoint : optimistic_authentication_state.checkpoints)
        if (not checkpoint.promoted)
            for (const auto& derivation : checkpoint.output_derivations)
                for (const auto& term : derivation.terms)
                    if (term.handle.batch_id == batch_id)
                    {
                        if (checkpoint_id != 0
                                && checkpoint_id
                                        != checkpoint.checkpoint_id)
                            return false;
                        checkpoint_id = checkpoint.checkpoint_id;
                    }
    if (checkpoint_id == 0)
        return false;
    return authenticate_checkpoint_source_batches(checkpoint_id,
            vector<uint64_t>(1, batch_id),
            inject_bad_presentation
                    ? GlobalAuthenticationTestFault::aggregate_holder_tag
                    : GlobalAuthenticationTestFault::none,
            inject_bad_verify_sharing ? batch->dealer : -1,
            inject_bad_base_sharing ? batch->dealer : -1);
}

template<class T>
bool AtlasGsz<T>::authenticated_handle_exists(
        const AuthenticatedSourceHandle& handle) const
{
    const auto* batch = find_dealer_source_batch(handle.batch_id);
    if (batch == 0
            || batch->dealer != handle.dealer
            || batch->authentication_state
                    != DealerBatchAuthenticationState::authenticated)
        return false;
    return find(batch->authenticated_handles.begin(),
            batch->authenticated_handles.end(), handle)
            != batch->authenticated_handles.end();
}

template<class T>
uint64_t AtlasGsz<T>::create_optimistic_checkpoint(
        const vector<LinearDerivation>& output_derivations)
{
    assert(not output_derivations.empty());
    OptimisticCheckpointRecord checkpoint{};
    checkpoint.checkpoint_id =
            optimistic_authentication_state.next_checkpoint_id++;
    checkpoint.output_derivations = output_derivations;
    optimistic_authentication_state.checkpoints.push_back(checkpoint);
    return checkpoint.checkpoint_id;
}

template<class T>
bool AtlasGsz<T>::promote_optimistic_checkpoint(uint64_t checkpoint_id)
{
    for (auto& checkpoint : optimistic_authentication_state.checkpoints)
        if (checkpoint.checkpoint_id == checkpoint_id)
        {
            if (checkpoint.promoted)
                return true;
            if (optimistic_authentication_state.status
                            != OptimisticAuthenticationStatus::ready)
                return false;
            for (const auto& derivation : checkpoint.output_derivations)
            {
                if (derivation.terms.empty())
                    return false;
                for (const auto& term : derivation.terms)
                    if (not authenticated_handle_exists(term.handle))
                        return false;
            }
            checkpoint.sealed = true;
            checkpoint.promoted = true;
            return true;
        }
    return false;
}

template<class T>
bool AtlasGsz<T>::run_optimistic_authentication_test_hook(
        const string& mode)
{
    auto& state = optimistic_authentication_state;
    assert(not state.test_hook_ran);
    state.test_hook_ran = true;
    assert(P.num_players() >= 3);
    assert(ShamirMachine::s().threshold * 2 < P.num_players());
    const size_t width = base_field_ftag_chunk_width();
    const size_t first_original_source_count = 9;
    const size_t second_original_source_count = 6;
    const size_t expected_first_ftag_chunks =
            base_field_ftag_chunk_count(first_original_source_count);
    const size_t expected_second_ftag_chunks =
            base_field_ftag_chunk_count(second_original_source_count);
    const size_t expected_total_ftag_chunks = checked_size_sum(
            expected_first_ftag_chunks, expected_second_ftag_chunks,
            "AtlasGsz test: total FTag chunk count overflow");

    const bool source_only = mode == "source-only-honest"
            || mode == "source-only-verify-failure"
            || mode == "source-only-failure";
    const bool global_mode = source_only || mode == "honest"
            || mode == "singleton-honest"
            || mode == "failure"
            || mode == "ordinary-failure"
            || mode == "base-contribution-failure"
            || mode == "verify-failure"
            || mode == "base-failure"
            || mode == "duplicate-batch"
            || mode == "duplicate-dealer"
            || mode == "omission"
            || mode == "missing-chunk"
            || mode == "duplicate-chunk"
            || mode == "epoch-mismatch";
    if (global_mode)
    {
        const bool singleton = mode == "singleton-honest";
        const bool duplicate_dealer = mode == "duplicate-dealer";
        vector<typename T::open_type> first_values;
        if (P.my_num() == 0)
            for (size_t i = 0; i < first_original_source_count; i++)
                first_values.push_back(
                        typename T::open_type(100 + int(i)));
        auto first_local_shares = deal_optimistic_source_values(
                0, first_values, first_original_source_count);
        const uint64_t first_batch_id = register_dealer_source_batch(
                0, first_local_shares);

        uint64_t second_batch_id = 0;
        int second_dealer = duplicate_dealer ? 0 : 1;
        if (not singleton)
        {
            vector<typename T::open_type> second_values;
            if (P.my_num() == second_dealer)
                for (size_t i = 0;
                        i < second_original_source_count; i++)
                    second_values.push_back(
                            typename T::open_type(200 + int(i)));
            auto second_local_shares = deal_optimistic_source_values(
                    second_dealer, second_values,
                    second_original_source_count);
            second_batch_id = register_dealer_source_batch(
                    second_dealer, second_local_shares);
        }

        uint64_t checkpoint_id = 0;
        if (not source_only)
        {
            LinearDerivation checkpoint_derivation{};
            auto append_derivation_terms = [&](uint64_t batch_id,
                    int dealer, size_t source_count)
            {
                for (size_t ordinal = 0; ordinal < source_count; ordinal++)
                {
                    LinearDerivationTerm term{};
                    term.handle.batch_id = batch_id;
                    term.handle.dealer = dealer;
                    term.handle.source_ordinal = ordinal;
                    term.coefficient =
                            typename T::open_type(int(ordinal + 1));
                    checkpoint_derivation.terms.push_back(term);
                }
            };
            append_derivation_terms(first_batch_id, 0,
                    first_original_source_count);
            if (not singleton)
                append_derivation_terms(second_batch_id, second_dealer,
                        second_original_source_count);
            checkpoint_id = create_optimistic_checkpoint(
                    vector<LinearDerivation>(1,
                            checkpoint_derivation));
            assert(not promote_optimistic_checkpoint(checkpoint_id));
        }

        vector<uint64_t> requested_batch_ids;
        if (singleton)
            requested_batch_ids.push_back(first_batch_id);
        else
        {
            // Deliberately reversed: the retained invocation must have the
            // same ascending-dealer layout as a canonical caller.
            requested_batch_ids.push_back(second_batch_id);
            requested_batch_ids.push_back(first_batch_id);
        }
        if (mode == "duplicate-batch")
            requested_batch_ids.insert(
                    requested_batch_ids.begin(), first_batch_id);
        else if (mode == "omission")
            requested_batch_ids.assign(1, first_batch_id);

        GlobalAuthenticationTestFault test_fault =
                GlobalAuthenticationTestFault::none;
        if (mode == "failure" || mode == "source-only-failure")
            test_fault =
                    GlobalAuthenticationTestFault::aggregate_holder_tag;
        else if (mode == "ordinary-failure")
            test_fault = GlobalAuthenticationTestFault::
                    ordinary_source_presentation;
        else if (mode == "base-contribution-failure")
            test_fault = GlobalAuthenticationTestFault::
                    base_sharing_presentation;
        else if (mode == "missing-chunk")
            test_fault = GlobalAuthenticationTestFault::missing_chunk;
        else if (mode == "duplicate-chunk")
            test_fault = GlobalAuthenticationTestFault::duplicate_chunk;
        else if (mode == "epoch-mismatch")
            test_fault = GlobalAuthenticationTestFault::key_epoch_mismatch;

        const int verify_failure_dealer =
                (mode == "verify-failure"
                        || mode == "source-only-verify-failure") ? 0 : -1;
        const int base_failure_dealer =
                mode == "base-failure" ? 0 : -1;
        const bool accepted = source_only
                ? authenticate_source_batches(requested_batch_ids,
                        test_fault, verify_failure_dealer,
                        base_failure_dealer)
                : authenticate_checkpoint_source_batches(checkpoint_id,
                        requested_batch_ids, test_fault,
                        verify_failure_dealer, base_failure_dealer);
        assert(state.global_invocations.size() == 1);
        const auto& invocation = state.global_invocations.front();
        assert(invocation.invocation_id == 1);
        assert(invocation.checkpoint_id == checkpoint_id);
        assert(invocation.key_epoch == state.key_epoch);

        const bool expected_success = mode == "honest" || singleton
                || mode == "source-only-honest";
        assert(accepted == expected_success);
        const auto* checkpoint = source_only ? 0 :
                find_optimistic_checkpoint(checkpoint_id);
        if (source_only)
        {
            assert(checkpoint_id == 0);
            assert(state.checkpoints.empty());
            assert(state.next_checkpoint_id == 1);
            assert(verifiable_registry.checkpoints.empty());
        }
        else
            assert(checkpoint != 0);
        const auto* first_batch =
                find_dealer_source_batch(first_batch_id);
        const auto* second_batch = singleton ? 0 :
                find_dealer_source_batch(second_batch_id);
        assert(first_batch != 0);
        assert(second_batch != 0 || singleton);

        if (expected_success)
        {
            const size_t expected_member_count = singleton ? 1 : 2;
            const size_t expected_chunks = singleton
                    ? expected_first_ftag_chunks
                    : expected_total_ftag_chunks;
            assert(invocation.completed && invocation.passed);
            assert(invocation.failure_class
                    == OptimisticAuthenticationFailureClass::none);
            assert(invocation.challenge_sampled);
            assert(invocation.members.size() == expected_member_count);
            assert(invocation.members.front().dealer == 0);
            assert(invocation.members.front().batch_id == first_batch_id);
            assert(invocation.members.front().ftag_chunk_count
                    == expected_first_ftag_chunks);
            if (not singleton)
            {
                assert(invocation.members.at(1).dealer == 1);
                assert(invocation.members.at(1).batch_id
                        == second_batch_id);
                assert(invocation.members.at(1).ftag_chunk_count
                        == expected_second_ftag_chunks);
            }
            assert(invocation.max_ftag_chunk_count
                    == max(expected_first_ftag_chunks,
                            singleton ? size_t(0)
                                    : expected_second_ftag_chunks));
            assert(state.global_check_tag_challenges == 1);
            assert(source_only
                    || (checkpoint->sealed && checkpoint->promoted));
            assert(first_batch->authentication_state
                    == DealerBatchAuthenticationState::authenticated);
            assert(first_batch->authenticated_handles.size()
                    == first_original_source_count);
            if (not singleton)
            {
                assert(second_batch->authentication_state
                        == DealerBatchAuthenticationState::authenticated);
                assert(second_batch->authenticated_handles.size()
                        == second_original_source_count);
            }
            assert(state.status == OptimisticAuthenticationStatus::ready);
            assert(state.key_establishment_runs == 1);
            assert(state.keys_established && state.keys_checked);
            assert(state.total_ftag_chunks == expected_chunks);

            const size_t expected_material_records =
                    checked_size_product(state.keys.size(),
                            checked_size_sum(expected_chunks,
                                    expected_member_count,
                                    "AtlasGsz test: global material count overflow"),
                            "AtlasGsz test: global material count overflow");
            assert(state.nu_material.size()
                    == expected_material_records);
            assert(state.holder_tags.size()
                    == expected_material_records);
            for (const auto& material : state.nu_material)
            {
                assert(material.key_epoch == state.key_epoch);
                assert(material.owns_nu
                        == (P.my_num() == material.verifier));
            }
            for (const auto& tag : state.holder_tags)
            {
                assert(tag.key_epoch == state.key_epoch);
                assert(tag.owns_tag
                        == (P.my_num() == tag.holder));
            }
            for (const auto& batch : state.dealer_batches)
            {
                assert(not batch.verify_sharing_failure_evidence);
                assert(not batch.base_sharing_failure_evidence);
                for (size_t handle_index = 0;
                        handle_index < batch.authenticated_handles.size();
                        handle_index++)
                {
                    const auto& handle =
                            batch.authenticated_handles.at(handle_index);
                    assert(handle.batch_id == batch.batch_id);
                    assert(handle.dealer == batch.dealer);
                    assert(handle.source_ordinal == handle_index);
                    assert(handle.source_ordinal
                            < batch.local_source_shares.size());
                }
            }

            const size_t max_degree = checked_size_product(
                    invocation.members.size(),
                    checked_size_sum(invocation.max_ftag_chunk_count, 1,
                            "AtlasGsz test: global degree overflow"),
                    "AtlasGsz test: global degree overflow") - 1;
            assert(state.verify_sharing_communication > 0);
            assert(state.base_sharing_communication > 0);
            assert(state.tag_generation_communication > 0);
            assert(state.tag_checking_communication > 0);
            if (P.my_num() == 0)
                cout << "ATLAS_GSZ_AUTH_TEST " << mode
                     << " PASS checker=global batches="
                     << expected_member_count
                     << " caller_order="
                     << (singleton ? "canonical" : "reversed")
                     << " canonical_order=ascending-dealer"
                     << " base_field_ftag_chunk_width=" << width
                     << " first_original_source_count="
                     << first_original_source_count
                     << " second_original_source_count="
                     << (singleton ? 0 : second_original_source_count)
                     << " first_ftag_chunks="
                     << expected_first_ftag_chunks
                     << " second_ftag_chunks="
                     << (singleton ? 0 : expected_second_ftag_chunks)
                     << " W=" << invocation.max_ftag_chunk_count
                     << " max_degree=" << max_degree
                     << " global_challenges=1 zero_permitted=1"
                     << " compact_decisions=" << P.num_players()
                     << " decision_rounds=1"
                     << " base_sharings=" << expected_member_count
                     << " key_epoch=1 key_runs=1"
                     << " verify_sharing_comm="
                     << state.verify_sharing_communication
                     << " base_sharing_comm="
                     << state.base_sharing_communication
                     << " tag_comm="
                     << state.tag_generation_communication
                     << " global_check_comm="
                     << state.tag_checking_communication
                     << " handles="
                     << (first_original_source_count
                             + (singleton ? 0
                                     : second_original_source_count))
                     << " checkpoint_id=" << checkpoint_id
                     << " checkpoints=" << state.checkpoints.size()
                     << " sealed=" << (source_only ? 0 : 1)
                     << " promoted=" << (source_only ? 0 : 1) << endl;
            return true;
        }

        assert(not accepted);
        assert(invocation.completed && not invocation.passed);
        assert(source_only
                || (not checkpoint->sealed && not checkpoint->promoted));
        assert(first_batch->authentication_state
                != DealerBatchAuthenticationState::authenticated);
        assert(first_batch->authenticated_handles.empty());
        if (second_batch != 0)
        {
            assert(second_batch->authentication_state
                    != DealerBatchAuthenticationState::authenticated);
            assert(second_batch->authenticated_handles.empty());
        }
        assert(state.status == OptimisticAuthenticationStatus::
                RecoveryNotImplemented);
        const bool tag_failure = mode == "failure"
                || mode == "source-only-failure"
                || mode == "ordinary-failure"
                || mode == "base-contribution-failure";
        const char* fault_component = mode == "ordinary-failure"
                ? "ordinary_sigma"
                : mode == "base-contribution-failure"
                    ? "base_sigma"
                    : mode == "failure" || mode == "source-only-failure"
                        ? "aggregate_tag"
                        : "none";
        if (tag_failure)
        {
            assert(invocation.failure_class
                    == OptimisticAuthenticationFailureClass::tag_check);
            assert(invocation.challenge_sampled);
            assert(state.global_check_tag_challenges == 1);
            assert(state.failed_batch_id == 0);
            assert(invocation.failed_verifier == 0);
            assert(invocation.failed_holder == 1);
            assert(invocation.owns_failure_presentation
                    == (P.my_num() == 0));
            assert(not invocation.owns_failure_presentation
                    || invocation.failure_sigma.size() == width);
            assert(state.tag_checking_communication > 0);
        }
        else
        {
            assert(not invocation.challenge_sampled);
            assert(state.global_check_tag_challenges == 0);
            assert(not invocation.owns_failure_presentation);
            if (mode == "verify-failure"
                    || mode == "source-only-verify-failure")
            {
                assert(invocation.failure_class
                        == OptimisticAuthenticationFailureClass::
                            verify_sharing);
                assert(first_batch->verify_sharing_failure_evidence);
                assert(first_batch->verify_sharing_failure_evidence
                                ->published_shares.size()
                        == size_t(P.num_players()));
                assert(not first_batch->base_sharing_failure_evidence);
                assert(not state.keys_established);
            }
            else if (mode == "base-failure")
            {
                assert(invocation.failure_class
                        == OptimisticAuthenticationFailureClass::
                            base_sharing);
                assert(first_batch->base_sharing_failure_evidence);
                assert(first_batch->base_sharing_failure_evidence
                                ->published_shares.size()
                        == size_t(P.num_players()));
                assert(not first_batch->verify_sharing_failure_evidence);
                assert(state.keys_established && state.keys_checked);
            }
            else
                assert(invocation.failure_class
                        == OptimisticAuthenticationFailureClass::
                            invocation_validation);
        }
        if (tag_failure)
            for (const auto& batch : state.dealer_batches)
            {
                assert(not batch.verify_sharing_failure_evidence);
                assert(not batch.base_sharing_failure_evidence);
            }
        assert(dispute_control_state.corr.empty());
        assert(dispute_control_state.disp.empty());
        assert(pending_analyze_sharing_state.requests.empty());
        if (P.my_num() == 0)
            cout << "ATLAS_GSZ_AUTH_TEST " << mode
                 << " PASS status=RecoveryNotImplemented"
                 << " checker=global handles=0 checkpoint_id="
                 << checkpoint_id
                 << " checkpoints=" << state.checkpoints.size()
                 << " sealed=0 promoted=0"
                 << " failed_batch_id=" << state.failed_batch_id
                 << " failed_verifier=" << state.failed_verifier
                 << " failed_holder=" << state.failed_holder
                 << " global_challenges="
                 << state.global_check_tag_challenges
                 << " zero_permitted=1"
                 << " compact_decisions="
                 << (tag_failure ? P.num_players() : 0)
                 << " decision_rounds=" << (tag_failure ? 1 : 0)
                 << " fault_component=" << fault_component
                 << " base_field_ftag_chunk_width=" << width
                 << " first_ftag_chunks="
                 << expected_first_ftag_chunks
                 << " second_ftag_chunks="
                 << (singleton ? 0 : expected_second_ftag_chunks)
                 << " verify_sharing_comm="
                 << state.verify_sharing_communication
                 << " base_sharing_comm="
                 << state.base_sharing_communication
                 << " tag_comm="
                 << state.tag_generation_communication
                 << " global_check_comm="
                 << state.tag_checking_communication << endl;
        return false;
    }

    throw logic_error("AtlasGsz: unreachable focused authentication mode");
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
void AtlasGsz<T>::ensure_pending_analyze_sharing_state_initialized()
{
    if (not pending_analyze_sharing_state.initialized)
    {
        pending_analyze_sharing_state.next_request_id = 1;
        pending_analyze_sharing_state.requests.clear();
        pending_analyze_sharing_state.initialized = true;
    }

    assert(pending_analyze_sharing_state.next_request_id > 0);
}

template<class T>
void AtlasGsz<T>::validate_pending_analyze_sharing_state() const
{
    if (not pending_analyze_sharing_state.initialized)
        return;

    assert(pending_analyze_sharing_state.next_request_id > 0);

    auto find_checkpoint = [&](uint64_t checkpoint_id)
        -> const CheckpointRecord*
    {
        if (checkpoint_id == 0 || not verifiable_registry.initialized)
            return 0;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == checkpoint_id)
                return &checkpoint;
        return 0;
    };

    for (size_t i = 0;
            i < pending_analyze_sharing_state.requests.size(); i++)
    {
        const auto& request =
                pending_analyze_sharing_state.requests.at(i);
        assert(request.valid);
        assert(request.id != 0);
        assert(request.source != PendingAnalyzeSharingSource::none);
        assert(request.target != PendingAnalyzeSharingTarget::none);

        for (size_t j = i + 1;
                j < pending_analyze_sharing_state.requests.size(); j++)
        {
            const auto& other =
                    pending_analyze_sharing_state.requests.at(j);
            assert(request.id != other.id);
            if (request.source
                        == PendingAnalyzeSharingSource::
                            authentication_rejection
                    && other.source
                        == PendingAnalyzeSharingSource::
                            authentication_rejection)
                assert(not (request.checkpoint_id == other.checkpoint_id
                        && request.sharing_id == other.sharing_id));
            if (request.source
                        == PendingAnalyzeSharingSource::ultimate_failure
                    && other.source
                        == PendingAnalyzeSharingSource::ultimate_failure)
                assert(request.target != other.target);
        }

        switch (request.source)
        {
        case PendingAnalyzeSharingSource::authentication_rejection:
        {
            assert(request.target
                    == PendingAnalyzeSharingTarget::
                        registered_checkpoint_output_sharing);
            assert(request.checkpoint_id != 0);
            assert(request.segment_id != 0);
            assert(request.sharing_id != 0);
            assert(request.registered_snapshot_id == 0);
            assert(request.authentication_plan_record_ids.empty());
            assert(request.authentication_material_record_ids.empty());
            assert(not request.rejected_holder_ids.empty());

            const auto* checkpoint = find_checkpoint(
                    request.checkpoint_id);
            assert(checkpoint != 0);
            assert(checkpoint->segment_id == request.segment_id);
            assert(std::find(checkpoint->sharing_ids.begin(),
                    checkpoint->sharing_ids.end(), request.sharing_id)
                    != checkpoint->sharing_ids.end());

            const auto* sharing = find_registered_sharing(
                    request.sharing_id);
            assert(sharing != 0);
            assert(sharing->kind
                    == RegisteredSharingKind::checkpoint_output);
            assert(sharing->checkpoint_id == request.checkpoint_id);
            assert(sharing->segment_id == request.segment_id);

            for (size_t j = 0;
                    j < request.rejected_holder_ids.size(); j++)
            {
                int holder = request.rejected_holder_ids.at(j);
                assert(0 <= holder);
                assert(holder < P.num_players());
                assert(is_active_party(holder));
                for (size_t k = j + 1;
                        k < request.rejected_holder_ids.size(); k++)
                    assert(holder != request.rejected_holder_ids.at(k));
            }
            break;
        }

        case PendingAnalyzeSharingSource::ultimate_failure:
        {
            assert(request.target
                    == PendingAnalyzeSharingTarget::published_alpha
                    || request.target
                        == PendingAnalyzeSharingTarget::published_beta);
            assert(request.checkpoint_id == 0);
            assert(request.segment_id == 0);
            assert(request.sharing_id == 0);
            assert(request.rejected_holder_ids.empty());

            const auto* snapshot = find_registered_sharing(
                    request.registered_snapshot_id);
            assert(request.registered_snapshot_id != 0);
            assert(snapshot != 0);
            assert(snapshot->kind
                    == RegisteredSharingKind::analyze_request_snapshot);
            assert(snapshot->degree == RegisteredSharingDegree::degree_t);
            assert(snapshot->has_published_snapshot);
            assert(not request.authentication_plan_record_ids.empty());
            assert(request.authentication_material_record_ids.size()
                    == request.authentication_plan_record_ids.size());

            for (auto record_id :
                    request.authentication_plan_record_ids)
            {
                const auto* record =
                        find_authentication_plan_record(record_id);
                assert(record != 0);
                assert(record->sharing_id
                        == request.registered_snapshot_id);
                assert(record->checkpoint_id == 0);
                assert(record->kind
                        == AuthenticationRecordKind::
                            analyze_request_snapshot);
            }

            for (auto material_id :
                    request.authentication_material_record_ids)
            {
                const auto* material =
                        find_authentication_material_record(material_id);
                assert(material != 0);
                assert(material->sharing_id
                        == request.registered_snapshot_id);
                assert(material->checkpoint_id == 0);
                assert(material->kind
                        == AuthenticationRecordKind::
                            analyze_request_snapshot);
                assert(std::find(
                        request.authentication_plan_record_ids.begin(),
                        request.authentication_plan_record_ids.end(),
                        material->auth_record_id)
                        != request.authentication_plan_record_ids.end());
            }
            break;
        }

        case PendingAnalyzeSharingSource::none:
            assert(false);
            break;
        }
    }
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingRequest*
AtlasGsz<T>::find_pending_analyze_sharing_request(uint64_t id)
{
    for (auto& request : pending_analyze_sharing_state.requests)
        if (request.id == id)
            return &request;
    return 0;
}

template<class T>
const typename AtlasGsz<T>::PendingAnalyzeSharingRequest*
AtlasGsz<T>::find_pending_analyze_sharing_request(uint64_t id) const
{
    for (const auto& request : pending_analyze_sharing_state.requests)
        if (request.id == id)
            return &request;
    return 0;
}

template<class T>
bool AtlasGsz<T>::pending_analyze_sharing_request_exists_for_authentication_rejection(
        uint64_t checkpoint_id,
        uint64_t sharing_id) const
{
    if (not pending_analyze_sharing_state.initialized)
        return false;

    for (const auto& request :
            pending_analyze_sharing_state.requests)
        if (request.source
                    == PendingAnalyzeSharingSource::
                        authentication_rejection
                && request.target
                    == PendingAnalyzeSharingTarget::
                        registered_checkpoint_output_sharing
                && request.checkpoint_id == checkpoint_id
                && request.sharing_id == sharing_id)
            return true;
    return false;
}

template<class T>
bool AtlasGsz<T>::pending_analyze_sharing_request_exists_for_ultimate_failure(
        PendingAnalyzeSharingTarget target) const
{
    assert(target == PendingAnalyzeSharingTarget::published_alpha
            || target == PendingAnalyzeSharingTarget::published_beta);

    if (target != PendingAnalyzeSharingTarget::published_alpha
            && target != PendingAnalyzeSharingTarget::published_beta)
        return false;

    if (not pending_analyze_sharing_state.initialized)
        return false;

    for (const auto& request :
            pending_analyze_sharing_state.requests)
        if (request.source
                    == PendingAnalyzeSharingSource::ultimate_failure
                && request.target == target)
            return true;
    return false;
}

template<class T>
uint64_t AtlasGsz<T>::create_pending_analyze_sharing_request_for_authentication_rejection(
        const AuthenticationAnalyzeSharingPlanEntry& entry)
{
    ensure_pending_analyze_sharing_state_initialized();
    validate_authentication_analyze_plan_entry(entry);
    assert(entry.kind
            == AuthenticationRecordKind::checkpoint_output_share);
    assert(entry.sharing_status
            == AuthenticationSharingDecisionStatus::rejected);
    assert(entry.would_analyze_sharing);

    const auto* sharing = find_registered_sharing(entry.sharing_id);
    assert(sharing != 0);
    assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
    assert(sharing->checkpoint_id == entry.checkpoint_id);
    assert(sharing->segment_id == entry.segment_id);

    for (const auto& request :
            pending_analyze_sharing_state.requests)
        if (request.source
                    == PendingAnalyzeSharingSource::
                        authentication_rejection
                && request.target
                    == PendingAnalyzeSharingTarget::
                        registered_checkpoint_output_sharing
                && request.checkpoint_id == entry.checkpoint_id
                && request.sharing_id == entry.sharing_id)
            return request.id;

    PendingAnalyzeSharingRequest request{};
    request.valid = true;
    request.id = pending_analyze_sharing_state.next_request_id++;
    assert(pending_analyze_sharing_state.next_request_id > 0);
    request.source =
            PendingAnalyzeSharingSource::authentication_rejection;
    request.target =
            PendingAnalyzeSharingTarget::
                registered_checkpoint_output_sharing;
    request.checkpoint_id = entry.checkpoint_id;
    request.segment_id = entry.segment_id;
    request.sharing_id = entry.sharing_id;
    request.rejected_holder_ids = entry.rejected_holder_ids;

    pending_analyze_sharing_state.requests.push_back(request);
    validate_pending_analyze_sharing_state();
    return request.id;
}

template<class T>
uint64_t AtlasGsz<T>::create_pending_analyze_sharing_request_for_ultimate_failure(
        const AnalyzeSharingRequest& analyze_request)
{
    PendingAnalyzeSharingTarget target =
            PendingAnalyzeSharingTarget::none;
    if (analyze_request.target == AnalyzeSharingRequestTarget::alpha)
        target = PendingAnalyzeSharingTarget::published_alpha;
    else if (analyze_request.target == AnalyzeSharingRequestTarget::beta)
        target = PendingAnalyzeSharingTarget::published_beta;
    else
        return 0;

    if (not analyze_request.valid
            || not analyze_request.has_registered_snapshot
            || analyze_request.registered_snapshot_id == 0
            || not analyze_request.has_authentication_plan
            || not analyze_request.has_authentication_material
            || analyze_request.authentication_plan_record_ids.empty()
            || analyze_request.authentication_material_record_ids.size()
                != analyze_request.authentication_plan_record_ids.size())
        return 0;

    const auto* snapshot = find_registered_sharing(
            analyze_request.registered_snapshot_id);
    if (snapshot == 0
            || snapshot->kind
                != RegisteredSharingKind::analyze_request_snapshot
            || snapshot->degree != RegisteredSharingDegree::degree_t
            || not snapshot->has_published_snapshot)
        return 0;

    for (auto record_id : analyze_request.authentication_plan_record_ids)
    {
        const auto* record = find_authentication_plan_record(record_id);
        if (record == 0
                || record->sharing_id
                    != analyze_request.registered_snapshot_id
                || record->checkpoint_id != 0
                || record->kind
                    != AuthenticationRecordKind::
                        analyze_request_snapshot)
            return 0;
    }

    for (auto material_id :
            analyze_request.authentication_material_record_ids)
    {
        const auto* material =
                find_authentication_material_record(material_id);
        if (material == 0
                || material->sharing_id
                    != analyze_request.registered_snapshot_id
                || material->checkpoint_id != 0
                || material->kind
                    != AuthenticationRecordKind::
                        analyze_request_snapshot
                || std::find(
                    analyze_request.authentication_plan_record_ids.begin(),
                    analyze_request.authentication_plan_record_ids.end(),
                    material->auth_record_id)
                    == analyze_request.authentication_plan_record_ids.end())
            return 0;
    }

#ifndef NDEBUG
    validate_analyze_sharing_request(analyze_request);
#endif

    if (pending_analyze_sharing_state.initialized)
        for (const auto& request :
                pending_analyze_sharing_state.requests)
            if (request.source
                        == PendingAnalyzeSharingSource::ultimate_failure
                    && request.target == target)
            {
                if (request.registered_snapshot_id
                            != analyze_request.registered_snapshot_id
                        || request.authentication_plan_record_ids
                            != analyze_request.authentication_plan_record_ids
                        || request.authentication_material_record_ids
                            != analyze_request
                                .authentication_material_record_ids)
                    return 0;
                return request.id;
            }

    ensure_pending_analyze_sharing_state_initialized();

    PendingAnalyzeSharingRequest request{};
    request.valid = true;
    request.id = pending_analyze_sharing_state.next_request_id++;
    assert(pending_analyze_sharing_state.next_request_id > 0);
    request.source = PendingAnalyzeSharingSource::ultimate_failure;
    request.target = target;
    request.registered_snapshot_id =
            analyze_request.registered_snapshot_id;
    request.authentication_plan_record_ids =
            analyze_request.authentication_plan_record_ids;
    request.authentication_material_record_ids =
            analyze_request.authentication_material_record_ids;

    pending_analyze_sharing_state.requests.push_back(request);
    validate_pending_analyze_sharing_state();
    return request.id;
}

template<class T>
typename AtlasGsz<T>::UltimateFailureAnalyzeEnqueueResult
AtlasGsz<T>::enqueue_current_ultimate_failure_analyze_request_once()
{
    UltimateFailureAnalyzeEnqueueResult result{};
    result.valid = true;

    auto finish = [&](UltimateFailureAnalyzeEnqueueAction action)
            -> UltimateFailureAnalyzeEnqueueResult
    {
        result.action = action;
        validate_ultimate_failure_analyze_enqueue_result(result);
        return result;
    };

    auto finish_inconsistent = [&]()
            -> UltimateFailureAnalyzeEnqueueResult
    {
        result.state_updated = false;
        result.pending_request_id = 0;
        result.registered_snapshot_id = 0;
        result.authentication_plan_record_ids.clear();
        result.authentication_material_record_ids.clear();
        return finish(
                UltimateFailureAnalyzeEnqueueAction::
                    inconsistent_state);
    };

    if (not have_ultimate_failure_context)
        return finish(
                UltimateFailureAnalyzeEnqueueAction::
                    no_current_failure);

    const auto& context = ultimate_failure_context;
    if (not context.valid
            || not context.fault_localization.valid
            || not context.fault_application.valid)
        return finish_inconsistent();

    result.sharing_to_analyze =
            context.fault_localization.sharing_to_analyze;
    result.source = context.fault_localization.source;

    bool fault_needs_analyze =
            context.fault_localization.action
            == FaultLocalizationAction::needs_analyze_sharing;
    bool application_pending =
            context.fault_application.action
            == FaultLocalizationApplicationAction::
                pending_analyze_sharing;

    if (not fault_needs_analyze && not application_pending)
        return finish(
                UltimateFailureAnalyzeEnqueueAction::
                    no_analyze_required);

    if (fault_needs_analyze != application_pending)
        return finish_inconsistent();

    if (not context.has_analyze_sharing_request
            || not context.analyze_sharing_request.valid)
        return finish(
                UltimateFailureAnalyzeEnqueueAction::
                    missing_analyze_request);

    const auto& analyze_request = context.analyze_sharing_request;
    if (analyze_request.target == AnalyzeSharingRequestTarget::alpha)
        result.target = PendingAnalyzeSharingTarget::published_alpha;
    else if (analyze_request.target == AnalyzeSharingRequestTarget::beta)
        result.target = PendingAnalyzeSharingTarget::published_beta;
    else
        return finish_inconsistent();

    if (analyze_request.sharing_to_analyze
                != result.sharing_to_analyze
            || analyze_request.source != result.source
            || not analyze_request.has_registered_snapshot
            || analyze_request.registered_snapshot_id == 0
            || not analyze_request.has_authentication_plan
            || not analyze_request.has_authentication_material)
        return finish_inconsistent();

    result.registered_snapshot_id =
            analyze_request.registered_snapshot_id;
    result.authentication_plan_record_ids =
            analyze_request.authentication_plan_record_ids;
    result.authentication_material_record_ids =
            analyze_request.authentication_material_record_ids;

#ifndef NDEBUG
    validate_analyze_sharing_request(analyze_request);
#endif

    if (pending_analyze_sharing_state.initialized)
    {
        for (const auto& request :
                pending_analyze_sharing_state.requests)
        {
            if (request.source
                        != PendingAnalyzeSharingSource::
                            ultimate_failure
                    || request.target != result.target)
                continue;

            if (request.registered_snapshot_id
                        != result.registered_snapshot_id
                    || request.authentication_plan_record_ids
                        != result.authentication_plan_record_ids
                    || request.authentication_material_record_ids
                        != result.authentication_material_record_ids)
                return finish_inconsistent();

            result.pending_request_id = request.id;
            result.state_updated = false;
            return finish(
                    UltimateFailureAnalyzeEnqueueAction::
                        already_enqueued);
        }
    }

    uint64_t request_id =
            create_pending_analyze_sharing_request_for_ultimate_failure(
                    analyze_request);
    if (request_id == 0)
        return finish_inconsistent();

    result.pending_request_id = request_id;
    result.state_updated = true;
    return finish(
            UltimateFailureAnalyzeEnqueueAction::enqueued_request);
}

template<class T>
void AtlasGsz<T>::validate_ultimate_failure_analyze_enqueue_result(
        const UltimateFailureAnalyzeEnqueueResult& result) const
{
    assert(result.valid);
    assert(result.action
            != UltimateFailureAnalyzeEnqueueAction::none);

    auto has_pending_target = [&]()
    {
        return result.target == PendingAnalyzeSharingTarget::published_alpha
                || result.target
                    == PendingAnalyzeSharingTarget::published_beta;
    };

    auto validate_request_link = [&]()
    {
        assert(result.pending_request_id != 0);
        assert(has_pending_target());
        assert(result.registered_snapshot_id != 0);
        assert(not result.authentication_plan_record_ids.empty());
        assert(result.authentication_material_record_ids.size()
                == result.authentication_plan_record_ids.size());

        const auto* request = find_pending_analyze_sharing_request(
                result.pending_request_id);
        assert(request != 0);
        assert(request->source
                == PendingAnalyzeSharingSource::ultimate_failure);
        assert(request->target == result.target);
        assert(request->registered_snapshot_id
                == result.registered_snapshot_id);
        assert(request->authentication_plan_record_ids
                == result.authentication_plan_record_ids);
        assert(request->authentication_material_record_ids
                == result.authentication_material_record_ids);

        const auto* snapshot = find_registered_sharing(
                result.registered_snapshot_id);
        assert(snapshot != 0);
        assert(snapshot->kind
                == RegisteredSharingKind::analyze_request_snapshot);
        assert(snapshot->degree == RegisteredSharingDegree::degree_t);
        assert(snapshot->has_published_snapshot);
    };

    switch (result.action)
    {
    case UltimateFailureAnalyzeEnqueueAction::no_current_failure:
        assert(not result.state_updated);
        assert(result.sharing_to_analyze == SharingToAnalyze::none);
        assert(result.source == FaultLocalizationSource::none);
        assert(result.target == PendingAnalyzeSharingTarget::none);
        assert(result.pending_request_id == 0);
        assert(result.registered_snapshot_id == 0);
        assert(result.authentication_plan_record_ids.empty());
        assert(result.authentication_material_record_ids.empty());
        break;

    case UltimateFailureAnalyzeEnqueueAction::no_analyze_required:
    case UltimateFailureAnalyzeEnqueueAction::missing_analyze_request:
        assert(not result.state_updated);
        assert(result.target == PendingAnalyzeSharingTarget::none);
        assert(result.pending_request_id == 0);
        assert(result.registered_snapshot_id == 0);
        assert(result.authentication_plan_record_ids.empty());
        assert(result.authentication_material_record_ids.empty());
        break;

    case UltimateFailureAnalyzeEnqueueAction::already_enqueued:
        assert(not result.state_updated);
        assert(result.sharing_to_analyze == SharingToAnalyze::alpha
                || result.sharing_to_analyze == SharingToAnalyze::beta);
        assert(result.source == FaultLocalizationSource::inconsistent_alpha
                || result.source
                    == FaultLocalizationSource::inconsistent_beta);
        validate_request_link();
        break;

    case UltimateFailureAnalyzeEnqueueAction::enqueued_request:
        assert(result.state_updated);
        assert(result.sharing_to_analyze == SharingToAnalyze::alpha
                || result.sharing_to_analyze == SharingToAnalyze::beta);
        assert(result.source == FaultLocalizationSource::inconsistent_alpha
                || result.source
                    == FaultLocalizationSource::inconsistent_beta);
        validate_request_link();
        break;

    case UltimateFailureAnalyzeEnqueueAction::inconsistent_state:
        assert(not result.state_updated);
        assert(result.pending_request_id == 0);
        assert(result.registered_snapshot_id == 0);
        assert(result.authentication_plan_record_ids.empty());
        assert(result.authentication_material_record_ids.empty());
        break;

    case UltimateFailureAnalyzeEnqueueAction::none:
        assert(false);
        break;
    }
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingDispatchPlan
AtlasGsz<T>::inspect_pending_analyze_sharing_request_by_index(
        size_t index) const
{
#ifndef NDEBUG
    bool pending_state_was_initialized =
            pending_analyze_sharing_state.initialized;
    uint64_t next_pending_request_id_before =
            pending_analyze_sharing_state.next_request_id;
    size_t pending_request_count_before =
            pending_analyze_sharing_state.requests.size();

    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_inspection = dispute_control_state.corr;
    auto disp_before_inspection = dispute_control_state.disp;

    bool segment_lifecycle_was_initialized =
            segment_lifecycle.initialized;
    uint64_t lifecycle_current_segment_before =
            segment_lifecycle.current_segment_id;
    uint64_t lifecycle_last_completed_before =
            segment_lifecycle.last_completed_segment_id;
    bool lifecycle_segment_open_before = segment_lifecycle.segment_open;
    bool lifecycle_checkpoint_open_before =
            segment_lifecycle.checkpoint_open;
    uint64_t lifecycle_input_checkpoint_before =
            segment_lifecycle.current_input_checkpoint_id;
    uint64_t lifecycle_output_checkpoint_before =
            segment_lifecycle.current_output_checkpoint_id;
    auto lifecycle_input_sharings_before =
            segment_lifecycle.current_segment_input_sharings;
    auto lifecycle_output_sharings_before =
            segment_lifecycle.current_segment_output_sharings;

    bool verifiable_registry_was_initialized =
            verifiable_registry.initialized;
    uint64_t next_sharing_id_before =
            verifiable_registry.next_sharing_id;
    uint64_t next_checkpoint_id_before =
            verifiable_registry.next_checkpoint_id;
    uint64_t registry_current_segment_before =
            verifiable_registry.current_segment_id;
    size_t sharing_count_before =
            verifiable_registry.sharings.size();
    size_t checkpoint_count_before =
            verifiable_registry.checkpoints.size();
    vector<uint64_t> checkpoint_ids_before;
    vector<uint64_t> checkpoint_segment_ids_before;
    vector<vector<uint64_t>> checkpoint_sharing_ids_before;
    vector<bool> checkpoint_sealed_before;
    vector<bool> checkpoint_authentication_requested_before;
    vector<bool> checkpoint_authenticated_before;
    for (const auto& checkpoint : verifiable_registry.checkpoints)
    {
        checkpoint_ids_before.push_back(checkpoint.checkpoint_id);
        checkpoint_segment_ids_before.push_back(checkpoint.segment_id);
        checkpoint_sharing_ids_before.push_back(checkpoint.sharing_ids);
        checkpoint_sealed_before.push_back(checkpoint.sealed);
        checkpoint_authentication_requested_before.push_back(
                checkpoint.authentication_requested);
        checkpoint_authenticated_before.push_back(
                checkpoint.authenticated);
    }

    bool authentication_plan_was_initialized =
            authentication_plan_state.initialized;
    uint64_t next_auth_record_id_before =
            authentication_plan_state.next_auth_record_id;
    size_t auth_record_count_before =
            authentication_plan_state.records.size();
    bool authentication_material_was_initialized =
            authentication_material_state.initialized;
    uint64_t next_material_id_before =
            authentication_material_state.next_material_id;
    size_t auth_material_count_before =
            authentication_material_state.records.size();

    auto assert_inspection_read_only = [&]()
    {
        assert(pending_analyze_sharing_state.initialized
                == pending_state_was_initialized);
        assert(pending_analyze_sharing_state.next_request_id
                == next_pending_request_id_before);
        assert(pending_analyze_sharing_state.requests.size()
                == pending_request_count_before);

        assert(dispute_control_state.initialized
                == dispute_state_was_initialized);
        assert(dispute_control_state.corr == corr_before_inspection);
        assert(dispute_control_state.disp == disp_before_inspection);

        assert(segment_lifecycle.initialized
                == segment_lifecycle_was_initialized);
        assert(segment_lifecycle.current_segment_id
                == lifecycle_current_segment_before);
        assert(segment_lifecycle.last_completed_segment_id
                == lifecycle_last_completed_before);
        assert(segment_lifecycle.segment_open
                == lifecycle_segment_open_before);
        assert(segment_lifecycle.checkpoint_open
                == lifecycle_checkpoint_open_before);
        assert(segment_lifecycle.current_input_checkpoint_id
                == lifecycle_input_checkpoint_before);
        assert(segment_lifecycle.current_output_checkpoint_id
                == lifecycle_output_checkpoint_before);
        assert(segment_lifecycle.current_segment_input_sharings
                == lifecycle_input_sharings_before);
        assert(segment_lifecycle.current_segment_output_sharings
                == lifecycle_output_sharings_before);

        assert(verifiable_registry.initialized
                == verifiable_registry_was_initialized);
        assert(verifiable_registry.next_sharing_id
                == next_sharing_id_before);
        assert(verifiable_registry.next_checkpoint_id
                == next_checkpoint_id_before);
        assert(verifiable_registry.current_segment_id
                == registry_current_segment_before);
        assert(verifiable_registry.sharings.size()
                == sharing_count_before);
        assert(verifiable_registry.checkpoints.size()
                == checkpoint_count_before);
        for (size_t i = 0; i < verifiable_registry.checkpoints.size(); i++)
        {
            const auto& checkpoint =
                    verifiable_registry.checkpoints.at(i);
            assert(checkpoint.checkpoint_id
                    == checkpoint_ids_before.at(i));
            assert(checkpoint.segment_id
                    == checkpoint_segment_ids_before.at(i));
            assert(checkpoint.sharing_ids
                    == checkpoint_sharing_ids_before.at(i));
            assert(checkpoint.sealed == checkpoint_sealed_before.at(i));
            assert(checkpoint.authentication_requested
                    == checkpoint_authentication_requested_before.at(i));
            assert(checkpoint.authenticated
                    == checkpoint_authenticated_before.at(i));
        }

        assert(authentication_plan_state.initialized
                == authentication_plan_was_initialized);
        assert(authentication_plan_state.next_auth_record_id
                == next_auth_record_id_before);
        assert(authentication_plan_state.records.size()
                == auth_record_count_before);
        assert(authentication_material_state.initialized
                == authentication_material_was_initialized);
        assert(authentication_material_state.next_material_id
                == next_material_id_before);
        assert(authentication_material_state.records.size()
                == auth_material_count_before);
    };
#endif

    PendingAnalyzeSharingDispatchPlan plan{};
    plan.valid = true;
    auto finish = [&](PendingAnalyzeSharingInspectionAction action)
            -> PendingAnalyzeSharingDispatchPlan
    {
        plan.action = action;
        validate_pending_analyze_sharing_dispatch_plan(plan);
#ifndef NDEBUG
        assert_inspection_read_only();
#endif
        return plan;
    };

    auto find_checkpoint = [&](uint64_t checkpoint_id)
        -> const CheckpointRecord*
    {
        if (checkpoint_id == 0 || not verifiable_registry.initialized)
            return 0;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == checkpoint_id)
                return &checkpoint;
        return 0;
    };

    auto party_in_range = [&](int party)
    {
        return 0 <= party && party < P.num_players();
    };

    auto holder_list_valid = [&](const vector<int>& holders)
    {
        for (size_t i = 0; i < holders.size(); i++)
        {
            int holder = holders.at(i);
            if (not party_in_range(holder) || not is_active_party(holder))
                return false;
            for (size_t j = i + 1; j < holders.size(); j++)
                if (holder == holders.at(j))
                    return false;
        }
        return true;
    };

    auto append_unique_party = [](vector<int>& parties, int party)
    {
        if (std::find(parties.begin(), parties.end(), party)
                == parties.end())
            parties.push_back(party);
    };

    auto record_ids_are_unique = [](const vector<uint64_t>& ids)
    {
        for (size_t i = 0; i < ids.size(); i++)
        {
            if (ids.at(i) == 0)
                return false;
            for (size_t j = i + 1; j < ids.size(); j++)
                if (ids.at(i) == ids.at(j))
                    return false;
        }
        return true;
    };

    auto plan_record_metadata_valid =
            [&](uint64_t expected_sharing_id,
                    uint64_t expected_checkpoint_id,
                    uint64_t expected_segment_id,
                    AuthenticationRecordKind expected_kind)
    {
        if (not record_ids_are_unique(
                plan.authentication_plan_record_ids))
            return false;

        bool ok = true;
        for (auto record_id : plan.authentication_plan_record_ids)
        {
            const auto* record =
                    find_authentication_plan_record(record_id);
            if (record == 0
                    || not record->valid
                    || record->sharing_id != expected_sharing_id
                    || record->checkpoint_id != expected_checkpoint_id
                    || record->segment_id != expected_segment_id
                    || record->kind != expected_kind
                    || not party_in_range(record->verifier)
                    || not party_in_range(record->holder)
                    || record->verifier == record->holder
                    || record->status == AuthenticationPlanStatus::none)
            {
                ok = false;
                continue;
            }

            append_unique_party(
                    plan.authentication_verifier_ids,
                    record->verifier);
            append_unique_party(
                    plan.authentication_holder_ids,
                    record->holder);
            plan.authentication_plan_statuses.push_back(record->status);
        }
        return ok;
    };

    auto material_metadata_valid =
            [&](uint64_t expected_sharing_id,
                    uint64_t expected_checkpoint_id,
                    uint64_t expected_segment_id,
                    AuthenticationRecordKind expected_kind)
    {
        if (not record_ids_are_unique(
                plan.authentication_material_record_ids))
            return false;

        bool ok = true;
        for (auto material_id : plan.authentication_material_record_ids)
        {
            const auto* material =
                    find_authentication_material_record(material_id);
            if (material == 0
                    || not material->valid
                    || material->sharing_id != expected_sharing_id
                    || material->checkpoint_id != expected_checkpoint_id
                    || material->segment_id != expected_segment_id
                    || material->kind != expected_kind
                    || not party_in_range(material->verifier)
                    || not party_in_range(material->holder)
                    || material->verifier == material->holder
                    || material->status
                        == AuthenticationMaterialStatus::none
                    || std::find(
                        plan.authentication_plan_record_ids.begin(),
                        plan.authentication_plan_record_ids.end(),
                        material->auth_record_id)
                        == plan.authentication_plan_record_ids.end())
            {
                ok = false;
                continue;
            }

            append_unique_party(
                    plan.authentication_verifier_ids,
                    material->verifier);
            append_unique_party(
                    plan.authentication_holder_ids,
                    material->holder);
            plan.authentication_material_statuses.push_back(
                    material->status);
        }
        return ok;
    };

    if (not pending_analyze_sharing_state.initialized
            || index >= pending_analyze_sharing_state.requests.size())
        return finish(
                PendingAnalyzeSharingInspectionAction::
                    no_pending_request);

    const auto& request =
            pending_analyze_sharing_state.requests.at(index);
    plan.request_found = true;
    plan.pending_request_id = request.id;
    plan.source = request.source;
    plan.target = request.target;
    plan.checkpoint_id = request.checkpoint_id;
    plan.segment_id = request.segment_id;
    plan.sharing_id = request.sharing_id;
    plan.registered_snapshot_id = request.registered_snapshot_id;
    plan.ultimate_failure_snapshot_id = request.registered_snapshot_id;
    plan.rejected_holder_ids = request.rejected_holder_ids;
    plan.authentication_plan_record_ids =
            request.authentication_plan_record_ids;
    plan.authentication_material_record_ids =
            request.authentication_material_record_ids;
    plan.is_authentication_rejection_request =
            request.source
            == PendingAnalyzeSharingSource::authentication_rejection;
    plan.is_ultimate_failure_request =
            request.source == PendingAnalyzeSharingSource::ultimate_failure;
    plan.target_is_published_alpha =
            request.target == PendingAnalyzeSharingTarget::published_alpha;
    plan.target_is_published_beta =
            request.target == PendingAnalyzeSharingTarget::published_beta;

    bool structurally_valid =
            request.valid
            && request.id != 0
            && request.source != PendingAnalyzeSharingSource::none
            && request.target != PendingAnalyzeSharingTarget::none
            && (plan.is_authentication_rejection_request
                != plan.is_ultimate_failure_request);

    switch (request.source)
    {
    case PendingAnalyzeSharingSource::authentication_rejection:
    {
        plan.future_requires_analyze_sharing = true;
        plan.future_requires_localization = true;
        plan.future_requires_dispute_control_update = true;
        plan.future_requires_segment_recovery_or_retry = true;
        plan.planned_analyze_checkpoint_output_sharing = true;
        plan.planned_localize_corrupted_party_or_disputed_pair = true;
        plan.planned_feed_dispute_control_update = true;
        plan.planned_feed_segment_recovery = true;
        plan.registered_checkpoint_output_sharing_id =
                request.sharing_id;

        structurally_valid =
                structurally_valid
                && request.target
                    == PendingAnalyzeSharingTarget::
                        registered_checkpoint_output_sharing
                && request.checkpoint_id != 0
                && request.segment_id != 0
                && request.sharing_id != 0
                && request.registered_snapshot_id == 0
                && request.authentication_plan_record_ids.empty()
                && request.authentication_material_record_ids.empty()
                && not request.rejected_holder_ids.empty()
                && holder_list_valid(request.rejected_holder_ids);

        const auto* checkpoint = find_checkpoint(request.checkpoint_id);
        const auto* sharing = find_registered_sharing(request.sharing_id);
        structurally_valid =
                structurally_valid
                && checkpoint != 0
                && sharing != 0
                && checkpoint->segment_id == request.segment_id
                && std::find(
                    checkpoint->sharing_ids.begin(),
                    checkpoint->sharing_ids.end(),
                    request.sharing_id)
                    != checkpoint->sharing_ids.end()
                && sharing->kind == RegisteredSharingKind::checkpoint_output
                && sharing->checkpoint_id == request.checkpoint_id
                && sharing->segment_id == request.segment_id;

        if (sharing != 0)
        {
            plan.authentication_plan_record_ids =
                    authentication_records_for_sharing(
                            request.sharing_id);
            plan.authentication_material_record_ids =
                    authentication_material_for_sharing(
                            request.sharing_id);
            structurally_valid =
                    structurally_valid
                    && plan_record_metadata_valid(
                        request.sharing_id,
                        request.checkpoint_id,
                        request.segment_id,
                        AuthenticationRecordKind::
                            checkpoint_output_share)
                    && material_metadata_valid(
                        request.sharing_id,
                        request.checkpoint_id,
                        request.segment_id,
                        AuthenticationRecordKind::
                            checkpoint_output_share);

            auto sharing_decision =
                    authentication_sharing_decision(request.sharing_id);
            plan.authentication_sharing_status =
                    sharing_decision.status;
            plan.expected_holders = sharing_decision.expected_holders;
            plan.total_holder_decisions =
                    sharing_decision.total_holder_decisions;
            plan.rejected_holders = sharing_decision.rejected_holders;
            structurally_valid =
                    structurally_valid
                    && sharing_decision.valid
                    && sharing_decision.status
                        == AuthenticationSharingDecisionStatus::rejected
                    && sharing_decision.rejected_holder_ids
                        == request.rejected_holder_ids;
        }

        if (checkpoint != 0)
        {
            auto checkpoint_decision =
                    authentication_checkpoint_decision(
                            request.checkpoint_id);
            plan.authentication_checkpoint_status =
                    checkpoint_decision.status;
            plan.expected_sharings =
                    checkpoint_decision.expected_sharings;
            plan.rejected_sharings =
                    checkpoint_decision.rejected_sharings;
            plan.not_ready_sharings =
                    checkpoint_decision.not_ready_sharings;
            plan.unavailable_sharings =
                    checkpoint_decision.unavailable_sharings;
            plan.insufficient_sharings =
                    checkpoint_decision.insufficient_sharings;
            plan.checkpoint_sharing_ids =
                    checkpoint_decision.sharing_ids;
            plan.rejected_sharing_ids =
                    checkpoint_decision.rejected_sharing_ids;

            auto outcome =
                    authentication_decision_outcome_from_checkpoint_decision(
                            checkpoint_decision);
            plan.authentication_outcome_action = outcome.action;

            auto analyze_plan =
                    authentication_analyze_plan_for_checkpoint(
                            request.checkpoint_id);
            plan.authentication_analyze_plan_action =
                    analyze_plan.action;

            structurally_valid =
                    structurally_valid
                    && checkpoint_decision.valid
                    && checkpoint_decision.status
                        == AuthenticationCheckpointDecisionStatus::
                            rejected
                    && std::find(
                        checkpoint_decision.rejected_sharing_ids.begin(),
                        checkpoint_decision.rejected_sharing_ids.end(),
                        request.sharing_id)
                        != checkpoint_decision
                            .rejected_sharing_ids.end()
                    && outcome.valid
                    && outcome.action
                        == AuthenticationDecisionOutcomeAction::
                            reject_checkpoint
                    && analyze_plan.valid
                    && analyze_plan.action
                        == AuthenticationAnalyzePlanAction::
                            would_analyze_rejected_sharings;
        }

        plan.request_structurally_valid = structurally_valid;
        if (not structurally_valid)
            return finish(
                    PendingAnalyzeSharingInspectionAction::
                        inconsistent_state);

        return finish(
                PendingAnalyzeSharingInspectionAction::
                    planned_authentication_rejection);
    }

    case PendingAnalyzeSharingSource::ultimate_failure:
    {
        plan.future_requires_analyze_sharing = true;
        plan.future_requires_localization = true;
        plan.future_requires_dispute_control_update = true;
        plan.planned_analyze_published_snapshot = true;
        plan.planned_localize_corrupted_party_or_disputed_pair = true;
        plan.planned_feed_dispute_control_update = true;

        if (request.target == PendingAnalyzeSharingTarget::published_alpha)
        {
            plan.sharing_to_analyze = SharingToAnalyze::alpha;
            plan.fault_source = FaultLocalizationSource::inconsistent_alpha;
        }
        else if (request.target
                == PendingAnalyzeSharingTarget::published_beta)
        {
            plan.sharing_to_analyze = SharingToAnalyze::beta;
            plan.fault_source = FaultLocalizationSource::inconsistent_beta;
        }

        structurally_valid =
                structurally_valid
                && (request.target
                    == PendingAnalyzeSharingTarget::published_alpha
                    || request.target
                        == PendingAnalyzeSharingTarget::published_beta)
                && request.checkpoint_id == 0
                && request.segment_id == 0
                && request.sharing_id == 0
                && request.registered_snapshot_id != 0
                && request.rejected_holder_ids.empty()
                && not request.authentication_plan_record_ids.empty()
                && request.authentication_material_record_ids.size()
                    == request.authentication_plan_record_ids.size();

        const auto* snapshot = find_registered_sharing(
                request.registered_snapshot_id);
        structurally_valid =
                structurally_valid
                && snapshot != 0
                && snapshot->kind
                    == RegisteredSharingKind::analyze_request_snapshot
                && snapshot->degree == RegisteredSharingDegree::degree_t
                && snapshot->has_published_snapshot;

        uint64_t snapshot_segment_id =
                snapshot == 0 ? 0 : snapshot->segment_id;
        structurally_valid =
                structurally_valid
                && plan_record_metadata_valid(
                    request.registered_snapshot_id,
                    0,
                    snapshot_segment_id,
                    AuthenticationRecordKind::analyze_request_snapshot)
                && material_metadata_valid(
                    request.registered_snapshot_id,
                    0,
                    snapshot_segment_id,
                    AuthenticationRecordKind::analyze_request_snapshot);

        if (snapshot != 0)
        {
            auto sharing_decision =
                    authentication_sharing_decision(
                            request.registered_snapshot_id);
            plan.authentication_sharing_status =
                    sharing_decision.status;
            plan.expected_holders = sharing_decision.expected_holders;
            plan.total_holder_decisions =
                    sharing_decision.total_holder_decisions;
            plan.rejected_holders = sharing_decision.rejected_holders;
            structurally_valid =
                    structurally_valid
                    && sharing_decision.valid;
        }

        plan.has_current_ultimate_failure_context =
                have_ultimate_failure_context;
        if (have_ultimate_failure_context)
        {
            const auto& context = ultimate_failure_context;
            plan.ultimate_failure_kind = context.failure_kind;
            plan.ultimate_failure_action = context.decision.action;
            plan.ultimate_failure_context_matches_request =
                    context.valid
                    && context.has_analyze_sharing_request
                    && context.analyze_sharing_request
                        .registered_snapshot_id
                        == request.registered_snapshot_id
                    && context.has_analyze_enqueue_result
                    && context.analyze_enqueue_result.pending_request_id
                        == request.id
                    && context.analyze_enqueue_result.target
                        == request.target;

            if (plan.ultimate_failure_context_matches_request
                    && context.fault_localization.valid)
            {
                plan.fault_source = context.fault_localization.source;
                plan.sharing_to_analyze =
                        context.fault_localization.sharing_to_analyze;
            }
        }

        plan.request_structurally_valid = structurally_valid;
        if (not structurally_valid)
            return finish(
                    PendingAnalyzeSharingInspectionAction::
                        inconsistent_state);

        return finish(
                PendingAnalyzeSharingInspectionAction::
                    planned_ultimate_failure);
    }

    case PendingAnalyzeSharingSource::none:
        plan.request_structurally_valid = false;
        return finish(
                PendingAnalyzeSharingInspectionAction::
                    inconsistent_state);
    }

    plan.request_structurally_valid = false;
    return finish(
            PendingAnalyzeSharingInspectionAction::inconsistent_state);
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingDispatchPlan
AtlasGsz<T>::inspect_pending_analyze_sharing_request(uint64_t id) const
{
    if (pending_analyze_sharing_state.initialized)
        for (size_t i = 0;
                i < pending_analyze_sharing_state.requests.size(); i++)
            if (pending_analyze_sharing_state.requests.at(i).id == id)
                return inspect_pending_analyze_sharing_request_by_index(i);

    return inspect_pending_analyze_sharing_request_by_index(
            pending_analyze_sharing_state.requests.size());
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingDispatchPlan
AtlasGsz<T>::inspect_next_pending_analyze_sharing_request() const
{
    return inspect_pending_analyze_sharing_request_by_index(0);
}

template<class T>
void AtlasGsz<T>::validate_pending_analyze_sharing_dispatch_plan(
        const PendingAnalyzeSharingDispatchPlan& plan) const
{
    assert(plan.valid);
    assert(plan.action != PendingAnalyzeSharingInspectionAction::none);
    assert(not plan.state_updated);
    assert(not plan.performed_action);

    auto party_in_range = [&](int party)
    {
        return 0 <= party && party < P.num_players();
    };

    for (size_t i = 0; i < plan.rejected_holder_ids.size(); i++)
    {
        int holder = plan.rejected_holder_ids.at(i);
        assert(party_in_range(holder));
        assert(is_active_party(holder));
        for (size_t j = i + 1;
                j < plan.rejected_holder_ids.size(); j++)
            assert(holder != plan.rejected_holder_ids.at(j));
    }

    for (size_t i = 0; i < plan.authentication_verifier_ids.size(); i++)
    {
        int verifier = plan.authentication_verifier_ids.at(i);
        assert(party_in_range(verifier));
        for (size_t j = i + 1;
                j < plan.authentication_verifier_ids.size(); j++)
            assert(verifier != plan.authentication_verifier_ids.at(j));
    }

    for (size_t i = 0; i < plan.authentication_holder_ids.size(); i++)
    {
        int holder = plan.authentication_holder_ids.at(i);
        assert(party_in_range(holder));
        for (size_t j = i + 1;
                j < plan.authentication_holder_ids.size(); j++)
            assert(holder != plan.authentication_holder_ids.at(j));
    }

    assert(plan.authentication_plan_statuses.size()
            <= plan.authentication_plan_record_ids.size());
    assert(plan.authentication_material_statuses.size()
            <= plan.authentication_material_record_ids.size());

    if (not plan.request_found)
    {
        assert(plan.action
                == PendingAnalyzeSharingInspectionAction::
                    no_pending_request);
        assert(not plan.request_structurally_valid);
        assert(plan.pending_request_id == 0);
        assert(plan.source == PendingAnalyzeSharingSource::none);
        assert(plan.target == PendingAnalyzeSharingTarget::none);
        assert(not plan.is_authentication_rejection_request);
        assert(not plan.is_ultimate_failure_request);
        assert(not plan.future_requires_analyze_sharing);
        assert(not plan.future_requires_localization);
        assert(not plan.future_requires_dispute_control_update);
        assert(not plan.future_requires_segment_recovery_or_retry);
        return;
    }

    assert(plan.pending_request_id != 0);
    assert(plan.source != PendingAnalyzeSharingSource::none);
    assert(plan.target != PendingAnalyzeSharingTarget::none);
    assert(plan.is_authentication_rejection_request
            != plan.is_ultimate_failure_request);

    if (const auto* request =
            find_pending_analyze_sharing_request(plan.pending_request_id))
    {
        assert(request->id == plan.pending_request_id);
        assert(request->source == plan.source);
        assert(request->target == plan.target);
    }

    if (plan.action
            == PendingAnalyzeSharingInspectionAction::
                inconsistent_state)
    {
        assert(not plan.request_structurally_valid);
        return;
    }

    assert(plan.request_structurally_valid);
    assert(plan.future_requires_analyze_sharing);
    assert(plan.future_requires_localization);
    assert(plan.future_requires_dispute_control_update);
    assert(plan.planned_localize_corrupted_party_or_disputed_pair);
    assert(plan.planned_feed_dispute_control_update);

    switch (plan.action)
    {
    case PendingAnalyzeSharingInspectionAction::
            planned_authentication_rejection:
        assert(plan.is_authentication_rejection_request);
        assert(not plan.is_ultimate_failure_request);
        assert(plan.source
                == PendingAnalyzeSharingSource::
                    authentication_rejection);
        assert(plan.target
                == PendingAnalyzeSharingTarget::
                    registered_checkpoint_output_sharing);
        assert(plan.checkpoint_id != 0);
        assert(plan.segment_id != 0);
        assert(plan.sharing_id != 0);
        assert(plan.registered_checkpoint_output_sharing_id
                == plan.sharing_id);
        assert(plan.registered_snapshot_id == 0);
        assert(plan.ultimate_failure_snapshot_id == 0);
        assert(not plan.rejected_holder_ids.empty());
        assert(plan.planned_analyze_checkpoint_output_sharing);
        assert(not plan.planned_analyze_published_snapshot);
        assert(plan.future_requires_segment_recovery_or_retry);
        assert(plan.planned_feed_segment_recovery);
        assert(plan.authentication_sharing_status
                == AuthenticationSharingDecisionStatus::rejected);
        assert(plan.authentication_checkpoint_status
                == AuthenticationCheckpointDecisionStatus::rejected);
        assert(plan.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    reject_checkpoint);
        assert(plan.authentication_analyze_plan_action
                == AuthenticationAnalyzePlanAction::
                    would_analyze_rejected_sharings);
        assert(std::find(
                plan.rejected_sharing_ids.begin(),
                plan.rejected_sharing_ids.end(),
                plan.sharing_id) != plan.rejected_sharing_ids.end());
        break;

    case PendingAnalyzeSharingInspectionAction::planned_ultimate_failure:
        assert(plan.is_ultimate_failure_request);
        assert(not plan.is_authentication_rejection_request);
        assert(plan.source == PendingAnalyzeSharingSource::ultimate_failure);
        assert(plan.target
                == PendingAnalyzeSharingTarget::published_alpha
                || plan.target
                    == PendingAnalyzeSharingTarget::published_beta);
        assert(plan.target_is_published_alpha
                != plan.target_is_published_beta);
        assert(plan.target_is_published_alpha
                == (plan.target
                    == PendingAnalyzeSharingTarget::published_alpha));
        assert(plan.target_is_published_beta
                == (plan.target
                    == PendingAnalyzeSharingTarget::published_beta));
        assert(plan.checkpoint_id == 0);
        assert(plan.segment_id == 0);
        assert(plan.sharing_id == 0);
        assert(plan.registered_checkpoint_output_sharing_id == 0);
        assert(plan.registered_snapshot_id != 0);
        assert(plan.ultimate_failure_snapshot_id
                == plan.registered_snapshot_id);
        assert(not plan.authentication_plan_record_ids.empty());
        assert(plan.authentication_material_record_ids.size()
                == plan.authentication_plan_record_ids.size());
        assert(plan.planned_analyze_published_snapshot);
        assert(not plan.planned_analyze_checkpoint_output_sharing);
        assert(not plan.future_requires_segment_recovery_or_retry);
        assert(not plan.planned_feed_segment_recovery);
        assert(plan.authentication_sharing_status
                != AuthenticationSharingDecisionStatus::none);
        assert(plan.authentication_checkpoint_status
                == AuthenticationCheckpointDecisionStatus::none);
        assert(plan.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::none);
        assert(plan.authentication_analyze_plan_action
                == AuthenticationAnalyzePlanAction::none);
        if (plan.target_is_published_alpha)
            assert(plan.sharing_to_analyze == SharingToAnalyze::alpha);
        if (plan.target_is_published_beta)
            assert(plan.sharing_to_analyze == SharingToAnalyze::beta);
        break;

    case PendingAnalyzeSharingInspectionAction::no_pending_request:
    case PendingAnalyzeSharingInspectionAction::inconsistent_state:
    case PendingAnalyzeSharingInspectionAction::none:
        assert(false);
        break;
    }
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingExecutionReadinessPlan
AtlasGsz<T>::inspect_pending_analyze_sharing_execution_plan_for_request(
        uint64_t pending_request_id) const
{
#ifndef NDEBUG
    size_t pending_request_count_before =
            pending_analyze_sharing_state.requests.size();
#endif

    PendingAnalyzeSharingExecutionReadinessPlan plan{};
    plan.valid = true;

    auto finish =
            [&](PendingAnalyzeSharingExecutionReadinessAction action)
                -> PendingAnalyzeSharingExecutionReadinessPlan
    {
        plan.action = action;
        validate_pending_analyze_sharing_execution_plan(plan);
#ifndef NDEBUG
        assert(pending_analyze_sharing_state.requests.size()
                == pending_request_count_before);
#endif
        return plan;
    };

    auto request_plan = inspect_pending_analyze_sharing_request(
            pending_request_id);
    validate_pending_analyze_sharing_dispatch_plan(request_plan);

    plan.request_found = request_plan.request_found;
    plan.request_structurally_valid =
            request_plan.request_structurally_valid;
    plan.pending_request_id = request_plan.pending_request_id;
    plan.source = request_plan.source;
    plan.target = request_plan.target;
    plan.is_authentication_rejection_request =
            request_plan.is_authentication_rejection_request;
    plan.is_ultimate_failure_request =
            request_plan.is_ultimate_failure_request;
    plan.future_requires_analyze_sharing =
            request_plan.future_requires_analyze_sharing;
    plan.future_requires_localization =
            request_plan.future_requires_localization;
    plan.future_requires_dispute_control_update =
            request_plan.future_requires_dispute_control_update;
    plan.future_requires_segment_recovery_or_retry =
            request_plan.future_requires_segment_recovery_or_retry;
    plan.planned_analyze_checkpoint_output_sharing =
            request_plan.planned_analyze_checkpoint_output_sharing;
    plan.planned_analyze_published_snapshot =
            request_plan.planned_analyze_published_snapshot;
    plan.planned_localize_corrupted_party_or_disputed_pair =
            request_plan.planned_localize_corrupted_party_or_disputed_pair;
    plan.planned_feed_dispute_control_update =
            request_plan.planned_feed_dispute_control_update;
    plan.planned_feed_segment_recovery =
            request_plan.planned_feed_segment_recovery;
    plan.would_analyze_checkpoint_output_sharing =
            request_plan.planned_analyze_checkpoint_output_sharing;
    plan.would_analyze_published_snapshot =
            request_plan.planned_analyze_published_snapshot;
    plan.would_feed_localization =
            request_plan.planned_localize_corrupted_party_or_disputed_pair;
    plan.would_feed_dispute_control_update =
            request_plan.planned_feed_dispute_control_update;
    plan.would_feed_segment_recovery_or_retry =
            request_plan.planned_feed_segment_recovery;
    plan.target_is_published_alpha =
            request_plan.target_is_published_alpha;
    plan.target_is_published_beta =
            request_plan.target_is_published_beta;
    plan.checkpoint_id = request_plan.checkpoint_id;
    plan.segment_id = request_plan.segment_id;
    plan.sharing_id = request_plan.sharing_id;
    plan.registered_checkpoint_output_sharing_id =
            request_plan.registered_checkpoint_output_sharing_id;
    plan.rejected_holder_ids = request_plan.rejected_holder_ids;
    plan.registered_snapshot_id = request_plan.registered_snapshot_id;
    plan.ultimate_failure_snapshot_id =
            request_plan.ultimate_failure_snapshot_id;
    plan.authentication_plan_record_ids =
            request_plan.authentication_plan_record_ids;
    plan.authentication_material_record_ids =
            request_plan.authentication_material_record_ids;
    plan.authentication_verifier_ids =
            request_plan.authentication_verifier_ids;
    plan.authentication_holder_ids =
            request_plan.authentication_holder_ids;

    if (not request_plan.request_found)
        return finish(
                PendingAnalyzeSharingExecutionReadinessAction::
                    no_pending_request);

    if (not request_plan.request_structurally_valid)
        return finish(
                PendingAnalyzeSharingExecutionReadinessAction::
                    inconsistent_state);

    switch (request_plan.action)
    {
    case PendingAnalyzeSharingInspectionAction::
            planned_authentication_rejection:
    {
        const CheckpointRecord* checkpoint = 0;
        if (verifiable_registry.initialized)
            for (const auto& candidate : verifiable_registry.checkpoints)
                if (candidate.checkpoint_id == plan.checkpoint_id)
                {
                    checkpoint = &candidate;
                    break;
                }

        const auto* sharing = find_registered_sharing(plan.sharing_id);
        plan.checkpoint_record_exists =
                checkpoint != 0 && checkpoint->valid;
        plan.registered_checkpoint_output_sharing_exists =
                sharing != 0
                && sharing->valid
                && sharing->kind == RegisteredSharingKind::checkpoint_output
                && sharing->degree == RegisteredSharingDegree::degree_t;
        plan.checkpoint_output_sharing_belongs_to_checkpoint =
                checkpoint != 0
                && sharing != 0
                && checkpoint->segment_id == plan.segment_id
                && sharing->checkpoint_id == plan.checkpoint_id
                && sharing->segment_id == plan.segment_id
                && std::find(
                    checkpoint->sharing_ids.begin(),
                    checkpoint->sharing_ids.end(),
                    plan.sharing_id) != checkpoint->sharing_ids.end();
        plan.authentication_decision_metadata_available =
                request_plan.authentication_sharing_status
                    == AuthenticationSharingDecisionStatus::rejected
                && request_plan.authentication_checkpoint_status
                    == AuthenticationCheckpointDecisionStatus::rejected
                && request_plan.authentication_outcome_action
                    == AuthenticationDecisionOutcomeAction::reject_checkpoint
                && request_plan.authentication_analyze_plan_action
                    == AuthenticationAnalyzePlanAction::
                        would_analyze_rejected_sharings;
        plan.authentication_plan_metadata_available =
                not plan.authentication_plan_record_ids.empty();
        plan.authentication_material_metadata_available =
                not plan.authentication_material_record_ids.empty()
                && plan.authentication_material_record_ids.size()
                    == plan.authentication_plan_record_ids.size();
        plan.authentication_metadata_internally_consistent =
                plan.authentication_decision_metadata_available
                && plan.authentication_plan_metadata_available
                && plan.authentication_material_metadata_available;
        plan.metadata_complete =
                plan.request_structurally_valid
                && plan.checkpoint_record_exists
                && plan.registered_checkpoint_output_sharing_exists
                && plan.checkpoint_output_sharing_belongs_to_checkpoint
                && plan.authentication_metadata_internally_consistent;
        plan.execution_inputs_metadata_complete = plan.metadata_complete;

        if (not plan.execution_inputs_metadata_complete)
            return finish(
                    PendingAnalyzeSharingExecutionReadinessAction::
                        inconsistent_state);

        return finish(
                PendingAnalyzeSharingExecutionReadinessAction::
                    ready_authentication_rejection);
    }

    case PendingAnalyzeSharingInspectionAction::planned_ultimate_failure:
    {
        const auto* snapshot = find_registered_sharing(
                plan.registered_snapshot_id);
        plan.registered_published_snapshot_exists =
                snapshot != 0
                && snapshot->valid
                && snapshot->kind
                    == RegisteredSharingKind::analyze_request_snapshot
                && snapshot->degree == RegisteredSharingDegree::degree_t
                && snapshot->has_published_snapshot;
        plan.authentication_plan_metadata_available =
                not plan.authentication_plan_record_ids.empty();
        plan.authentication_material_metadata_available =
                not plan.authentication_material_record_ids.empty()
                && plan.authentication_material_record_ids.size()
                    == plan.authentication_plan_record_ids.size();
        plan.authentication_metadata_internally_consistent =
                plan.authentication_plan_metadata_available
                && plan.authentication_material_metadata_available;
        plan.metadata_complete =
                plan.request_structurally_valid
                && plan.registered_published_snapshot_exists
                && plan.authentication_metadata_internally_consistent;
        plan.execution_inputs_metadata_complete = plan.metadata_complete;

        if (not plan.execution_inputs_metadata_complete)
            return finish(
                    PendingAnalyzeSharingExecutionReadinessAction::
                        inconsistent_state);

        return finish(
                PendingAnalyzeSharingExecutionReadinessAction::
                    ready_ultimate_failure);
    }

    case PendingAnalyzeSharingInspectionAction::no_pending_request:
    case PendingAnalyzeSharingInspectionAction::inconsistent_state:
    case PendingAnalyzeSharingInspectionAction::none:
        break;
    }

    return finish(
            PendingAnalyzeSharingExecutionReadinessAction::
                inconsistent_state);
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingExecutionReadinessPlan
AtlasGsz<T>::inspect_next_pending_analyze_sharing_execution_plan() const
{
    uint64_t request_id = 0;
    if (pending_analyze_sharing_state.initialized
            && not pending_analyze_sharing_state.requests.empty())
        request_id = pending_analyze_sharing_state.requests.front().id;

    return inspect_pending_analyze_sharing_execution_plan_for_request(
            request_id);
}

template<class T>
void AtlasGsz<T>::validate_pending_analyze_sharing_execution_plan(
        const PendingAnalyzeSharingExecutionReadinessPlan& plan) const
{
    assert(plan.valid);
    assert(plan.action
            != PendingAnalyzeSharingExecutionReadinessAction::none);
    assert(not plan.state_updated);
    assert(not plan.performed_action);

    if (not plan.request_found)
    {
        assert(plan.action
                == PendingAnalyzeSharingExecutionReadinessAction::
                    no_pending_request);
        assert(not plan.request_structurally_valid);
        assert(plan.pending_request_id == 0);
        assert(plan.source == PendingAnalyzeSharingSource::none);
        assert(plan.target == PendingAnalyzeSharingTarget::none);
        assert(not plan.metadata_complete);
        assert(not plan.execution_inputs_metadata_complete);
        return;
    }

    assert(plan.pending_request_id != 0);
    assert(find_pending_analyze_sharing_request(plan.pending_request_id)
            != 0);
    assert(plan.source != PendingAnalyzeSharingSource::none);
    assert(plan.target != PendingAnalyzeSharingTarget::none);
    assert(plan.is_authentication_rejection_request
            != plan.is_ultimate_failure_request);

    if (plan.action
            == PendingAnalyzeSharingExecutionReadinessAction::
                inconsistent_state)
    {
        assert(not plan.execution_inputs_metadata_complete);
        return;
    }

    assert(plan.request_structurally_valid);
    assert(plan.metadata_complete);
    assert(plan.execution_inputs_metadata_complete);
    assert(plan.future_requires_analyze_sharing);
    assert(plan.future_requires_localization);
    assert(plan.future_requires_dispute_control_update);
    assert(plan.planned_localize_corrupted_party_or_disputed_pair);
    assert(plan.planned_feed_dispute_control_update);
    assert(plan.would_feed_localization);
    assert(plan.would_feed_dispute_control_update);

    switch (plan.action)
    {
    case PendingAnalyzeSharingExecutionReadinessAction::
            ready_authentication_rejection:
        assert(plan.is_authentication_rejection_request);
        assert(plan.target
                == PendingAnalyzeSharingTarget::
                    registered_checkpoint_output_sharing);
        assert(plan.checkpoint_record_exists);
        assert(plan.registered_checkpoint_output_sharing_exists);
        assert(plan.checkpoint_output_sharing_belongs_to_checkpoint);
        assert(plan.authentication_decision_metadata_available);
        assert(plan.authentication_metadata_internally_consistent);
        assert(plan.planned_analyze_checkpoint_output_sharing);
        assert(plan.would_analyze_checkpoint_output_sharing);
        assert(plan.future_requires_segment_recovery_or_retry);
        assert(plan.would_feed_segment_recovery_or_retry);
        break;

    case PendingAnalyzeSharingExecutionReadinessAction::
            ready_ultimate_failure:
        assert(plan.is_ultimate_failure_request);
        assert(plan.target
                == PendingAnalyzeSharingTarget::published_alpha
                || plan.target
                    == PendingAnalyzeSharingTarget::published_beta);
        assert(plan.registered_published_snapshot_exists);
        assert(plan.authentication_metadata_internally_consistent);
        assert(plan.planned_analyze_published_snapshot);
        assert(plan.would_analyze_published_snapshot);
        assert(not plan.future_requires_segment_recovery_or_retry);
        assert(not plan.would_feed_segment_recovery_or_retry);
        break;

    case PendingAnalyzeSharingExecutionReadinessAction::
            no_pending_request:
    case PendingAnalyzeSharingExecutionReadinessAction::
            inconsistent_state:
    case PendingAnalyzeSharingExecutionReadinessAction::none:
        assert(false);
        break;
    }
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingExecutionAttemptRunPlan
AtlasGsz<T>::inspect_pending_analyze_sharing_execution_attempt_run_plan(
        uint64_t pending_request_id) const
{
#ifndef NDEBUG
    size_t pending_request_count_before =
            pending_analyze_sharing_state.requests.size();
#endif

    PendingAnalyzeSharingExecutionAttemptRunPlan plan{};
    plan.valid = true;

    auto finish =
            [&](PendingAnalyzeSharingExecutionAttemptRunAction action)
                -> PendingAnalyzeSharingExecutionAttemptRunPlan
    {
        plan.action = action;
        validate_pending_analyze_sharing_execution_attempt_run_plan(plan);
#ifndef NDEBUG
        assert(pending_analyze_sharing_state.requests.size()
                == pending_request_count_before);
#endif
        return plan;
    };

    auto readiness =
            inspect_pending_analyze_sharing_execution_plan_for_request(
                    pending_request_id);
    validate_pending_analyze_sharing_execution_plan(readiness);

    plan.request_found = readiness.request_found;
    plan.request_structurally_valid =
            readiness.request_structurally_valid;
    plan.metadata_complete = readiness.metadata_complete;
    plan.execution_inputs_metadata_complete =
            readiness.execution_inputs_metadata_complete;
    plan.pending_request_id = readiness.pending_request_id;
    plan.source = readiness.source;
    plan.target = readiness.target;
    plan.is_authentication_rejection_request =
            readiness.is_authentication_rejection_request;
    plan.is_ultimate_failure_request =
            readiness.is_ultimate_failure_request;
    plan.checkpoint_id = readiness.checkpoint_id;
    plan.segment_id = readiness.segment_id;
    plan.sharing_id = readiness.sharing_id;
    plan.registered_checkpoint_output_sharing_id =
            readiness.registered_checkpoint_output_sharing_id;
    plan.registered_snapshot_id = readiness.registered_snapshot_id;
    plan.ultimate_failure_snapshot_id =
            readiness.ultimate_failure_snapshot_id;
    plan.rejected_holder_ids = readiness.rejected_holder_ids;
    plan.authentication_plan_record_ids =
            readiness.authentication_plan_record_ids;
    plan.authentication_material_record_ids =
            readiness.authentication_material_record_ids;
    plan.authentication_verifier_ids =
            readiness.authentication_verifier_ids;
    plan.authentication_holder_ids =
            readiness.authentication_holder_ids;
    plan.future_requires_analyze_sharing =
            readiness.future_requires_analyze_sharing;
    plan.future_requires_localization =
            readiness.future_requires_localization;
    plan.future_requires_dispute_control_update =
            readiness.future_requires_dispute_control_update;
    plan.future_requires_segment_recovery_or_retry =
            readiness.future_requires_segment_recovery_or_retry;
    plan.planned_analyze_checkpoint_output_sharing =
            readiness.planned_analyze_checkpoint_output_sharing;
    plan.planned_analyze_published_snapshot =
            readiness.planned_analyze_published_snapshot;
    plan.planned_localize_corrupted_party_or_disputed_pair =
            readiness.planned_localize_corrupted_party_or_disputed_pair;
    plan.planned_feed_dispute_control_update =
            readiness.planned_feed_dispute_control_update;
    plan.planned_feed_segment_recovery =
            readiness.planned_feed_segment_recovery;
    plan.would_analyze_checkpoint_output_sharing =
            readiness.would_analyze_checkpoint_output_sharing;
    plan.would_analyze_published_snapshot =
            readiness.would_analyze_published_snapshot;
    plan.would_feed_localization =
            readiness.would_feed_localization;
    plan.would_feed_dispute_control_update =
            readiness.would_feed_dispute_control_update;
    plan.would_feed_segment_recovery_or_retry =
            readiness.would_feed_segment_recovery_or_retry;

    switch (readiness.action)
    {
    case PendingAnalyzeSharingExecutionReadinessAction::
            no_pending_request:
        return finish(
                PendingAnalyzeSharingExecutionAttemptRunAction::
                    no_pending_request);

    case PendingAnalyzeSharingExecutionReadinessAction::
            inconsistent_state:
        return finish(
                PendingAnalyzeSharingExecutionAttemptRunAction::
                    inconsistent_state);

    case PendingAnalyzeSharingExecutionReadinessAction::
            ready_authentication_rejection:
        if (not readiness.metadata_complete
                || not readiness.execution_inputs_metadata_complete)
            return finish(
                    PendingAnalyzeSharingExecutionAttemptRunAction::
                        inconsistent_state);

        plan.would_execute_analyze_sharing = true;
        plan.would_use_checkpoint_output_sharing = true;
        plan.would_feed_run_localization = true;
        plan.would_feed_run_dispute_control_update = true;
        plan.would_feed_run_segment_recovery_or_retry = true;
        return finish(
                PendingAnalyzeSharingExecutionAttemptRunAction::
                    ready_authentication_rejection);

    case PendingAnalyzeSharingExecutionReadinessAction::
            ready_ultimate_failure:
        if (not readiness.metadata_complete
                || not readiness.execution_inputs_metadata_complete)
            return finish(
                    PendingAnalyzeSharingExecutionAttemptRunAction::
                        inconsistent_state);

        plan.would_execute_analyze_sharing = true;
        plan.would_use_published_snapshot = true;
        plan.would_feed_run_localization = true;
        plan.would_feed_run_dispute_control_update = true;
        return finish(
                PendingAnalyzeSharingExecutionAttemptRunAction::
                    ready_ultimate_failure);

    case PendingAnalyzeSharingExecutionReadinessAction::none:
        break;
    }

    return finish(
            PendingAnalyzeSharingExecutionAttemptRunAction::
                inconsistent_state);
}

template<class T>
typename AtlasGsz<T>::PendingAnalyzeSharingExecutionAttemptRunPlan
AtlasGsz<T>::
inspect_next_pending_analyze_sharing_execution_attempt_run_plan() const
{
    uint64_t request_id = 0;
    if (pending_analyze_sharing_state.initialized
            && not pending_analyze_sharing_state.requests.empty())
        request_id = pending_analyze_sharing_state.requests.front().id;

    return inspect_pending_analyze_sharing_execution_attempt_run_plan(
            request_id);
}

template<class T>
void AtlasGsz<T>::
validate_pending_analyze_sharing_execution_attempt_run_plan(
        const PendingAnalyzeSharingExecutionAttemptRunPlan& plan) const
{
    assert(plan.valid);
    assert(plan.action
            != PendingAnalyzeSharingExecutionAttemptRunAction::none);
    assert(not plan.state_updated);
    assert(not plan.performed_action);

    if (not plan.request_found)
    {
        assert(plan.action
                == PendingAnalyzeSharingExecutionAttemptRunAction::
                    no_pending_request);
        assert(not plan.request_structurally_valid);
        assert(plan.pending_request_id == 0);
        assert(not plan.would_execute_analyze_sharing);
        return;
    }

    assert(plan.pending_request_id != 0);
    assert(find_pending_analyze_sharing_request(plan.pending_request_id)
            != 0);
    assert(plan.source != PendingAnalyzeSharingSource::none);
    assert(plan.target != PendingAnalyzeSharingTarget::none);

    if (plan.action
            == PendingAnalyzeSharingExecutionAttemptRunAction::
                inconsistent_state)
    {
        assert(not plan.execution_inputs_metadata_complete);
        assert(not plan.would_execute_analyze_sharing);
        return;
    }

    assert(plan.request_structurally_valid);
    assert(plan.metadata_complete);
    assert(plan.execution_inputs_metadata_complete);
    assert(plan.would_execute_analyze_sharing);
    assert(plan.would_feed_run_localization);
    assert(plan.would_feed_run_dispute_control_update);

    switch (plan.action)
    {
    case PendingAnalyzeSharingExecutionAttemptRunAction::
            ready_authentication_rejection:
        assert(plan.is_authentication_rejection_request);
        assert(plan.would_use_checkpoint_output_sharing);
        assert(not plan.would_use_published_snapshot);
        assert(plan.would_feed_run_segment_recovery_or_retry);
        break;

    case PendingAnalyzeSharingExecutionAttemptRunAction::
            ready_ultimate_failure:
        assert(plan.is_ultimate_failure_request);
        assert(not plan.would_use_checkpoint_output_sharing);
        assert(plan.would_use_published_snapshot);
        assert(not plan.would_feed_run_segment_recovery_or_retry);
        break;

    case PendingAnalyzeSharingExecutionAttemptRunAction::
            no_pending_request:
    case PendingAnalyzeSharingExecutionAttemptRunAction::
            inconsistent_state:
    case PendingAnalyzeSharingExecutionAttemptRunAction::none:
        assert(false);
        break;
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
            for (auto sharing_id : checkpoint.sharing_ids)
            {
                auto* sharing = find_registered_sharing(sharing_id);
                assert(sharing != 0);
                if (sharing->kind == RegisteredSharingKind::checkpoint_output
                        && sharing->status
                            == VerifiableSharingStatus::registered)
                    sharing->status =
                            VerifiableSharingStatus::
                                authentication_pending;
            }
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
            for (auto sharing_id : checkpoint.sharing_ids)
            {
                auto* sharing = find_registered_sharing(sharing_id);
                assert(sharing != 0);
                assert(sharing->status != VerifiableSharingStatus::none);
                sharing->status = VerifiableSharingStatus::authenticated;
            }
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
        {
            const auto* sharing = find_registered_sharing(sharing_id);
            assert(sharing != 0);
            assert(sharing->checkpoint_id == checkpoint.checkpoint_id);
            assert(sharing->segment_id == checkpoint.segment_id);
            if (checkpoint.authenticated)
                assert(sharing->status
                        == VerifiableSharingStatus::authenticated);
        }
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

    if (segment_lifecycle.current_segment_id != 0
            && segment_lifecycle.last_completed_segment_id
                == segment_lifecycle.current_segment_id)
        assert(not segment_lifecycle.segment_open);

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
        if (checkpoint->authenticated)
            for (auto sharing_id : checkpoint->sharing_ids)
            {
                const auto* sharing = find_registered_sharing(
                        sharing_id);
                assert(sharing != 0);
                if (sharing->kind
                        == RegisteredSharingKind::checkpoint_output)
                    assert(sharing->status
                            == VerifiableSharingStatus::authenticated);
            }
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
typename AtlasGsz<T>::SegmentCompletionReadinessResult
AtlasGsz<T>::inspect_current_segment_completion_readiness() const
{
    if (not segment_lifecycle.initialized)
    {
        SegmentCompletionReadinessResult result{};
        result.valid = true;
        result.action =
                SegmentCompletionReadinessAction::no_open_segment;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    return inspect_segment_completion_readiness(
            segment_lifecycle.current_segment_id,
            segment_lifecycle.current_output_checkpoint_id);
}

template<class T>
typename AtlasGsz<T>::SegmentCompletionReadinessResult
AtlasGsz<T>::inspect_segment_completion_readiness(
        uint64_t segment_id,
        uint64_t checkpoint_id) const
{
    SegmentCompletionReadinessResult result{};
    result.valid = true;
    result.segment_id = segment_id;
    result.checkpoint_id = checkpoint_id;

    auto find_checkpoint = [&](uint64_t id)
        -> const CheckpointRecord*
    {
        if (id == 0 || not verifiable_registry.initialized)
            return 0;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == id)
                return &checkpoint;
        return 0;
    };

    auto checkpoint_sharings_authenticated =
            [&](const CheckpointRecord& checkpoint)
    {
        for (auto sharing_id : checkpoint.sharing_ids)
        {
            const auto* sharing = find_registered_sharing(sharing_id);
            assert(sharing != 0);
            if (sharing == 0)
                return false;
            assert(sharing->checkpoint_id == checkpoint.checkpoint_id);
            assert(sharing->segment_id == checkpoint.segment_id);
            if (sharing->kind != RegisteredSharingKind::checkpoint_output)
                return false;
            if (sharing->status
                    != VerifiableSharingStatus::authenticated)
                return false;
        }
        return true;
    };

    const auto* checkpoint = find_checkpoint(checkpoint_id);
    if (checkpoint != 0)
    {
        result.sharing_ids = checkpoint->sharing_ids;
        result.authentication_record_ids =
                authentication_records_for_checkpoint(checkpoint_id);
    }

    if (not segment_lifecycle.initialized
            || segment_id == 0
            || segment_id != segment_lifecycle.current_segment_id)
    {
        result.sharing_ids.clear();
        result.authentication_record_ids.clear();
        result.action =
                SegmentCompletionReadinessAction::no_open_segment;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (not segment_lifecycle.segment_open)
    {
        if (segment_lifecycle.last_completed_segment_id == segment_id
                && checkpoint != 0
                && checkpoint->authenticated
                && checkpoint_authentication_plan_complete(checkpoint_id)
                && checkpoint_sharings_authenticated(*checkpoint))
        {
            result.action =
                    SegmentCompletionReadinessAction::already_completed;
            validate_segment_completion_readiness_result(result);
            return result;
        }

        result.action =
                SegmentCompletionReadinessAction::no_open_segment;
        result.sharing_ids.clear();
        result.authentication_record_ids.clear();
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (checkpoint_id == 0
            || checkpoint == 0
            || checkpoint->segment_id != segment_id
            || segment_lifecycle.current_output_checkpoint_id
                != checkpoint_id)
    {
        result.sharing_ids.clear();
        result.authentication_record_ids.clear();
        result.action =
                SegmentCompletionReadinessAction::
                    missing_output_checkpoint;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (segment_lifecycle.checkpoint_open)
    {
        result.action =
                SegmentCompletionReadinessAction::checkpoint_still_open;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (not checkpoint->sealed)
    {
        result.action =
                SegmentCompletionReadinessAction::checkpoint_not_sealed;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (not checkpoint->authentication_requested)
    {
        result.action =
                SegmentCompletionReadinessAction::
                    authentication_not_requested;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (result.authentication_record_ids.empty())
    {
        result.action =
                SegmentCompletionReadinessAction::
                    authentication_records_missing;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (not checkpoint_authentication_plan_complete(checkpoint_id))
    {
        result.action =
                SegmentCompletionReadinessAction::
                    authentication_incomplete;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    if (not checkpoint->authenticated
            || not checkpoint_sharings_authenticated(*checkpoint))
    {
        result.action =
                SegmentCompletionReadinessAction::
                    checkpoint_not_authenticated;
        validate_segment_completion_readiness_result(result);
        return result;
    }

    result.action = SegmentCompletionReadinessAction::ready;
    result.ready = true;
    validate_segment_completion_readiness_result(result);
    return result;
}

template<class T>
typename AtlasGsz<T>::SegmentCompletionReadinessResult
AtlasGsz<T>::complete_current_segment_if_checkpoint_authenticated()
{
    auto result = inspect_current_segment_completion_readiness();
    validate_segment_completion_readiness_result(result);
    if (result.action
            == SegmentCompletionReadinessAction::already_completed)
        return result;
    if (not result.ready)
        return result;

#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_completion = dispute_control_state.corr;
    auto disp_before_completion = dispute_control_state.disp;
    size_t sharing_count_before_completion =
            verifiable_registry.sharings.size();
    size_t checkpoint_count_before_completion =
            verifiable_registry.checkpoints.size();
    size_t auth_record_count_before_completion =
            authentication_plan_state.records.size();
    size_t auth_material_count_before_completion =
            authentication_material_state.records.size();
#endif

    assert(segment_lifecycle.initialized);
    assert(segment_lifecycle.segment_open);
    assert(not segment_lifecycle.checkpoint_open);
    assert(segment_lifecycle.current_segment_id == result.segment_id);
    assert(segment_lifecycle.current_output_checkpoint_id
            == result.checkpoint_id);

    segment_lifecycle.last_completed_segment_id = result.segment_id;
    segment_lifecycle.segment_open = false;
    segment_lifecycle.checkpoint_open = false;
    result.state_updated = true;

    validate_verifiable_registry();
    validate_segment_lifecycle();
    validate_authentication_plan();
    validate_authentication_material();
    validate_segment_completion_readiness_result(result);

#ifndef NDEBUG
    assert(dispute_control_state.initialized
            == dispute_state_was_initialized);
    assert(dispute_control_state.corr == corr_before_completion);
    assert(dispute_control_state.disp == disp_before_completion);
    assert(verifiable_registry.sharings.size()
            == sharing_count_before_completion);
    assert(verifiable_registry.checkpoints.size()
            == checkpoint_count_before_completion);
    assert(authentication_plan_state.records.size()
            == auth_record_count_before_completion);
    assert(authentication_material_state.records.size()
            == auth_material_count_before_completion);
#endif
    return result;
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
        auto outcome =
                authentication_decision_outcome_from_checkpoint_decision(
                        checkpoint_decision);
        validate_authentication_decision_outcome(outcome);
        auto hook_result = inspect_authentication_outcome_hook(outcome);
        validate_authentication_outcome_hook_result(hook_result);
        auto analyze_plan =
                authentication_analyze_plan_from_hook_result(hook_result);
        validate_authentication_analyze_sharing_plan(analyze_plan);
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
typename AtlasGsz<T>::AuthenticationDecisionOutcome
AtlasGsz<T>::authentication_decision_outcome_from_checkpoint_decision(
        const AuthenticationCheckpointDecision& decision) const
{
    AuthenticationDecisionOutcome outcome{};
    assert(decision.valid);
    assert(decision.status != AuthenticationCheckpointDecisionStatus::none);
    if (not decision.valid
            || decision.status == AuthenticationCheckpointDecisionStatus::none)
        return outcome;

    validate_authentication_checkpoint_decision(decision);

    outcome.valid = true;
    outcome.checkpoint_status = decision.status;
    outcome.checkpoint_id = decision.checkpoint_id;
    outcome.segment_id = decision.segment_id;
    outcome.expected_sharings = decision.expected_sharings;
    outcome.accepted_sharings = decision.accepted_sharings;
    outcome.rejected_sharings = decision.rejected_sharings;
    outcome.not_ready_sharings = decision.not_ready_sharings;
    outcome.unavailable_sharings = decision.unavailable_sharings;
    outcome.insufficient_sharings = decision.insufficient_sharings;
    outcome.sharing_ids = decision.sharing_ids;
    outcome.rejected_sharing_ids = decision.rejected_sharing_ids;
    outcome.rejected_holder_ids = decision.rejected_holder_ids;

    switch (decision.status)
    {
    case AuthenticationCheckpointDecisionStatus::accepted:
        outcome.action =
                AuthenticationDecisionOutcomeAction::accept_checkpoint;
        outcome.would_accept_checkpoint = true;
        break;
    case AuthenticationCheckpointDecisionStatus::rejected:
        outcome.action =
                AuthenticationDecisionOutcomeAction::reject_checkpoint;
        outcome.would_reject_checkpoint = true;
        break;
    case AuthenticationCheckpointDecisionStatus::holder_share_unavailable:
        outcome.action =
                AuthenticationDecisionOutcomeAction::
                    holder_share_unavailable;
        outcome.has_unavailable_holder_share = true;
        break;
    case AuthenticationCheckpointDecisionStatus::not_ready:
        outcome.action =
                AuthenticationDecisionOutcomeAction::wait_for_material;
        outcome.needs_more_authentication_material = true;
        break;
    case AuthenticationCheckpointDecisionStatus::insufficient_votes:
        outcome.action =
                AuthenticationDecisionOutcomeAction::insufficient_votes;
        outcome.has_insufficient_votes = true;
        break;
    case AuthenticationCheckpointDecisionStatus::none:
        assert(false);
        return AuthenticationDecisionOutcome{};
    }

    validate_authentication_decision_outcome(outcome);
    return outcome;
}

template<class T>
typename AtlasGsz<T>::AuthenticationDecisionOutcome
AtlasGsz<T>::authentication_decision_outcome_for_checkpoint(
        uint64_t checkpoint_id) const
{
    auto decision = authentication_checkpoint_decision(checkpoint_id);
    return authentication_decision_outcome_from_checkpoint_decision(
            decision);
}

template<class T>
typename AtlasGsz<T>::AuthenticationDecisionOutcome
AtlasGsz<T>::current_output_checkpoint_authentication_outcome() const
{
    auto decision = current_output_checkpoint_authentication_decision();
    return authentication_decision_outcome_from_checkpoint_decision(
            decision);
}

template<class T>
typename AtlasGsz<T>::AuthenticationOutcomeHookResult
AtlasGsz<T>::inspect_authentication_outcome_hook(
        const AuthenticationDecisionOutcome& outcome) const
{
    AuthenticationOutcomeHookResult result{};
    assert(outcome.valid);
    assert(outcome.action != AuthenticationDecisionOutcomeAction::none);
    if (not outcome.valid
            || outcome.action == AuthenticationDecisionOutcomeAction::none)
        return result;

    validate_authentication_decision_outcome(outcome);

    result.valid = true;
    result.outcome_action = outcome.action;
    result.checkpoint_status = outcome.checkpoint_status;
    result.checkpoint_id = outcome.checkpoint_id;
    result.segment_id = outcome.segment_id;
    result.sharing_ids = outcome.sharing_ids;
    result.rejected_sharing_ids = outcome.rejected_sharing_ids;
    result.rejected_holder_ids = outcome.rejected_holder_ids;

    switch (outcome.action)
    {
    case AuthenticationDecisionOutcomeAction::accept_checkpoint:
        result.action =
                AuthenticationOutcomeHookAction::would_accept_checkpoint;
        result.would_accept = true;
        break;
    case AuthenticationDecisionOutcomeAction::reject_checkpoint:
        result.action =
                AuthenticationOutcomeHookAction::would_reject_checkpoint;
        result.would_reject = true;
        break;
    case AuthenticationDecisionOutcomeAction::wait_for_material:
        result.action =
                AuthenticationOutcomeHookAction::would_wait_for_material;
        result.would_wait = true;
        break;
    case AuthenticationDecisionOutcomeAction::holder_share_unavailable:
        result.action =
                AuthenticationOutcomeHookAction::
                    would_request_holder_share_recovery;
        result.would_need_recovery = true;
        break;
    case AuthenticationDecisionOutcomeAction::insufficient_votes:
        result.action =
                AuthenticationOutcomeHookAction::
                    would_report_insufficient_votes;
        result.would_report_insufficient = true;
        break;
    case AuthenticationDecisionOutcomeAction::none:
        assert(false);
        return AuthenticationOutcomeHookResult{};
    }

    validate_authentication_outcome_hook_result(result);
    return result;
}

template<class T>
typename AtlasGsz<T>::AuthenticationOutcomeHookResult
AtlasGsz<T>::inspect_authentication_outcome_hook_for_checkpoint(
        uint64_t checkpoint_id) const
{
    auto outcome = authentication_decision_outcome_for_checkpoint(
            checkpoint_id);
    return inspect_authentication_outcome_hook(outcome);
}

template<class T>
typename AtlasGsz<T>::AuthenticationOutcomeHookResult
AtlasGsz<T>::inspect_current_output_checkpoint_authentication_hook() const
{
    auto outcome = current_output_checkpoint_authentication_outcome();
    return inspect_authentication_outcome_hook(outcome);
}

template<class T>
typename AtlasGsz<T>::AuthenticationPromotionResult
AtlasGsz<T>::promote_accepted_authentication_outcome(
        const AuthenticationDecisionOutcome& outcome)
{
    AuthenticationPromotionResult result{};
#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_promotion = dispute_control_state.corr;
    auto disp_before_promotion = dispute_control_state.disp;
    auto assert_dispute_state_unchanged = [&]()
    {
        assert(dispute_control_state.initialized
                == dispute_state_was_initialized);
        assert(dispute_control_state.corr == corr_before_promotion);
        assert(dispute_control_state.disp == disp_before_promotion);
    };
#endif

    assert(outcome.valid);
    assert(outcome.action != AuthenticationDecisionOutcomeAction::none);
    if (not outcome.valid
            || outcome.action == AuthenticationDecisionOutcomeAction::none)
    {
#ifndef NDEBUG
        assert_dispute_state_unchanged();
#endif
        return result;
    }

    validate_authentication_decision_outcome(outcome);

    result.valid = true;
    result.checkpoint_id = outcome.checkpoint_id;
    result.segment_id = outcome.segment_id;

    if (outcome.action
            != AuthenticationDecisionOutcomeAction::accept_checkpoint)
    {
        result.action = AuthenticationPromotionAction::not_accepted;
        validate_authentication_promotion_result(result);
#ifndef NDEBUG
        assert_dispute_state_unchanged();
#endif
        return result;
    }

    auto decision = authentication_checkpoint_decision(
            outcome.checkpoint_id);
    validate_authentication_checkpoint_decision(decision);
    assert(decision.status
            == AuthenticationCheckpointDecisionStatus::accepted);
    if (decision.status
            != AuthenticationCheckpointDecisionStatus::accepted)
    {
        result.action = AuthenticationPromotionAction::not_accepted;
        validate_authentication_promotion_result(result);
#ifndef NDEBUG
        assert_dispute_state_unchanged();
#endif
        return result;
    }

    assert(decision.segment_id == outcome.segment_id);
    assert(decision.sharing_ids == outcome.sharing_ids);

    CheckpointRecord* checkpoint = 0;
    for (auto& candidate : verifiable_registry.checkpoints)
        if (candidate.checkpoint_id == outcome.checkpoint_id)
        {
            checkpoint = &candidate;
            break;
        }
    assert(checkpoint != 0);
    if (checkpoint == 0)
    {
#ifndef NDEBUG
        assert_dispute_state_unchanged();
#endif
        return AuthenticationPromotionResult{};
    }

    auto record_ids = authentication_records_for_checkpoint(
            outcome.checkpoint_id);
    assert(not record_ids.empty());
    if (record_ids.empty())
    {
#ifndef NDEBUG
        assert_dispute_state_unchanged();
#endif
        return AuthenticationPromotionResult{};
    }

    result.authentication_record_ids = record_ids;

    if (checkpoint->authenticated)
    {
        result.action =
                AuthenticationPromotionAction::already_authenticated;
        result.state_updated = false;
        validate_authentication_promotion_result(result);
#ifndef NDEBUG
        assert_dispute_state_unchanged();
#endif
        return result;
    }

    result.action = AuthenticationPromotionAction::promoted_checkpoint;
    result.promoted_sharing_ids = decision.sharing_ids;

    bool state_updated = false;
    for (auto record_id : record_ids)
    {
        auto* record = find_authentication_plan_record(record_id);
        assert(record != 0);
        assert(record->checkpoint_id == outcome.checkpoint_id);
        assert(record->kind
                == AuthenticationRecordKind::checkpoint_output_share);
        if (record->status != AuthenticationPlanStatus::authenticated)
            state_updated = true;
        mark_authentication_record_authenticated(record_id);
    }
    assert(checkpoint_authentication_plan_complete(
            outcome.checkpoint_id));

    if (not checkpoint->authenticated)
        state_updated = true;
    for (auto sharing_id : checkpoint->sharing_ids)
    {
        auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->checkpoint_id == outcome.checkpoint_id);
        if (sharing->status != VerifiableSharingStatus::authenticated)
            state_updated = true;
    }

    mark_checkpoint_authenticated(outcome.checkpoint_id);
    result.state_updated = state_updated;

    validate_verifiable_registry();
    validate_authentication_plan();
    validate_authentication_material();
    validate_authentication_promotion_result(result);
#ifndef NDEBUG
    assert_dispute_state_unchanged();
#endif
    return result;
}

template<class T>
typename AtlasGsz<T>::AuthenticationPromotionResult
AtlasGsz<T>::promote_accepted_authentication_outcome_for_checkpoint(
        uint64_t checkpoint_id)
{
    auto outcome = authentication_decision_outcome_for_checkpoint(
            checkpoint_id);
    return promote_accepted_authentication_outcome(outcome);
}

template<class T>
typename AtlasGsz<T>::AuthenticationPromotionResult
AtlasGsz<T>::promote_current_output_checkpoint_authentication_outcome()
{
    auto outcome = current_output_checkpoint_authentication_outcome();
    return promote_accepted_authentication_outcome(outcome);
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeSharingPlanEntry
AtlasGsz<T>::authentication_analyze_plan_entry_for_rejected_sharing(
        uint64_t sharing_id) const
{
    AuthenticationAnalyzeSharingPlanEntry entry{};
    const auto* sharing = find_registered_sharing(sharing_id);
    assert(sharing != 0);
    if (sharing == 0)
        return entry;

    auto sharing_decision = authentication_sharing_decision(sharing_id);
    validate_authentication_sharing_decision(sharing_decision);
    assert(sharing_decision.status
            == AuthenticationSharingDecisionStatus::rejected);
    if (sharing_decision.status
            != AuthenticationSharingDecisionStatus::rejected)
        return entry;

    entry.valid = true;
    entry.checkpoint_id = sharing_decision.checkpoint_id;
    entry.segment_id = sharing_decision.segment_id;
    entry.sharing_id = sharing_id;
    entry.kind = sharing_decision.kind;
    entry.sharing_status = sharing_decision.status;
    entry.rejected_holder_ids = sharing_decision.rejected_holder_ids;
    entry.would_analyze_sharing = true;

    validate_authentication_analyze_plan_entry(entry);
    return entry;
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeSharingPlan
AtlasGsz<T>::authentication_analyze_plan_from_hook_result(
        const AuthenticationOutcomeHookResult& hook_result) const
{
    AuthenticationAnalyzeSharingPlan plan{};
    assert(hook_result.valid);
    assert(hook_result.action != AuthenticationOutcomeHookAction::none);
    assert(hook_result.action != AuthenticationOutcomeHookAction::no_action);
    if (not hook_result.valid
            || hook_result.action == AuthenticationOutcomeHookAction::none
            || hook_result.action == AuthenticationOutcomeHookAction::no_action)
        return plan;

    validate_authentication_outcome_hook_result(hook_result);

    plan.valid = true;
    plan.hook_action = hook_result.action;
    plan.outcome_action = hook_result.outcome_action;
    plan.checkpoint_status = hook_result.checkpoint_status;
    plan.checkpoint_id = hook_result.checkpoint_id;
    plan.segment_id = hook_result.segment_id;
    plan.sharing_ids = hook_result.sharing_ids;
    plan.rejected_sharing_ids = hook_result.rejected_sharing_ids;
    plan.rejected_holder_ids = hook_result.rejected_holder_ids;

    switch (hook_result.action)
    {
    case AuthenticationOutcomeHookAction::would_reject_checkpoint:
        plan.action =
                AuthenticationAnalyzePlanAction::
                    would_analyze_rejected_sharings;
        plan.would_create_analyze_requests = true;
        for (auto sharing_id : hook_result.rejected_sharing_ids)
        {
            auto entry =
                    authentication_analyze_plan_entry_for_rejected_sharing(
                            sharing_id);
            validate_authentication_analyze_plan_entry(entry);
            plan.entries.push_back(entry);
        }
        break;
    case AuthenticationOutcomeHookAction::would_wait_for_material:
        plan.action = AuthenticationAnalyzePlanAction::wait_for_material;
        break;
    case AuthenticationOutcomeHookAction::would_request_holder_share_recovery:
        plan.action =
                AuthenticationAnalyzePlanAction::holder_share_unavailable;
        break;
    case AuthenticationOutcomeHookAction::would_report_insufficient_votes:
        plan.action = AuthenticationAnalyzePlanAction::insufficient_votes;
        break;
    case AuthenticationOutcomeHookAction::would_accept_checkpoint:
        plan.action = AuthenticationAnalyzePlanAction::no_action;
        break;
    case AuthenticationOutcomeHookAction::no_action:
    case AuthenticationOutcomeHookAction::none:
        assert(false);
        return AuthenticationAnalyzeSharingPlan{};
    }

    validate_authentication_analyze_sharing_plan(plan);
    return plan;
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeSharingPlan
AtlasGsz<T>::authentication_analyze_plan_for_checkpoint(
        uint64_t checkpoint_id) const
{
    auto hook_result = inspect_authentication_outcome_hook_for_checkpoint(
            checkpoint_id);
    return authentication_analyze_plan_from_hook_result(hook_result);
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeSharingPlan
AtlasGsz<T>::current_output_checkpoint_authentication_analyze_plan() const
{
    auto hook_result =
            inspect_current_output_checkpoint_authentication_hook();
    return authentication_analyze_plan_from_hook_result(hook_result);
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeEnqueueResult
AtlasGsz<T>::enqueue_authentication_analyze_plan(
        const AuthenticationAnalyzeSharingPlan& plan)
{
    AuthenticationAnalyzeEnqueueResult result{};
    assert(plan.valid);
    assert(plan.action != AuthenticationAnalyzePlanAction::none);
    if (not plan.valid
            || plan.action == AuthenticationAnalyzePlanAction::none)
        return result;

    validate_authentication_analyze_sharing_plan(plan);

    result.valid = true;
    result.checkpoint_id = plan.checkpoint_id;
    result.segment_id = plan.segment_id;

    if (plan.action == AuthenticationAnalyzePlanAction::no_action)
    {
        result.action = AuthenticationAnalyzeEnqueueAction::no_action;
        validate_authentication_analyze_enqueue_result(result);
        return result;
    }

    if (plan.action
            != AuthenticationAnalyzePlanAction::
                would_analyze_rejected_sharings)
    {
        result.action = AuthenticationAnalyzeEnqueueAction::not_rejected;
        validate_authentication_analyze_enqueue_result(result);
        return result;
    }

    if (plan.entries.empty())
    {
        result.action =
                AuthenticationAnalyzeEnqueueAction::
                    no_analyze_candidates;
        validate_authentication_analyze_enqueue_result(result);
        return result;
    }

#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_enqueue = dispute_control_state.corr;
    auto disp_before_enqueue = dispute_control_state.disp;

    bool segment_lifecycle_was_initialized =
            segment_lifecycle.initialized;
    uint64_t lifecycle_current_segment_before =
            segment_lifecycle.current_segment_id;
    uint64_t lifecycle_last_completed_before =
            segment_lifecycle.last_completed_segment_id;
    bool lifecycle_segment_open_before = segment_lifecycle.segment_open;
    bool lifecycle_checkpoint_open_before =
            segment_lifecycle.checkpoint_open;
    uint64_t lifecycle_input_checkpoint_before =
            segment_lifecycle.current_input_checkpoint_id;
    uint64_t lifecycle_output_checkpoint_before =
            segment_lifecycle.current_output_checkpoint_id;
    auto lifecycle_input_sharings_before =
            segment_lifecycle.current_segment_input_sharings;
    auto lifecycle_output_sharings_before =
            segment_lifecycle.current_segment_output_sharings;

    bool verifiable_registry_was_initialized =
            verifiable_registry.initialized;
    uint64_t next_sharing_id_before =
            verifiable_registry.next_sharing_id;
    uint64_t next_checkpoint_id_before =
            verifiable_registry.next_checkpoint_id;
    uint64_t registry_current_segment_before =
            verifiable_registry.current_segment_id;
    size_t sharing_count_before =
            verifiable_registry.sharings.size();
    size_t checkpoint_count_before =
            verifiable_registry.checkpoints.size();
    vector<uint64_t> sharing_ids_before;
    vector<uint64_t> sharing_checkpoint_ids_before;
    vector<uint64_t> sharing_segment_ids_before;
    vector<RegisteredSharingKind> sharing_kinds_before;
    vector<VerifiableSharingStatus> sharing_statuses_before;
    for (const auto& sharing : verifiable_registry.sharings)
    {
        sharing_ids_before.push_back(sharing.id);
        sharing_checkpoint_ids_before.push_back(sharing.checkpoint_id);
        sharing_segment_ids_before.push_back(sharing.segment_id);
        sharing_kinds_before.push_back(sharing.kind);
        sharing_statuses_before.push_back(sharing.status);
    }
    vector<uint64_t> checkpoint_ids_before;
    vector<uint64_t> checkpoint_segment_ids_before;
    vector<bool> checkpoint_sealed_before;
    vector<bool> checkpoint_authentication_requested_before;
    vector<bool> checkpoint_authenticated_before;
    for (const auto& checkpoint : verifiable_registry.checkpoints)
    {
        checkpoint_ids_before.push_back(checkpoint.checkpoint_id);
        checkpoint_segment_ids_before.push_back(checkpoint.segment_id);
        checkpoint_sealed_before.push_back(checkpoint.sealed);
        checkpoint_authentication_requested_before.push_back(
                checkpoint.authentication_requested);
        checkpoint_authenticated_before.push_back(
                checkpoint.authenticated);
    }

    bool authentication_plan_was_initialized =
            authentication_plan_state.initialized;
    uint64_t next_auth_record_id_before =
            authentication_plan_state.next_auth_record_id;
    size_t auth_record_count_before =
            authentication_plan_state.records.size();
    bool authentication_material_was_initialized =
            authentication_material_state.initialized;
    uint64_t next_material_id_before =
            authentication_material_state.next_material_id;
    size_t auth_material_count_before =
            authentication_material_state.records.size();
#endif

    bool created_any = false;
    for (const auto& entry : plan.entries)
    {
        validate_authentication_analyze_plan_entry(entry);
        assert(entry.checkpoint_id == plan.checkpoint_id);
        assert(entry.segment_id == plan.segment_id);
        assert(entry.kind
                == AuthenticationRecordKind::checkpoint_output_share);
        assert(entry.sharing_status
                == AuthenticationSharingDecisionStatus::rejected);

        const auto* sharing = find_registered_sharing(entry.sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        assert(sharing->checkpoint_id == plan.checkpoint_id);
        assert(sharing->segment_id == plan.segment_id);

        bool already_pending =
                pending_analyze_sharing_request_exists_for_authentication_rejection(
                        entry.checkpoint_id, entry.sharing_id);
        uint64_t request_id =
                create_pending_analyze_sharing_request_for_authentication_rejection(
                        entry);
        assert(request_id != 0);
        result.sharing_ids.push_back(entry.sharing_id);
        result.pending_request_ids.push_back(request_id);
        if (not already_pending)
            created_any = true;
    }

    if (result.sharing_ids.empty())
        result.action =
                AuthenticationAnalyzeEnqueueAction::
                    no_analyze_candidates;
    else if (created_any)
    {
        result.action =
                AuthenticationAnalyzeEnqueueAction::
                    enqueued_requests;
        result.state_updated = true;
    }
    else
        result.action =
                AuthenticationAnalyzeEnqueueAction::already_enqueued;

    validate_pending_analyze_sharing_state();
    validate_authentication_analyze_enqueue_result(result);

#ifndef NDEBUG
    assert(dispute_control_state.initialized
            == dispute_state_was_initialized);
    assert(dispute_control_state.corr == corr_before_enqueue);
    assert(dispute_control_state.disp == disp_before_enqueue);

    assert(segment_lifecycle.initialized
            == segment_lifecycle_was_initialized);
    assert(segment_lifecycle.current_segment_id
            == lifecycle_current_segment_before);
    assert(segment_lifecycle.last_completed_segment_id
            == lifecycle_last_completed_before);
    assert(segment_lifecycle.segment_open
            == lifecycle_segment_open_before);
    assert(segment_lifecycle.checkpoint_open
            == lifecycle_checkpoint_open_before);
    assert(segment_lifecycle.current_input_checkpoint_id
            == lifecycle_input_checkpoint_before);
    assert(segment_lifecycle.current_output_checkpoint_id
            == lifecycle_output_checkpoint_before);
    assert(segment_lifecycle.current_segment_input_sharings
            == lifecycle_input_sharings_before);
    assert(segment_lifecycle.current_segment_output_sharings
            == lifecycle_output_sharings_before);

    assert(verifiable_registry.initialized
            == verifiable_registry_was_initialized);
    assert(verifiable_registry.next_sharing_id
            == next_sharing_id_before);
    assert(verifiable_registry.next_checkpoint_id
            == next_checkpoint_id_before);
    assert(verifiable_registry.current_segment_id
            == registry_current_segment_before);
    assert(verifiable_registry.sharings.size() == sharing_count_before);
    assert(verifiable_registry.checkpoints.size()
            == checkpoint_count_before);
    for (size_t i = 0; i < verifiable_registry.sharings.size(); i++)
    {
        const auto& sharing = verifiable_registry.sharings.at(i);
        assert(sharing.id == sharing_ids_before.at(i));
        assert(sharing.checkpoint_id
                == sharing_checkpoint_ids_before.at(i));
        assert(sharing.segment_id == sharing_segment_ids_before.at(i));
        assert(sharing.kind == sharing_kinds_before.at(i));
        assert(sharing.status == sharing_statuses_before.at(i));
    }
    for (size_t i = 0; i < verifiable_registry.checkpoints.size(); i++)
    {
        const auto& checkpoint = verifiable_registry.checkpoints.at(i);
        assert(checkpoint.checkpoint_id == checkpoint_ids_before.at(i));
        assert(checkpoint.segment_id
                == checkpoint_segment_ids_before.at(i));
        assert(checkpoint.sealed == checkpoint_sealed_before.at(i));
        assert(checkpoint.authentication_requested
                == checkpoint_authentication_requested_before.at(i));
        assert(checkpoint.authenticated
                == checkpoint_authenticated_before.at(i));
    }

    assert(authentication_plan_state.initialized
            == authentication_plan_was_initialized);
    assert(authentication_plan_state.next_auth_record_id
            == next_auth_record_id_before);
    assert(authentication_plan_state.records.size()
            == auth_record_count_before);
    assert(authentication_material_state.initialized
            == authentication_material_was_initialized);
    assert(authentication_material_state.next_material_id
            == next_material_id_before);
    assert(authentication_material_state.records.size()
            == auth_material_count_before);
#endif
    return result;
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeEnqueueResult
AtlasGsz<T>::enqueue_authentication_analyze_requests_from_hook_result(
        const AuthenticationOutcomeHookResult& hook)
{
    auto plan = authentication_analyze_plan_from_hook_result(hook);
    return enqueue_authentication_analyze_plan(plan);
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeEnqueueResult
AtlasGsz<T>::enqueue_authentication_analyze_requests_for_checkpoint(
        uint64_t checkpoint_id)
{
    auto plan = authentication_analyze_plan_for_checkpoint(checkpoint_id);
    return enqueue_authentication_analyze_plan(plan);
}

template<class T>
typename AtlasGsz<T>::AuthenticationAnalyzeEnqueueResult
AtlasGsz<T>::enqueue_current_output_checkpoint_authentication_analyze_requests()
{
    auto plan = current_output_checkpoint_authentication_analyze_plan();
    return enqueue_authentication_analyze_plan(plan);
}

template<class T>
typename AtlasGsz<T>::SegmentRecoveryDecisionResult
AtlasGsz<T>::inspect_current_segment_recovery_decision() const
{
    if (not segment_lifecycle.initialized)
        return inspect_segment_recovery_decision(0, 0);

    return inspect_segment_recovery_decision(
            segment_lifecycle.current_segment_id,
            segment_lifecycle.current_output_checkpoint_id);
}

template<class T>
typename AtlasGsz<T>::SegmentRecoveryDecisionResult
AtlasGsz<T>::inspect_segment_recovery_decision(
        uint64_t segment_id,
        uint64_t checkpoint_id) const
{
    SegmentRecoveryDecisionResult result{};
    result.valid = true;
    result.segment_id = segment_id;
    result.checkpoint_id = checkpoint_id;

#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_inspection = dispute_control_state.corr;
    auto disp_before_inspection = dispute_control_state.disp;

    bool segment_lifecycle_was_initialized =
            segment_lifecycle.initialized;
    uint64_t lifecycle_current_segment_before =
            segment_lifecycle.current_segment_id;
    uint64_t lifecycle_last_completed_before =
            segment_lifecycle.last_completed_segment_id;
    bool lifecycle_segment_open_before = segment_lifecycle.segment_open;
    bool lifecycle_checkpoint_open_before =
            segment_lifecycle.checkpoint_open;
    uint64_t lifecycle_input_checkpoint_before =
            segment_lifecycle.current_input_checkpoint_id;
    uint64_t lifecycle_output_checkpoint_before =
            segment_lifecycle.current_output_checkpoint_id;
    auto lifecycle_input_sharings_before =
            segment_lifecycle.current_segment_input_sharings;
    auto lifecycle_output_sharings_before =
            segment_lifecycle.current_segment_output_sharings;

    bool verifiable_registry_was_initialized =
            verifiable_registry.initialized;
    uint64_t next_sharing_id_before =
            verifiable_registry.next_sharing_id;
    uint64_t next_checkpoint_id_before =
            verifiable_registry.next_checkpoint_id;
    uint64_t registry_current_segment_before =
            verifiable_registry.current_segment_id;
    size_t sharing_count_before =
            verifiable_registry.sharings.size();
    size_t checkpoint_count_before =
            verifiable_registry.checkpoints.size();

    bool authentication_plan_was_initialized =
            authentication_plan_state.initialized;
    uint64_t next_auth_record_id_before =
            authentication_plan_state.next_auth_record_id;
    size_t auth_record_count_before =
            authentication_plan_state.records.size();
    bool authentication_material_was_initialized =
            authentication_material_state.initialized;
    uint64_t next_material_id_before =
            authentication_material_state.next_material_id;
    size_t auth_material_count_before =
            authentication_material_state.records.size();

    bool pending_state_was_initialized =
            pending_analyze_sharing_state.initialized;
    uint64_t next_pending_request_id_before =
            pending_analyze_sharing_state.next_request_id;
    size_t pending_request_count_before =
            pending_analyze_sharing_state.requests.size();
    vector<uint64_t> pending_request_ids_before;
    vector<PendingAnalyzeSharingSource> pending_sources_before;
    vector<PendingAnalyzeSharingTarget> pending_targets_before;
    vector<uint64_t> pending_checkpoint_ids_before;
    vector<uint64_t> pending_segment_ids_before;
    vector<uint64_t> pending_sharing_ids_before;
    vector<vector<int>> pending_rejected_holders_before;
    for (const auto& request : pending_analyze_sharing_state.requests)
    {
        pending_request_ids_before.push_back(request.id);
        pending_sources_before.push_back(request.source);
        pending_targets_before.push_back(request.target);
        pending_checkpoint_ids_before.push_back(request.checkpoint_id);
        pending_segment_ids_before.push_back(request.segment_id);
        pending_sharing_ids_before.push_back(request.sharing_id);
        pending_rejected_holders_before.push_back(
                request.rejected_holder_ids);
    }

    auto assert_inspection_read_only = [&]()
    {
        assert(dispute_control_state.initialized
                == dispute_state_was_initialized);
        assert(dispute_control_state.corr == corr_before_inspection);
        assert(dispute_control_state.disp == disp_before_inspection);

        assert(segment_lifecycle.initialized
                == segment_lifecycle_was_initialized);
        assert(segment_lifecycle.current_segment_id
                == lifecycle_current_segment_before);
        assert(segment_lifecycle.last_completed_segment_id
                == lifecycle_last_completed_before);
        assert(segment_lifecycle.segment_open
                == lifecycle_segment_open_before);
        assert(segment_lifecycle.checkpoint_open
                == lifecycle_checkpoint_open_before);
        assert(segment_lifecycle.current_input_checkpoint_id
                == lifecycle_input_checkpoint_before);
        assert(segment_lifecycle.current_output_checkpoint_id
                == lifecycle_output_checkpoint_before);
        assert(segment_lifecycle.current_segment_input_sharings
                == lifecycle_input_sharings_before);
        assert(segment_lifecycle.current_segment_output_sharings
                == lifecycle_output_sharings_before);

        assert(verifiable_registry.initialized
                == verifiable_registry_was_initialized);
        assert(verifiable_registry.next_sharing_id
                == next_sharing_id_before);
        assert(verifiable_registry.next_checkpoint_id
                == next_checkpoint_id_before);
        assert(verifiable_registry.current_segment_id
                == registry_current_segment_before);
        assert(verifiable_registry.sharings.size()
                == sharing_count_before);
        assert(verifiable_registry.checkpoints.size()
                == checkpoint_count_before);

        assert(authentication_plan_state.initialized
                == authentication_plan_was_initialized);
        assert(authentication_plan_state.next_auth_record_id
                == next_auth_record_id_before);
        assert(authentication_plan_state.records.size()
                == auth_record_count_before);
        assert(authentication_material_state.initialized
                == authentication_material_was_initialized);
        assert(authentication_material_state.next_material_id
                == next_material_id_before);
        assert(authentication_material_state.records.size()
                == auth_material_count_before);

        assert(pending_analyze_sharing_state.initialized
                == pending_state_was_initialized);
        assert(pending_analyze_sharing_state.next_request_id
                == next_pending_request_id_before);
        assert(pending_analyze_sharing_state.requests.size()
                == pending_request_count_before);
        for (size_t i = 0;
                i < pending_analyze_sharing_state.requests.size(); i++)
        {
            const auto& request =
                    pending_analyze_sharing_state.requests.at(i);
            assert(request.id == pending_request_ids_before.at(i));
            assert(request.source == pending_sources_before.at(i));
            assert(request.target == pending_targets_before.at(i));
            assert(request.checkpoint_id
                    == pending_checkpoint_ids_before.at(i));
            assert(request.segment_id
                    == pending_segment_ids_before.at(i));
            assert(request.sharing_id == pending_sharing_ids_before.at(i));
            assert(request.rejected_holder_ids
                    == pending_rejected_holders_before.at(i));
        }
    };
#endif

    auto finish = [&](SegmentRecoveryDecisionAction action)
    {
        result.action = action;
        validate_segment_recovery_decision_result(result);
#ifndef NDEBUG
        assert_inspection_read_only();
#endif
        return result;
    };

    auto find_checkpoint = [&](uint64_t id)
        -> const CheckpointRecord*
    {
        if (id == 0 || not verifiable_registry.initialized)
            return 0;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == id)
                return &checkpoint;
        return 0;
    };

    auto pending_request_id_for_rejection =
            [&](uint64_t rejected_sharing_id)
    {
        uint64_t request_id = 0;
        if (not pending_analyze_sharing_state.initialized)
            return request_id;

        for (const auto& request :
                pending_analyze_sharing_state.requests)
            if (request.source
                        == PendingAnalyzeSharingSource::
                            authentication_rejection
                    && request.target
                        == PendingAnalyzeSharingTarget::
                            registered_checkpoint_output_sharing
                    && request.checkpoint_id == result.checkpoint_id
                    && request.sharing_id == rejected_sharing_id)
            {
                request_id = request.id;
                break;
            }
        return request_id;
    };

    auto readiness = inspect_segment_completion_readiness(
            segment_id, checkpoint_id);
    result.segment_readiness_action = readiness.action;
    result.sharing_ids = readiness.sharing_ids;

    const bool inspecting_current =
            segment_lifecycle.initialized
            && segment_id == segment_lifecycle.current_segment_id
            && checkpoint_id
                == segment_lifecycle.current_output_checkpoint_id;

    if (not segment_lifecycle.initialized
            || segment_id == 0
            || segment_id != segment_lifecycle.current_segment_id)
    {
        if (checkpoint_id != 0 && find_checkpoint(checkpoint_id) == 0)
            result.checkpoint_id = 0;
        return finish(SegmentRecoveryDecisionAction::no_open_segment);
    }

    const auto* checkpoint = find_checkpoint(checkpoint_id);
    if (checkpoint != 0)
    {
        result.checkpoint_id = checkpoint->checkpoint_id;
        result.segment_id = checkpoint->segment_id;
        result.checkpoint_authenticated = checkpoint->authenticated;
        if (result.sharing_ids.empty())
            result.sharing_ids = checkpoint->sharing_ids;
    }

    if (not segment_lifecycle.segment_open)
    {
        if (readiness.action
                == SegmentCompletionReadinessAction::already_completed)
        {
            result.segment_completion_ready = false;
            return finish(SegmentRecoveryDecisionAction::already_completed);
        }
        return finish(SegmentRecoveryDecisionAction::no_open_segment);
    }

    if (checkpoint_id == 0
            || checkpoint == 0
            || checkpoint->segment_id != segment_id
            || segment_lifecycle.current_output_checkpoint_id
                != checkpoint_id)
    {
        if (checkpoint_id != 0 && checkpoint == 0)
            result.checkpoint_id = 0;
        return finish(SegmentRecoveryDecisionAction::wait_for_checkpoint);
    }

    if (readiness.action
            == SegmentCompletionReadinessAction::missing_output_checkpoint
            || readiness.action
                == SegmentCompletionReadinessAction::checkpoint_still_open
            || readiness.action
                == SegmentCompletionReadinessAction::checkpoint_not_sealed)
        return finish(SegmentRecoveryDecisionAction::wait_for_checkpoint);

    if (readiness.action
            == SegmentCompletionReadinessAction::
                authentication_not_requested)
        return finish(
                SegmentRecoveryDecisionAction::
                    wait_for_authentication_request);

    if (readiness.action == SegmentCompletionReadinessAction::ready)
        result.segment_completion_ready = true;

    AuthenticationOutcomeHookResult hook{};
    if (inspecting_current)
        hook = inspect_current_output_checkpoint_authentication_hook();
    else
        hook = inspect_authentication_outcome_hook_for_checkpoint(
                checkpoint_id);

    if (not hook.valid
            || hook.action == AuthenticationOutcomeHookAction::none)
        return finish(SegmentRecoveryDecisionAction::inconsistent_state);

    result.authentication_outcome_action = hook.outcome_action;
    result.authentication_hook_action = hook.action;
    result.sharing_ids = hook.sharing_ids;
    result.rejected_sharing_ids = hook.rejected_sharing_ids;

    switch (hook.action)
    {
    case AuthenticationOutcomeHookAction::would_wait_for_material:
        return finish(
                SegmentRecoveryDecisionAction::
                    wait_for_authentication_material);

    case AuthenticationOutcomeHookAction::
            would_request_holder_share_recovery:
        return finish(
                SegmentRecoveryDecisionAction::
                    holder_share_unavailable);

    case AuthenticationOutcomeHookAction::would_report_insufficient_votes:
        return finish(SegmentRecoveryDecisionAction::insufficient_votes);

    case AuthenticationOutcomeHookAction::would_accept_checkpoint:
        if (not checkpoint->authenticated)
        {
            result.checkpoint_promotion_ready = true;
            return finish(
                    SegmentRecoveryDecisionAction::
                        would_promote_checkpoint);
        }

        result.checkpoint_authenticated = true;
        if (readiness.ready)
        {
            result.segment_completion_ready = true;
            return finish(
                    SegmentRecoveryDecisionAction::
                        would_complete_authenticated_segment);
        }
        return finish(SegmentRecoveryDecisionAction::inconsistent_state);

    case AuthenticationOutcomeHookAction::would_reject_checkpoint:
    {
        AuthenticationAnalyzeSharingPlan plan{};
        if (inspecting_current)
            plan = current_output_checkpoint_authentication_analyze_plan();
        else
            plan = authentication_analyze_plan_from_hook_result(hook);

        if (not plan.valid
                || plan.action
                    != AuthenticationAnalyzePlanAction::
                        would_analyze_rejected_sharings)
            return finish(SegmentRecoveryDecisionAction::inconsistent_state);

        result.analyze_plan_action = plan.action;
        result.sharing_ids = plan.sharing_ids;
        result.rejected_sharing_ids = plan.rejected_sharing_ids;

        if (plan.entries.empty())
            return finish(SegmentRecoveryDecisionAction::inconsistent_state);

        for (const auto& entry : plan.entries)
        {
            if (entry.checkpoint_id != result.checkpoint_id
                    || entry.segment_id != result.segment_id)
                return finish(
                        SegmentRecoveryDecisionAction::
                            inconsistent_state);

            uint64_t pending_request_id =
                    pending_request_id_for_rejection(entry.sharing_id);
            if (pending_request_id != 0)
                result.pending_request_ids.push_back(
                        pending_request_id);
        }

        result.analyze_enqueue_ready = true;
        return finish(
                SegmentRecoveryDecisionAction::
                    would_enqueue_analyze_requests);
    }

    case AuthenticationOutcomeHookAction::no_action:
    case AuthenticationOutcomeHookAction::none:
        break;
    }

    return finish(SegmentRecoveryDecisionAction::inconsistent_state);
}

template<class T>
typename AtlasGsz<T>::SegmentRecoveryApplicationResult
AtlasGsz<T>::apply_current_segment_recovery_decision_once()
{
    auto decision = inspect_current_segment_recovery_decision();
    return apply_segment_recovery_decision_once(decision);
}

template<class T>
typename AtlasGsz<T>::SegmentRecoveryApplicationResult
AtlasGsz<T>::apply_segment_recovery_decision_once(
        const SegmentRecoveryDecisionResult& decision)
{
    SegmentRecoveryApplicationResult result{};

    assert(decision.valid);
    assert(decision.action != SegmentRecoveryDecisionAction::none);
    if (not decision.valid
            || decision.action == SegmentRecoveryDecisionAction::none)
        return result;

    validate_segment_recovery_decision_result(decision);

    result.valid = true;
    result.segment_id = decision.segment_id;
    result.checkpoint_id = decision.checkpoint_id;
    result.decision_action = decision.action;
    result.sharing_ids = decision.sharing_ids;
    result.rejected_sharing_ids = decision.rejected_sharing_ids;
    result.pending_request_ids = decision.pending_request_ids;

#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_application = dispute_control_state.corr;
    auto disp_before_application = dispute_control_state.disp;

    bool segment_lifecycle_was_initialized =
            segment_lifecycle.initialized;
    uint64_t lifecycle_current_segment_before =
            segment_lifecycle.current_segment_id;
    uint64_t lifecycle_last_completed_before =
            segment_lifecycle.last_completed_segment_id;
    bool lifecycle_segment_open_before = segment_lifecycle.segment_open;
    bool lifecycle_checkpoint_open_before =
            segment_lifecycle.checkpoint_open;
    uint64_t lifecycle_input_checkpoint_before =
            segment_lifecycle.current_input_checkpoint_id;
    uint64_t lifecycle_output_checkpoint_before =
            segment_lifecycle.current_output_checkpoint_id;
    auto lifecycle_input_sharings_before =
            segment_lifecycle.current_segment_input_sharings;
    auto lifecycle_output_sharings_before =
            segment_lifecycle.current_segment_output_sharings;

    bool verifiable_registry_was_initialized =
            verifiable_registry.initialized;
    uint64_t next_sharing_id_before =
            verifiable_registry.next_sharing_id;
    uint64_t next_checkpoint_id_before =
            verifiable_registry.next_checkpoint_id;
    uint64_t registry_current_segment_before =
            verifiable_registry.current_segment_id;
    size_t sharing_count_before =
            verifiable_registry.sharings.size();
    size_t checkpoint_count_before =
            verifiable_registry.checkpoints.size();
    vector<uint64_t> sharing_ids_before;
    vector<uint64_t> sharing_checkpoint_ids_before;
    vector<uint64_t> sharing_segment_ids_before;
    vector<RegisteredSharingKind> sharing_kinds_before;
    vector<VerifiableSharingStatus> sharing_statuses_before;
    for (const auto& sharing : verifiable_registry.sharings)
    {
        sharing_ids_before.push_back(sharing.id);
        sharing_checkpoint_ids_before.push_back(sharing.checkpoint_id);
        sharing_segment_ids_before.push_back(sharing.segment_id);
        sharing_kinds_before.push_back(sharing.kind);
        sharing_statuses_before.push_back(sharing.status);
    }
    vector<uint64_t> checkpoint_ids_before;
    vector<uint64_t> checkpoint_segment_ids_before;
    vector<vector<uint64_t>> checkpoint_sharing_ids_before;
    vector<bool> checkpoint_sealed_before;
    vector<bool> checkpoint_authentication_requested_before;
    vector<bool> checkpoint_authenticated_before;
    for (const auto& checkpoint : verifiable_registry.checkpoints)
    {
        checkpoint_ids_before.push_back(checkpoint.checkpoint_id);
        checkpoint_segment_ids_before.push_back(checkpoint.segment_id);
        checkpoint_sharing_ids_before.push_back(checkpoint.sharing_ids);
        checkpoint_sealed_before.push_back(checkpoint.sealed);
        checkpoint_authentication_requested_before.push_back(
                checkpoint.authentication_requested);
        checkpoint_authenticated_before.push_back(
                checkpoint.authenticated);
    }

    bool authentication_plan_was_initialized =
            authentication_plan_state.initialized;
    uint64_t next_auth_record_id_before =
            authentication_plan_state.next_auth_record_id;
    size_t auth_record_count_before =
            authentication_plan_state.records.size();
    vector<uint64_t> auth_record_ids_before;
    vector<uint64_t> auth_record_sharing_ids_before;
    vector<uint64_t> auth_record_checkpoint_ids_before;
    vector<uint64_t> auth_record_segment_ids_before;
    vector<int> auth_record_verifiers_before;
    vector<int> auth_record_holders_before;
    vector<AuthenticationRecordKind> auth_record_kinds_before;
    vector<AuthenticationPlanStatus> auth_record_statuses_before;
    for (const auto& record : authentication_plan_state.records)
    {
        auth_record_ids_before.push_back(record.id);
        auth_record_sharing_ids_before.push_back(record.sharing_id);
        auth_record_checkpoint_ids_before.push_back(record.checkpoint_id);
        auth_record_segment_ids_before.push_back(record.segment_id);
        auth_record_verifiers_before.push_back(record.verifier);
        auth_record_holders_before.push_back(record.holder);
        auth_record_kinds_before.push_back(record.kind);
        auth_record_statuses_before.push_back(record.status);
    }

    bool authentication_material_was_initialized =
            authentication_material_state.initialized;
    uint64_t next_material_id_before =
            authentication_material_state.next_material_id;
    size_t auth_material_count_before =
            authentication_material_state.records.size();

    bool pending_state_was_initialized =
            pending_analyze_sharing_state.initialized;
    uint64_t next_pending_request_id_before =
            pending_analyze_sharing_state.next_request_id;
    size_t pending_request_count_before =
            pending_analyze_sharing_state.requests.size();
    vector<uint64_t> pending_request_ids_before;
    vector<PendingAnalyzeSharingSource> pending_sources_before;
    vector<PendingAnalyzeSharingTarget> pending_targets_before;
    vector<uint64_t> pending_checkpoint_ids_before;
    vector<uint64_t> pending_segment_ids_before;
    vector<uint64_t> pending_sharing_ids_before;
    vector<vector<int>> pending_rejected_holders_before;
    for (const auto& request : pending_analyze_sharing_state.requests)
    {
        pending_request_ids_before.push_back(request.id);
        pending_sources_before.push_back(request.source);
        pending_targets_before.push_back(request.target);
        pending_checkpoint_ids_before.push_back(request.checkpoint_id);
        pending_segment_ids_before.push_back(request.segment_id);
        pending_sharing_ids_before.push_back(request.sharing_id);
        pending_rejected_holders_before.push_back(
                request.rejected_holder_ids);
    }

    bool called_promotion_helper = false;
    bool called_completion_helper = false;
    bool called_enqueue_helper = false;

    auto assert_application_mutation_scope = [&]()
    {
        assert(dispute_control_state.initialized
                == dispute_state_was_initialized);
        assert(dispute_control_state.corr == corr_before_application);
        assert(dispute_control_state.disp == disp_before_application);

        assert(segment_lifecycle.initialized
                == segment_lifecycle_was_initialized);
        assert(segment_lifecycle.current_segment_id
                == lifecycle_current_segment_before);
        assert(segment_lifecycle.current_input_checkpoint_id
                == lifecycle_input_checkpoint_before);
        assert(segment_lifecycle.current_output_checkpoint_id
                == lifecycle_output_checkpoint_before);
        assert(segment_lifecycle.current_segment_input_sharings
                == lifecycle_input_sharings_before);
        assert(segment_lifecycle.current_segment_output_sharings
                == lifecycle_output_sharings_before);
        if (not called_completion_helper)
        {
            assert(segment_lifecycle.last_completed_segment_id
                    == lifecycle_last_completed_before);
            assert(segment_lifecycle.segment_open
                    == lifecycle_segment_open_before);
            assert(segment_lifecycle.checkpoint_open
                    == lifecycle_checkpoint_open_before);
        }

        assert(verifiable_registry.initialized
                == verifiable_registry_was_initialized);
        assert(verifiable_registry.next_sharing_id
                == next_sharing_id_before);
        assert(verifiable_registry.next_checkpoint_id
                == next_checkpoint_id_before);
        assert(verifiable_registry.current_segment_id
                == registry_current_segment_before);
        assert(verifiable_registry.sharings.size()
                == sharing_count_before);
        assert(verifiable_registry.checkpoints.size()
                == checkpoint_count_before);
        for (size_t i = 0; i < verifiable_registry.sharings.size(); i++)
        {
            const auto& sharing = verifiable_registry.sharings.at(i);
            assert(sharing.id == sharing_ids_before.at(i));
            assert(sharing.checkpoint_id
                    == sharing_checkpoint_ids_before.at(i));
            assert(sharing.segment_id == sharing_segment_ids_before.at(i));
            assert(sharing.kind == sharing_kinds_before.at(i));
            if (not called_promotion_helper)
                assert(sharing.status == sharing_statuses_before.at(i));
        }
        for (size_t i = 0;
                i < verifiable_registry.checkpoints.size(); i++)
        {
            const auto& checkpoint =
                    verifiable_registry.checkpoints.at(i);
            assert(checkpoint.checkpoint_id
                    == checkpoint_ids_before.at(i));
            assert(checkpoint.segment_id
                    == checkpoint_segment_ids_before.at(i));
            assert(checkpoint.sharing_ids
                    == checkpoint_sharing_ids_before.at(i));
            assert(checkpoint.sealed == checkpoint_sealed_before.at(i));
            assert(checkpoint.authentication_requested
                    == checkpoint_authentication_requested_before.at(i));
            if (not called_promotion_helper)
                assert(checkpoint.authenticated
                        == checkpoint_authenticated_before.at(i));
        }

        assert(authentication_plan_state.initialized
                == authentication_plan_was_initialized);
        assert(authentication_plan_state.next_auth_record_id
                == next_auth_record_id_before);
        assert(authentication_plan_state.records.size()
                == auth_record_count_before);
        for (size_t i = 0;
                i < authentication_plan_state.records.size(); i++)
        {
            const auto& record = authentication_plan_state.records.at(i);
            assert(record.id == auth_record_ids_before.at(i));
            assert(record.sharing_id
                    == auth_record_sharing_ids_before.at(i));
            assert(record.checkpoint_id
                    == auth_record_checkpoint_ids_before.at(i));
            assert(record.segment_id
                    == auth_record_segment_ids_before.at(i));
            assert(record.verifier == auth_record_verifiers_before.at(i));
            assert(record.holder == auth_record_holders_before.at(i));
            assert(record.kind == auth_record_kinds_before.at(i));
            if (not called_promotion_helper)
                assert(record.status == auth_record_statuses_before.at(i));
        }

        assert(authentication_material_state.initialized
                == authentication_material_was_initialized);
        assert(authentication_material_state.next_material_id
                == next_material_id_before);
        assert(authentication_material_state.records.size()
                == auth_material_count_before);

        if (not called_enqueue_helper)
        {
            assert(pending_analyze_sharing_state.initialized
                    == pending_state_was_initialized);
            assert(pending_analyze_sharing_state.next_request_id
                    == next_pending_request_id_before);
            assert(pending_analyze_sharing_state.requests.size()
                    == pending_request_count_before);
        }
        else
        {
            assert(pending_analyze_sharing_state.initialized);
            assert(pending_analyze_sharing_state.requests.size()
                    >= pending_request_count_before);
            assert(pending_analyze_sharing_state.next_request_id
                    >= next_pending_request_id_before);
        }

        for (size_t i = 0; i < pending_request_count_before; i++)
        {
            const auto& request =
                    pending_analyze_sharing_state.requests.at(i);
            assert(request.id == pending_request_ids_before.at(i));
            assert(request.source == pending_sources_before.at(i));
            assert(request.target == pending_targets_before.at(i));
            assert(request.checkpoint_id
                    == pending_checkpoint_ids_before.at(i));
            assert(request.segment_id
                    == pending_segment_ids_before.at(i));
            assert(request.sharing_id == pending_sharing_ids_before.at(i));
            assert(request.rejected_holder_ids
                    == pending_rejected_holders_before.at(i));
        }
    };
#endif

    auto find_checkpoint = [&](uint64_t id)
        -> const CheckpointRecord*
    {
        if (id == 0 || not verifiable_registry.initialized)
            return 0;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == id)
                return &checkpoint;
        return 0;
    };

    auto finish = [&](SegmentRecoveryApplicationAction action)
    {
        result.action = action;
        validate_segment_recovery_application_result(result);
#ifndef NDEBUG
        assert_application_mutation_scope();
#endif
        return result;
    };

    const auto* checkpoint = find_checkpoint(decision.checkpoint_id);
    if (decision.checkpoint_id != 0
            && (checkpoint == 0
                || checkpoint->segment_id != decision.segment_id))
        return finish(SegmentRecoveryApplicationAction::inconsistent_state);

    switch (decision.action)
    {
    case SegmentRecoveryDecisionAction::would_promote_checkpoint:
    {
#ifndef NDEBUG
        called_promotion_helper = true;
#endif
        auto promotion =
                promote_accepted_authentication_outcome_for_checkpoint(
                        decision.checkpoint_id);
        result.promotion_action = promotion.action;
        result.state_updated = promotion.state_updated;
        if (not promotion.promoted_sharing_ids.empty())
            result.sharing_ids = promotion.promoted_sharing_ids;

        if (promotion.valid
                && (promotion.action
                    == AuthenticationPromotionAction::
                        promoted_checkpoint
                    || promotion.action
                        == AuthenticationPromotionAction::
                            already_authenticated))
            return finish(
                    SegmentRecoveryApplicationAction::
                        promoted_checkpoint);

        result.state_updated = false;
        return finish(SegmentRecoveryApplicationAction::inconsistent_state);
    }

    case SegmentRecoveryDecisionAction::
            would_complete_authenticated_segment:
    {
        if (not segment_lifecycle.initialized
                || segment_lifecycle.current_segment_id
                    != decision.segment_id
                || segment_lifecycle.current_output_checkpoint_id
                    != decision.checkpoint_id)
            return finish(
                    SegmentRecoveryApplicationAction::
                        inconsistent_state);

#ifndef NDEBUG
        called_completion_helper = true;
#endif
        auto completion =
                complete_current_segment_if_checkpoint_authenticated();
        result.completion_action = completion.action;
        result.state_updated = completion.state_updated;
        result.sharing_ids = completion.sharing_ids;

        if (completion.valid
                && completion.action
                    == SegmentCompletionReadinessAction::ready
                && completion.state_updated)
            return finish(
                    SegmentRecoveryApplicationAction::
                        completed_authenticated_segment);

        if (completion.valid
                && completion.action
                    == SegmentCompletionReadinessAction::
                        already_completed)
        {
            result.state_updated = false;
            return finish(SegmentRecoveryApplicationAction::no_action);
        }

        result.state_updated = false;
        return finish(SegmentRecoveryApplicationAction::inconsistent_state);
    }

    case SegmentRecoveryDecisionAction::
            would_enqueue_analyze_requests:
    {
#ifndef NDEBUG
        called_enqueue_helper = true;
#endif
        auto enqueue =
                enqueue_authentication_analyze_requests_for_checkpoint(
                        decision.checkpoint_id);
        result.enqueue_action = enqueue.action;
        result.state_updated = enqueue.state_updated;
        result.sharing_ids = enqueue.sharing_ids;
        result.pending_request_ids = enqueue.pending_request_ids;

        if (enqueue.valid
                && enqueue.action
                    == AuthenticationAnalyzeEnqueueAction::
                        enqueued_requests
                && enqueue.state_updated)
            return finish(
                    SegmentRecoveryApplicationAction::
                        enqueued_analyze_requests);

        if (enqueue.valid
                && enqueue.action
                    == AuthenticationAnalyzeEnqueueAction::
                        already_enqueued)
        {
            result.state_updated = false;
            return finish(SegmentRecoveryApplicationAction::no_action);
        }

        result.state_updated = false;
        return finish(SegmentRecoveryApplicationAction::inconsistent_state);
    }

    case SegmentRecoveryDecisionAction::already_completed:
        return finish(
                SegmentRecoveryApplicationAction::already_completed);

    case SegmentRecoveryDecisionAction::no_open_segment:
    case SegmentRecoveryDecisionAction::wait_for_checkpoint:
    case SegmentRecoveryDecisionAction::wait_for_authentication_request:
    case SegmentRecoveryDecisionAction::wait_for_authentication_material:
    case SegmentRecoveryDecisionAction::holder_share_unavailable:
    case SegmentRecoveryDecisionAction::insufficient_votes:
        return finish(SegmentRecoveryApplicationAction::waiting);

    case SegmentRecoveryDecisionAction::inconsistent_state:
        return finish(
                SegmentRecoveryApplicationAction::inconsistent_state);

    case SegmentRecoveryDecisionAction::none:
        break;
    }

    return finish(SegmentRecoveryApplicationAction::inconsistent_state);
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
void AtlasGsz<T>::validate_authentication_decision_outcome(
        const AuthenticationDecisionOutcome& outcome) const
{
    assert(outcome.valid);
    assert(outcome.action != AuthenticationDecisionOutcomeAction::none);
    assert(outcome.checkpoint_status
            != AuthenticationCheckpointDecisionStatus::none);
    assert(outcome.checkpoint_id != 0);
    assert(0 <= outcome.expected_sharings);
    assert(0 <= outcome.accepted_sharings);
    assert(0 <= outcome.rejected_sharings);
    assert(0 <= outcome.not_ready_sharings);
    assert(0 <= outcome.unavailable_sharings);
    assert(0 <= outcome.insufficient_sharings);
    assert(outcome.rejected_sharings
            == int(outcome.rejected_sharing_ids.size()));

    int total_sharings =
            outcome.accepted_sharings + outcome.rejected_sharings
            + outcome.not_ready_sharings + outcome.unavailable_sharings
            + outcome.insufficient_sharings;
    assert(total_sharings == int(outcome.sharing_ids.size()));

    const auto decision =
            authentication_checkpoint_decision(outcome.checkpoint_id);
    validate_authentication_checkpoint_decision(decision);
    assert(outcome.checkpoint_status == decision.status);
    assert(outcome.segment_id == decision.segment_id);
    assert(outcome.expected_sharings == decision.expected_sharings);
    assert(outcome.accepted_sharings == decision.accepted_sharings);
    assert(outcome.rejected_sharings == decision.rejected_sharings);
    assert(outcome.not_ready_sharings == decision.not_ready_sharings);
    assert(outcome.unavailable_sharings == decision.unavailable_sharings);
    assert(outcome.insufficient_sharings == decision.insufficient_sharings);
    assert(outcome.sharing_ids == decision.sharing_ids);
    assert(outcome.rejected_sharing_ids
            == decision.rejected_sharing_ids);
    assert(outcome.rejected_holder_ids == decision.rejected_holder_ids);

    for (auto sharing_id : outcome.rejected_sharing_ids)
        assert(std::find(outcome.sharing_ids.begin(),
                outcome.sharing_ids.end(), sharing_id)
                != outcome.sharing_ids.end());

    for (auto holder : outcome.rejected_holder_ids)
    {
        assert(0 <= holder);
        assert(holder < P.num_players());
        assert(is_active_party(holder));
    }

    int control_flags =
            int(outcome.would_accept_checkpoint)
            + int(outcome.would_reject_checkpoint)
            + int(outcome.needs_more_authentication_material)
            + int(outcome.has_unavailable_holder_share)
            + int(outcome.has_insufficient_votes);
    assert(control_flags == 1);

    switch (outcome.action)
    {
    case AuthenticationDecisionOutcomeAction::accept_checkpoint:
        assert(outcome.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::accepted);
        assert(outcome.would_accept_checkpoint);
        assert(not outcome.would_reject_checkpoint);
        assert(not outcome.needs_more_authentication_material);
        assert(not outcome.has_unavailable_holder_share);
        assert(not outcome.has_insufficient_votes);
        assert(outcome.rejected_sharing_ids.empty());
        assert(outcome.rejected_holder_ids.empty());
        break;
    case AuthenticationDecisionOutcomeAction::reject_checkpoint:
        assert(outcome.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::rejected);
        assert(not outcome.would_accept_checkpoint);
        assert(outcome.would_reject_checkpoint);
        assert(not outcome.needs_more_authentication_material);
        assert(not outcome.has_unavailable_holder_share);
        assert(not outcome.has_insufficient_votes);
        assert(outcome.rejected_sharings > 0);
        assert(not outcome.rejected_sharing_ids.empty());
        break;
    case AuthenticationDecisionOutcomeAction::wait_for_material:
        assert(outcome.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::not_ready);
        assert(not outcome.would_accept_checkpoint);
        assert(not outcome.would_reject_checkpoint);
        assert(outcome.needs_more_authentication_material);
        assert(not outcome.has_unavailable_holder_share);
        assert(not outcome.has_insufficient_votes);
        break;
    case AuthenticationDecisionOutcomeAction::holder_share_unavailable:
        assert(outcome.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::
                    holder_share_unavailable);
        assert(not outcome.would_accept_checkpoint);
        assert(not outcome.would_reject_checkpoint);
        assert(not outcome.needs_more_authentication_material);
        assert(outcome.has_unavailable_holder_share);
        assert(not outcome.has_insufficient_votes);
        break;
    case AuthenticationDecisionOutcomeAction::insufficient_votes:
        assert(outcome.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::
                    insufficient_votes);
        assert(not outcome.would_accept_checkpoint);
        assert(not outcome.would_reject_checkpoint);
        assert(not outcome.needs_more_authentication_material);
        assert(not outcome.has_unavailable_holder_share);
        assert(outcome.has_insufficient_votes);
        break;
    case AuthenticationDecisionOutcomeAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_outcome_hook_result(
        const AuthenticationOutcomeHookResult& result) const
{
    assert(result.valid);
    assert(result.action != AuthenticationOutcomeHookAction::none);
    assert(result.outcome_action
            != AuthenticationDecisionOutcomeAction::none);
    assert(result.checkpoint_status
            != AuthenticationCheckpointDecisionStatus::none);
    assert(result.checkpoint_id != 0);
    assert(not result.performed_action);

    auto outcome = authentication_decision_outcome_for_checkpoint(
            result.checkpoint_id);
    validate_authentication_decision_outcome(outcome);
    assert(result.outcome_action == outcome.action);
    assert(result.checkpoint_status == outcome.checkpoint_status);
    assert(result.segment_id == outcome.segment_id);
    assert(result.sharing_ids == outcome.sharing_ids);
    assert(result.rejected_sharing_ids
            == outcome.rejected_sharing_ids);
    assert(result.rejected_holder_ids == outcome.rejected_holder_ids);

    int would_flags =
            int(result.would_wait)
            + int(result.would_accept)
            + int(result.would_reject)
            + int(result.would_need_recovery)
            + int(result.would_report_insufficient);
    assert(would_flags == 1);

    assert(result.would_accept
            == (result.action
                == AuthenticationOutcomeHookAction::
                    would_accept_checkpoint));
    assert(result.would_reject
            == (result.action
                == AuthenticationOutcomeHookAction::
                    would_reject_checkpoint));
    assert(result.would_wait
            == (result.action
                == AuthenticationOutcomeHookAction::
                    would_wait_for_material));
    assert(result.would_need_recovery
            == (result.action
                == AuthenticationOutcomeHookAction::
                    would_request_holder_share_recovery));
    assert(result.would_report_insufficient
            == (result.action
                == AuthenticationOutcomeHookAction::
                    would_report_insufficient_votes));

    for (auto sharing_id : result.rejected_sharing_ids)
        assert(std::find(result.sharing_ids.begin(),
                result.sharing_ids.end(), sharing_id)
                != result.sharing_ids.end());

    for (auto holder : result.rejected_holder_ids)
    {
        assert(0 <= holder);
        assert(holder < P.num_players());
        assert(is_active_party(holder));
    }

    switch (result.action)
    {
    case AuthenticationOutcomeHookAction::would_accept_checkpoint:
        assert(result.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    accept_checkpoint);
        assert(result.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::accepted);
        assert(result.rejected_sharing_ids.empty());
        assert(result.rejected_holder_ids.empty());
        break;
    case AuthenticationOutcomeHookAction::would_reject_checkpoint:
        assert(result.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    reject_checkpoint);
        assert(result.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::rejected);
        assert(not result.rejected_sharing_ids.empty());
        assert(not result.rejected_holder_ids.empty());
        break;
    case AuthenticationOutcomeHookAction::would_wait_for_material:
        assert(result.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    wait_for_material);
        assert(result.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::not_ready);
        assert(result.rejected_sharing_ids.empty());
        assert(result.rejected_holder_ids.empty());
        break;
    case AuthenticationOutcomeHookAction::would_request_holder_share_recovery:
        assert(result.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    holder_share_unavailable);
        assert(result.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::
                    holder_share_unavailable);
        assert(result.rejected_sharing_ids.empty());
        assert(result.rejected_holder_ids.empty());
        break;
    case AuthenticationOutcomeHookAction::would_report_insufficient_votes:
        assert(result.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    insufficient_votes);
        assert(result.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::
                    insufficient_votes);
        assert(result.rejected_sharing_ids.empty());
        assert(result.rejected_holder_ids.empty());
        break;
    case AuthenticationOutcomeHookAction::no_action:
    case AuthenticationOutcomeHookAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_promotion_result(
        const AuthenticationPromotionResult& result) const
{
    assert(result.valid);
    assert(result.action != AuthenticationPromotionAction::none);
    assert(result.checkpoint_id != 0);

    const CheckpointRecord* checkpoint = 0;
    if (verifiable_registry.initialized)
        for (const auto& candidate : verifiable_registry.checkpoints)
            if (candidate.checkpoint_id == result.checkpoint_id)
            {
                checkpoint = &candidate;
                break;
            }
    assert(checkpoint != 0);
    assert(result.segment_id == checkpoint->segment_id);

    for (size_t i = 0; i < result.promoted_sharing_ids.size(); i++)
    {
        auto sharing_id = result.promoted_sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->checkpoint_id == result.checkpoint_id);
        assert(sharing->segment_id == result.segment_id);
        assert(std::find(checkpoint->sharing_ids.begin(),
                checkpoint->sharing_ids.end(), sharing_id)
                != checkpoint->sharing_ids.end());

        for (size_t j = i + 1;
                j < result.promoted_sharing_ids.size(); j++)
            assert(sharing_id != result.promoted_sharing_ids.at(j));
    }

    for (size_t i = 0; i < result.authentication_record_ids.size(); i++)
    {
        auto record_id = result.authentication_record_ids.at(i);
        const auto* record = find_authentication_plan_record(record_id);
        assert(record != 0);
        assert(record->checkpoint_id == result.checkpoint_id);
        assert(record->segment_id == result.segment_id);
        assert(record->kind
                == AuthenticationRecordKind::checkpoint_output_share);
        assert(std::find(checkpoint->sharing_ids.begin(),
                checkpoint->sharing_ids.end(), record->sharing_id)
                != checkpoint->sharing_ids.end());

        for (size_t j = i + 1;
                j < result.authentication_record_ids.size(); j++)
            assert(record_id != result.authentication_record_ids.at(j));
    }

    switch (result.action)
    {
    case AuthenticationPromotionAction::already_authenticated:
        assert(checkpoint->authenticated);
        assert(not result.state_updated);
        assert(result.promoted_sharing_ids.empty());
        assert(not result.authentication_record_ids.empty());
        assert(checkpoint_authentication_plan_complete(
                result.checkpoint_id));
        for (auto sharing_id : checkpoint->sharing_ids)
        {
            const auto* sharing = find_registered_sharing(sharing_id);
            assert(sharing != 0);
            assert(sharing->status
                    == VerifiableSharingStatus::authenticated);
        }
        break;

    case AuthenticationPromotionAction::promoted_checkpoint:
        assert(checkpoint->authenticated);
        assert(result.state_updated);
        assert(result.promoted_sharing_ids == checkpoint->sharing_ids);
        assert(not result.authentication_record_ids.empty());
        assert(checkpoint_authentication_plan_complete(
                result.checkpoint_id));
        for (auto sharing_id : checkpoint->sharing_ids)
        {
            const auto* sharing = find_registered_sharing(sharing_id);
            assert(sharing != 0);
            assert(sharing->status
                    == VerifiableSharingStatus::authenticated);
        }
        break;

    case AuthenticationPromotionAction::not_accepted:
        assert(not result.state_updated);
        assert(result.promoted_sharing_ids.empty());
        assert(result.authentication_record_ids.empty());
        break;

    case AuthenticationPromotionAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_segment_completion_readiness_result(
        const SegmentCompletionReadinessResult& result) const
{
    assert(result.valid);
    assert(result.action != SegmentCompletionReadinessAction::none);
    assert(result.ready
            == (result.action == SegmentCompletionReadinessAction::ready));
    if (result.state_updated)
        assert(result.action == SegmentCompletionReadinessAction::ready);

    auto find_checkpoint = [&](uint64_t id)
        -> const CheckpointRecord*
    {
        if (id == 0 || not verifiable_registry.initialized)
            return 0;
        for (const auto& checkpoint : verifiable_registry.checkpoints)
            if (checkpoint.checkpoint_id == id)
                return &checkpoint;
        return 0;
    };

    const auto* checkpoint = find_checkpoint(result.checkpoint_id);

    if (result.action
            == SegmentCompletionReadinessAction::no_open_segment)
    {
        assert(not result.ready);
        assert(not result.state_updated);
        assert(result.sharing_ids.empty());
        assert(result.authentication_record_ids.empty());
        return;
    }

    if (result.action
            == SegmentCompletionReadinessAction::
                missing_output_checkpoint)
    {
        assert(result.segment_id != 0);
        assert(not result.ready);
        assert(not result.state_updated);
        assert(result.sharing_ids.empty());
        assert(result.authentication_record_ids.empty());
        return;
    }

    assert(result.segment_id != 0);
    assert(result.checkpoint_id != 0);
    assert(checkpoint != 0);
    assert(checkpoint->segment_id == result.segment_id);
    assert(result.sharing_ids == checkpoint->sharing_ids);

    bool all_checkpoint_output_sharings = true;
    bool all_checkpoint_sharings_authenticated = true;
    for (size_t i = 0; i < result.sharing_ids.size(); i++)
    {
        auto sharing_id = result.sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->checkpoint_id == result.checkpoint_id);
        assert(sharing->segment_id == result.segment_id);
        if (sharing->kind != RegisteredSharingKind::checkpoint_output)
            all_checkpoint_output_sharings = false;
        if (sharing->status
                != VerifiableSharingStatus::authenticated)
            all_checkpoint_sharings_authenticated = false;

        for (size_t j = i + 1; j < result.sharing_ids.size(); j++)
            assert(sharing_id != result.sharing_ids.at(j));
    }
    assert(all_checkpoint_output_sharings);

    for (size_t i = 0; i < result.authentication_record_ids.size(); i++)
    {
        auto record_id = result.authentication_record_ids.at(i);
        const auto* record = find_authentication_plan_record(record_id);
        assert(record != 0);
        assert(record->checkpoint_id == result.checkpoint_id);
        assert(record->segment_id == result.segment_id);
        assert(record->kind
                == AuthenticationRecordKind::checkpoint_output_share);
        assert(std::find(result.sharing_ids.begin(),
                result.sharing_ids.end(), record->sharing_id)
                != result.sharing_ids.end());

        for (size_t j = i + 1;
                j < result.authentication_record_ids.size(); j++)
            assert(record_id != result.authentication_record_ids.at(j));
    }

    switch (result.action)
    {
    case SegmentCompletionReadinessAction::checkpoint_still_open:
        assert(segment_lifecycle.initialized);
        assert(segment_lifecycle.segment_open);
        assert(segment_lifecycle.checkpoint_open);
        assert(segment_lifecycle.current_segment_id
                == result.segment_id);
        assert(segment_lifecycle.current_output_checkpoint_id
                == result.checkpoint_id);
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::checkpoint_not_sealed:
        assert(segment_lifecycle.initialized);
        assert(segment_lifecycle.segment_open);
        assert(not segment_lifecycle.checkpoint_open);
        assert(not checkpoint->sealed);
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::
            authentication_not_requested:
        assert(segment_lifecycle.initialized);
        assert(segment_lifecycle.segment_open);
        assert(not segment_lifecycle.checkpoint_open);
        assert(checkpoint->sealed);
        assert(not checkpoint->authentication_requested);
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::
            authentication_records_missing:
        assert(checkpoint->sealed);
        assert(checkpoint->authentication_requested);
        assert(result.authentication_record_ids.empty());
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::
            authentication_incomplete:
        assert(checkpoint->sealed);
        assert(checkpoint->authentication_requested);
        assert(not result.authentication_record_ids.empty());
        assert(not checkpoint_authentication_plan_complete(
                result.checkpoint_id));
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::
            checkpoint_not_authenticated:
        assert(checkpoint->sealed);
        assert(checkpoint->authentication_requested);
        assert(not result.authentication_record_ids.empty());
        assert(checkpoint_authentication_plan_complete(
                result.checkpoint_id));
        assert(not checkpoint->authenticated
                || not all_checkpoint_sharings_authenticated);
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::ready:
        assert(checkpoint->sealed);
        assert(checkpoint->authentication_requested);
        assert(not result.authentication_record_ids.empty());
        assert(checkpoint_authentication_plan_complete(
                result.checkpoint_id));
        assert(checkpoint->authenticated);
        assert(all_checkpoint_sharings_authenticated);
        if (result.state_updated)
        {
            assert(segment_lifecycle.initialized);
            assert(not segment_lifecycle.segment_open);
            assert(not segment_lifecycle.checkpoint_open);
            assert(segment_lifecycle.current_segment_id
                    == result.segment_id);
            assert(segment_lifecycle.last_completed_segment_id
                    == result.segment_id);
            assert(segment_lifecycle.current_output_checkpoint_id
                    == result.checkpoint_id);
        }
        else if (segment_lifecycle.initialized
                && segment_lifecycle.current_segment_id
                    == result.segment_id)
        {
            assert(segment_lifecycle.segment_open);
            assert(not segment_lifecycle.checkpoint_open);
            assert(segment_lifecycle.current_output_checkpoint_id
                    == result.checkpoint_id);
        }
        break;

    case SegmentCompletionReadinessAction::already_completed:
        assert(segment_lifecycle.initialized);
        assert(not segment_lifecycle.segment_open);
        assert(not segment_lifecycle.checkpoint_open);
        assert(segment_lifecycle.current_segment_id
                == result.segment_id);
        assert(segment_lifecycle.last_completed_segment_id
                == result.segment_id);
        assert(segment_lifecycle.current_output_checkpoint_id
                == result.checkpoint_id);
        assert(checkpoint->authenticated);
        assert(not result.authentication_record_ids.empty());
        assert(checkpoint_authentication_plan_complete(
                result.checkpoint_id));
        assert(all_checkpoint_sharings_authenticated);
        assert(not result.ready);
        assert(not result.state_updated);
        break;

    case SegmentCompletionReadinessAction::no_open_segment:
    case SegmentCompletionReadinessAction::missing_output_checkpoint:
    case SegmentCompletionReadinessAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_analyze_plan_entry(
        const AuthenticationAnalyzeSharingPlanEntry& entry) const
{
    assert(entry.valid);
    assert(entry.sharing_id != 0);
    assert(entry.checkpoint_id != 0);
    assert(entry.sharing_status
            == AuthenticationSharingDecisionStatus::rejected);
    assert(entry.kind != AuthenticationRecordKind::none);
    assert(entry.would_analyze_sharing);
    assert(not entry.performed_action);
    assert(not entry.rejected_holder_ids.empty());

    const auto* sharing = find_registered_sharing(entry.sharing_id);
    assert(sharing != 0);
    assert(entry.checkpoint_id == sharing->checkpoint_id);
    assert(entry.segment_id == sharing->segment_id);

    auto sharing_decision =
            authentication_sharing_decision(entry.sharing_id);
    validate_authentication_sharing_decision(sharing_decision);
    assert(sharing_decision.status
            == AuthenticationSharingDecisionStatus::rejected);
    assert(entry.checkpoint_id == sharing_decision.checkpoint_id);
    assert(entry.segment_id == sharing_decision.segment_id);
    assert(entry.kind == sharing_decision.kind);
    assert(entry.rejected_holder_ids
            == sharing_decision.rejected_holder_ids);

    for (size_t i = 0; i < entry.rejected_holder_ids.size(); i++)
    {
        int holder = entry.rejected_holder_ids.at(i);
        assert(0 <= holder);
        assert(holder < P.num_players());
        assert(is_active_party(holder));
        for (size_t j = i + 1; j < entry.rejected_holder_ids.size(); j++)
            assert(holder != entry.rejected_holder_ids.at(j));
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_analyze_sharing_plan(
        const AuthenticationAnalyzeSharingPlan& plan) const
{
    assert(plan.valid);
    assert(plan.action != AuthenticationAnalyzePlanAction::none);
    assert(plan.hook_action != AuthenticationOutcomeHookAction::none);
    assert(plan.outcome_action
            != AuthenticationDecisionOutcomeAction::none);
    assert(plan.checkpoint_status
            != AuthenticationCheckpointDecisionStatus::none);
    assert(plan.checkpoint_id != 0);
    assert(not plan.performed_action);

    auto hook_result = inspect_authentication_outcome_hook_for_checkpoint(
            plan.checkpoint_id);
    validate_authentication_outcome_hook_result(hook_result);
    assert(plan.hook_action == hook_result.action);
    assert(plan.outcome_action == hook_result.outcome_action);
    assert(plan.checkpoint_status == hook_result.checkpoint_status);
    assert(plan.segment_id == hook_result.segment_id);
    assert(plan.sharing_ids == hook_result.sharing_ids);
    assert(plan.rejected_sharing_ids
            == hook_result.rejected_sharing_ids);
    assert(plan.rejected_holder_ids == hook_result.rejected_holder_ids);

    for (auto sharing_id : plan.rejected_sharing_ids)
        assert(std::find(plan.sharing_ids.begin(),
                plan.sharing_ids.end(), sharing_id)
                != plan.sharing_ids.end());

    for (auto holder : plan.rejected_holder_ids)
    {
        assert(0 <= holder);
        assert(holder < P.num_players());
        assert(is_active_party(holder));
    }

    switch (plan.action)
    {
    case AuthenticationAnalyzePlanAction::would_analyze_rejected_sharings:
        assert(plan.hook_action
                == AuthenticationOutcomeHookAction::
                    would_reject_checkpoint);
        assert(plan.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    reject_checkpoint);
        assert(plan.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::rejected);
        assert(plan.would_create_analyze_requests);
        assert(not plan.rejected_sharing_ids.empty());
        assert(not plan.rejected_holder_ids.empty());
        assert(plan.entries.size()
                == plan.rejected_sharing_ids.size());
        for (size_t i = 0; i < plan.entries.size(); i++)
        {
            const auto& entry = plan.entries.at(i);
            validate_authentication_analyze_plan_entry(entry);
            assert(entry.checkpoint_id == plan.checkpoint_id);
            assert(entry.segment_id == plan.segment_id);
            assert(std::find(plan.rejected_sharing_ids.begin(),
                    plan.rejected_sharing_ids.end(),
                    entry.sharing_id) != plan.rejected_sharing_ids.end());
            for (size_t j = i + 1; j < plan.entries.size(); j++)
                assert(entry.sharing_id
                        != plan.entries.at(j).sharing_id);
        }
        break;
    case AuthenticationAnalyzePlanAction::no_action:
        assert(plan.hook_action
                == AuthenticationOutcomeHookAction::
                    would_accept_checkpoint);
        assert(plan.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    accept_checkpoint);
        assert(plan.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::accepted);
        assert(not plan.would_create_analyze_requests);
        assert(plan.rejected_sharing_ids.empty());
        assert(plan.rejected_holder_ids.empty());
        assert(plan.entries.empty());
        break;
    case AuthenticationAnalyzePlanAction::wait_for_material:
        assert(plan.hook_action
                == AuthenticationOutcomeHookAction::
                    would_wait_for_material);
        assert(plan.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    wait_for_material);
        assert(plan.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::not_ready);
        assert(not plan.would_create_analyze_requests);
        assert(plan.rejected_sharing_ids.empty());
        assert(plan.rejected_holder_ids.empty());
        assert(plan.entries.empty());
        break;
    case AuthenticationAnalyzePlanAction::holder_share_unavailable:
        assert(plan.hook_action
                == AuthenticationOutcomeHookAction::
                    would_request_holder_share_recovery);
        assert(plan.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    holder_share_unavailable);
        assert(plan.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::
                    holder_share_unavailable);
        assert(not plan.would_create_analyze_requests);
        assert(plan.rejected_sharing_ids.empty());
        assert(plan.rejected_holder_ids.empty());
        assert(plan.entries.empty());
        break;
    case AuthenticationAnalyzePlanAction::insufficient_votes:
        assert(plan.hook_action
                == AuthenticationOutcomeHookAction::
                    would_report_insufficient_votes);
        assert(plan.outcome_action
                == AuthenticationDecisionOutcomeAction::
                    insufficient_votes);
        assert(plan.checkpoint_status
                == AuthenticationCheckpointDecisionStatus::
                    insufficient_votes);
        assert(not plan.would_create_analyze_requests);
        assert(plan.rejected_sharing_ids.empty());
        assert(plan.rejected_holder_ids.empty());
        assert(plan.entries.empty());
        break;
    case AuthenticationAnalyzePlanAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_authentication_analyze_enqueue_result(
        const AuthenticationAnalyzeEnqueueResult& result) const
{
    assert(result.valid);
    assert(result.action != AuthenticationAnalyzeEnqueueAction::none);
    assert(result.checkpoint_id != 0);

    const CheckpointRecord* checkpoint = 0;
    if (verifiable_registry.initialized)
        for (const auto& candidate : verifiable_registry.checkpoints)
            if (candidate.checkpoint_id == result.checkpoint_id)
            {
                checkpoint = &candidate;
                break;
            }
    assert(checkpoint != 0);
    assert(result.segment_id == checkpoint->segment_id);

    for (size_t i = 0; i < result.sharing_ids.size(); i++)
    {
        auto sharing_id = result.sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        assert(sharing->checkpoint_id == result.checkpoint_id);
        assert(sharing->segment_id == result.segment_id);
        assert(std::find(checkpoint->sharing_ids.begin(),
                checkpoint->sharing_ids.end(), sharing_id)
                != checkpoint->sharing_ids.end());

        for (size_t j = i + 1; j < result.sharing_ids.size(); j++)
            assert(sharing_id != result.sharing_ids.at(j));
    }

    for (size_t i = 0; i < result.pending_request_ids.size(); i++)
    {
        auto request_id = result.pending_request_ids.at(i);
        const auto* request =
                find_pending_analyze_sharing_request(request_id);
        assert(request != 0);
        assert(request->source
                == PendingAnalyzeSharingSource::
                    authentication_rejection);
        assert(request->target
                == PendingAnalyzeSharingTarget::
                    registered_checkpoint_output_sharing);
        assert(request->checkpoint_id == result.checkpoint_id);
        assert(request->segment_id == result.segment_id);
        assert(std::find(result.sharing_ids.begin(),
                result.sharing_ids.end(), request->sharing_id)
                != result.sharing_ids.end());

        for (size_t j = i + 1;
                j < result.pending_request_ids.size(); j++)
            assert(request_id != result.pending_request_ids.at(j));
    }

    switch (result.action)
    {
    case AuthenticationAnalyzeEnqueueAction::no_action:
        assert(not result.state_updated);
        assert(result.sharing_ids.empty());
        assert(result.pending_request_ids.empty());
        break;

    case AuthenticationAnalyzeEnqueueAction::not_rejected:
        assert(not result.state_updated);
        assert(result.sharing_ids.empty());
        assert(result.pending_request_ids.empty());
        break;

    case AuthenticationAnalyzeEnqueueAction::no_analyze_candidates:
        assert(not result.state_updated);
        assert(result.sharing_ids.empty());
        assert(result.pending_request_ids.empty());
        break;

    case AuthenticationAnalyzeEnqueueAction::enqueued_requests:
        assert(result.state_updated);
        assert(not result.sharing_ids.empty());
        assert(result.pending_request_ids.size()
                == result.sharing_ids.size());
        break;

    case AuthenticationAnalyzeEnqueueAction::already_enqueued:
        assert(not result.state_updated);
        assert(not result.sharing_ids.empty());
        assert(result.pending_request_ids.size()
                == result.sharing_ids.size());
        break;

    case AuthenticationAnalyzeEnqueueAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_segment_recovery_decision_result(
        const SegmentRecoveryDecisionResult& result) const
{
    assert(result.valid);
    assert(result.action != SegmentRecoveryDecisionAction::none);
    assert(not result.state_updated);

    const CheckpointRecord* checkpoint = 0;
    if (result.checkpoint_id != 0)
    {
        if (verifiable_registry.initialized)
            for (const auto& candidate : verifiable_registry.checkpoints)
                if (candidate.checkpoint_id == result.checkpoint_id)
                {
                    checkpoint = &candidate;
                    break;
                }
        assert(checkpoint != 0);
        assert(result.segment_id == checkpoint->segment_id);
        assert(result.checkpoint_authenticated
                == checkpoint->authenticated);
    }

    for (size_t i = 0; i < result.sharing_ids.size(); i++)
    {
        auto sharing_id = result.sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        if (result.checkpoint_id != 0)
        {
            assert(sharing->checkpoint_id == result.checkpoint_id);
            assert(sharing->segment_id == result.segment_id);
            assert(checkpoint != 0);
            assert(std::find(checkpoint->sharing_ids.begin(),
                    checkpoint->sharing_ids.end(), sharing_id)
                    != checkpoint->sharing_ids.end());
        }

        for (size_t j = i + 1; j < result.sharing_ids.size(); j++)
            assert(sharing_id != result.sharing_ids.at(j));
    }

    for (size_t i = 0; i < result.rejected_sharing_ids.size(); i++)
    {
        auto sharing_id = result.rejected_sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(result.checkpoint_id != 0);
        assert(checkpoint != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        assert(sharing->checkpoint_id == result.checkpoint_id);
        assert(sharing->segment_id == result.segment_id);
        assert(std::find(checkpoint->sharing_ids.begin(),
                checkpoint->sharing_ids.end(), sharing_id)
                != checkpoint->sharing_ids.end());
        assert(std::find(result.sharing_ids.begin(),
                result.sharing_ids.end(), sharing_id)
                != result.sharing_ids.end());

        for (size_t j = i + 1;
                j < result.rejected_sharing_ids.size(); j++)
            assert(sharing_id != result.rejected_sharing_ids.at(j));
    }

    for (size_t i = 0; i < result.pending_request_ids.size(); i++)
    {
        auto request_id = result.pending_request_ids.at(i);
        const auto* request =
                find_pending_analyze_sharing_request(request_id);
        assert(request != 0);
        assert(request->source
                == PendingAnalyzeSharingSource::
                    authentication_rejection);
        assert(request->target
                == PendingAnalyzeSharingTarget::
                    registered_checkpoint_output_sharing);
        assert(request->checkpoint_id == result.checkpoint_id);
        assert(request->segment_id == result.segment_id);
        assert(std::find(result.rejected_sharing_ids.begin(),
                result.rejected_sharing_ids.end(), request->sharing_id)
                != result.rejected_sharing_ids.end());

        for (size_t j = i + 1;
                j < result.pending_request_ids.size(); j++)
            assert(request_id != result.pending_request_ids.at(j));
    }

    switch (result.action)
    {
    case SegmentRecoveryDecisionAction::no_open_segment:
        assert(result.segment_readiness_action
                == SegmentCompletionReadinessAction::no_open_segment
                || result.segment_readiness_action
                    == SegmentCompletionReadinessAction::none);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::none);
        assert(result.analyze_plan_action
                == AuthenticationAnalyzePlanAction::none);
        assert(result.rejected_sharing_ids.empty());
        assert(result.pending_request_ids.empty());
        break;

    case SegmentRecoveryDecisionAction::wait_for_checkpoint:
        assert(result.segment_readiness_action
                == SegmentCompletionReadinessAction::
                    missing_output_checkpoint
                || result.segment_readiness_action
                    == SegmentCompletionReadinessAction::
                        checkpoint_still_open
                || result.segment_readiness_action
                    == SegmentCompletionReadinessAction::
                        checkpoint_not_sealed);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::none);
        assert(result.analyze_plan_action
                == AuthenticationAnalyzePlanAction::none);
        break;

    case SegmentRecoveryDecisionAction::
            wait_for_authentication_request:
        assert(result.segment_readiness_action
                == SegmentCompletionReadinessAction::
                    authentication_not_requested);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::none);
        break;

    case SegmentRecoveryDecisionAction::
            wait_for_authentication_material:
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::
                    would_wait_for_material);
        assert(result.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    wait_for_material);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::holder_share_unavailable:
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::
                    would_request_holder_share_recovery);
        assert(result.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    holder_share_unavailable);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::insufficient_votes:
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::
                    would_report_insufficient_votes);
        assert(result.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    insufficient_votes);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::would_promote_checkpoint:
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::
                    would_accept_checkpoint);
        assert(result.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    accept_checkpoint);
        assert(result.checkpoint_promotion_ready);
        assert(not result.checkpoint_authenticated);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::
            would_complete_authenticated_segment:
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::
                    would_accept_checkpoint);
        assert(result.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    accept_checkpoint);
        assert(result.checkpoint_authenticated);
        assert(result.segment_completion_ready);
        assert(result.segment_readiness_action
                == SegmentCompletionReadinessAction::ready);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::
            would_enqueue_analyze_requests:
        assert(result.authentication_hook_action
                == AuthenticationOutcomeHookAction::
                    would_reject_checkpoint);
        assert(result.authentication_outcome_action
                == AuthenticationDecisionOutcomeAction::
                    reject_checkpoint);
        assert(result.analyze_plan_action
                == AuthenticationAnalyzePlanAction::
                    would_analyze_rejected_sharings);
        assert(result.analyze_enqueue_ready);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.rejected_sharing_ids.empty());
        break;

    case SegmentRecoveryDecisionAction::already_completed:
        assert(result.segment_readiness_action
                == SegmentCompletionReadinessAction::already_completed);
        assert(result.checkpoint_authenticated);
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::inconsistent_state:
        assert(not result.checkpoint_promotion_ready);
        assert(not result.segment_completion_ready
                || result.segment_readiness_action
                    == SegmentCompletionReadinessAction::ready);
        assert(not result.analyze_enqueue_ready);
        break;

    case SegmentRecoveryDecisionAction::none:
        assert(false);
        break;
    }
}

template<class T>
void AtlasGsz<T>::validate_segment_recovery_application_result(
        const SegmentRecoveryApplicationResult& result) const
{
    assert(result.valid);
    assert(result.action != SegmentRecoveryApplicationAction::none);
    assert(result.decision_action != SegmentRecoveryDecisionAction::none);

    const CheckpointRecord* checkpoint = 0;
    if (result.checkpoint_id != 0)
    {
        if (verifiable_registry.initialized)
            for (const auto& candidate : verifiable_registry.checkpoints)
                if (candidate.checkpoint_id == result.checkpoint_id)
                {
                    checkpoint = &candidate;
                    break;
                }
        assert(checkpoint != 0);
        assert(result.segment_id == checkpoint->segment_id);
    }

    for (size_t i = 0; i < result.sharing_ids.size(); i++)
    {
        auto sharing_id = result.sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        if (result.checkpoint_id != 0)
        {
            assert(checkpoint != 0);
            assert(sharing->checkpoint_id == result.checkpoint_id);
            assert(sharing->segment_id == result.segment_id);
            assert(std::find(checkpoint->sharing_ids.begin(),
                    checkpoint->sharing_ids.end(), sharing_id)
                    != checkpoint->sharing_ids.end());
        }

        for (size_t j = i + 1; j < result.sharing_ids.size(); j++)
            assert(sharing_id != result.sharing_ids.at(j));
    }

    for (size_t i = 0; i < result.rejected_sharing_ids.size(); i++)
    {
        auto sharing_id = result.rejected_sharing_ids.at(i);
        const auto* sharing = find_registered_sharing(sharing_id);
        assert(sharing != 0);
        assert(sharing->kind == RegisteredSharingKind::checkpoint_output);
        assert(result.checkpoint_id != 0);
        assert(checkpoint != 0);
        assert(sharing->checkpoint_id == result.checkpoint_id);
        assert(sharing->segment_id == result.segment_id);
        assert(std::find(checkpoint->sharing_ids.begin(),
                checkpoint->sharing_ids.end(), sharing_id)
                != checkpoint->sharing_ids.end());
        assert(std::find(result.sharing_ids.begin(),
                result.sharing_ids.end(), sharing_id)
                != result.sharing_ids.end());

        for (size_t j = i + 1;
                j < result.rejected_sharing_ids.size(); j++)
            assert(sharing_id != result.rejected_sharing_ids.at(j));
    }

    for (size_t i = 0; i < result.pending_request_ids.size(); i++)
    {
        auto request_id = result.pending_request_ids.at(i);
        const auto* request =
                find_pending_analyze_sharing_request(request_id);
        assert(request != 0);
        assert(request->source
                == PendingAnalyzeSharingSource::
                    authentication_rejection);
        assert(request->target
                == PendingAnalyzeSharingTarget::
                    registered_checkpoint_output_sharing);
        assert(request->checkpoint_id == result.checkpoint_id);
        assert(request->segment_id == result.segment_id);
        assert(std::find(result.sharing_ids.begin(),
                result.sharing_ids.end(), request->sharing_id)
                != result.sharing_ids.end());
        if (not result.rejected_sharing_ids.empty())
            assert(std::find(result.rejected_sharing_ids.begin(),
                    result.rejected_sharing_ids.end(),
                    request->sharing_id)
                    != result.rejected_sharing_ids.end());

        for (size_t j = i + 1;
                j < result.pending_request_ids.size(); j++)
            assert(request_id != result.pending_request_ids.at(j));
    }

    switch (result.action)
    {
    case SegmentRecoveryApplicationAction::promoted_checkpoint:
        assert(result.decision_action
                == SegmentRecoveryDecisionAction::
                    would_promote_checkpoint);
        assert(result.promotion_action
                == AuthenticationPromotionAction::promoted_checkpoint
                || result.promotion_action
                    == AuthenticationPromotionAction::
                        already_authenticated);
        assert(result.completion_action
                == SegmentCompletionReadinessAction::none);
        assert(result.enqueue_action
                == AuthenticationAnalyzeEnqueueAction::none);
        assert(result.state_updated
                == (result.promotion_action
                    == AuthenticationPromotionAction::
                        promoted_checkpoint));
        break;

    case SegmentRecoveryApplicationAction::
            completed_authenticated_segment:
        assert(result.decision_action
                == SegmentRecoveryDecisionAction::
                    would_complete_authenticated_segment);
        assert(result.completion_action
                == SegmentCompletionReadinessAction::ready);
        assert(result.promotion_action
                == AuthenticationPromotionAction::none);
        assert(result.enqueue_action
                == AuthenticationAnalyzeEnqueueAction::none);
        assert(result.state_updated);
        break;

    case SegmentRecoveryApplicationAction::enqueued_analyze_requests:
        assert(result.decision_action
                == SegmentRecoveryDecisionAction::
                    would_enqueue_analyze_requests);
        assert(result.enqueue_action
                == AuthenticationAnalyzeEnqueueAction::
                    enqueued_requests);
        assert(result.promotion_action
                == AuthenticationPromotionAction::none);
        assert(result.completion_action
                == SegmentCompletionReadinessAction::none);
        assert(result.state_updated);
        assert(not result.pending_request_ids.empty());
        break;

    case SegmentRecoveryApplicationAction::already_completed:
        assert(result.decision_action
                == SegmentRecoveryDecisionAction::already_completed);
        assert(result.promotion_action
                == AuthenticationPromotionAction::none);
        assert(result.completion_action
                == SegmentCompletionReadinessAction::none);
        assert(result.enqueue_action
                == AuthenticationAnalyzeEnqueueAction::none);
        assert(not result.state_updated);
        break;

    case SegmentRecoveryApplicationAction::waiting:
        assert(result.decision_action
                == SegmentRecoveryDecisionAction::no_open_segment
                || result.decision_action
                    == SegmentRecoveryDecisionAction::
                        wait_for_checkpoint
                || result.decision_action
                    == SegmentRecoveryDecisionAction::
                        wait_for_authentication_request
                || result.decision_action
                    == SegmentRecoveryDecisionAction::
                        wait_for_authentication_material
                || result.decision_action
                    == SegmentRecoveryDecisionAction::
                        holder_share_unavailable
                || result.decision_action
                    == SegmentRecoveryDecisionAction::
                        insufficient_votes);
        assert(result.promotion_action
                == AuthenticationPromotionAction::none);
        assert(result.completion_action
                == SegmentCompletionReadinessAction::none);
        assert(result.enqueue_action
                == AuthenticationAnalyzeEnqueueAction::none);
        assert(not result.state_updated);
        break;

    case SegmentRecoveryApplicationAction::no_action:
        assert(not result.state_updated);
        if (result.decision_action
                == SegmentRecoveryDecisionAction::
                    would_enqueue_analyze_requests)
            assert(result.enqueue_action
                    == AuthenticationAnalyzeEnqueueAction::
                        already_enqueued);
        else if (result.decision_action
                == SegmentRecoveryDecisionAction::
                    would_complete_authenticated_segment)
            assert(result.completion_action
                    == SegmentCompletionReadinessAction::
                        already_completed);
        else
            assert(false);
        break;

    case SegmentRecoveryApplicationAction::inconsistent_state:
        assert(not result.state_updated);
        break;

    case SegmentRecoveryApplicationAction::none:
        assert(false);
        break;
    }
}

template<class T>
typename AtlasGsz<T>::DisputeControlUpdatePlan
AtlasGsz<T>::inspect_dispute_control_update_plan(
        const FaultLocalizationOutcome& outcome) const
{
#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_inspection = dispute_control_state.corr;
    auto disp_before_inspection = dispute_control_state.disp;
#endif

    DisputeControlUpdatePlan plan{};
    plan.valid = true;
    plan.fault_action = outcome.action;
    plan.source = outcome.source;
    plan.sharing_to_analyze = outcome.sharing_to_analyze;
    plan.corrupted_party = outcome.corrupted_party;
    plan.disputed_party_a = outcome.disputed_party_a;
    plan.disputed_party_b = outcome.disputed_party_b;
    plan.primary_party = outcome.primary_party;
    plan.counterparty = outcome.counterparty;

    auto finish = [&](DisputeControlUpdatePlanAction action)
            -> DisputeControlUpdatePlan
    {
        plan.action = action;
        validate_dispute_control_update_plan(plan);
#ifndef NDEBUG
        assert(dispute_control_state.initialized
                == dispute_state_was_initialized);
        assert(dispute_control_state.corr == corr_before_inspection);
        assert(dispute_control_state.disp == disp_before_inspection);
#endif
        return plan;
    };

    auto finish_inconsistent = [&]() -> DisputeControlUpdatePlan
    {
        plan.state_updated = false;
        plan.newly_corrupted_parties.clear();
        plan.newly_disputed_pairs.clear();
        return finish(DisputeControlUpdatePlanAction::inconsistent_state);
    };

    int n = P.num_players();
    int t = corruption_threshold();
    int threshold = t + 1;

    vector<bool> corr;
    vector<vector<bool>> disp;

    if (dispute_control_state.initialized)
    {
        bool shape_valid =
                dispute_control_state.corr.size() == size_t(n)
                && dispute_control_state.disp.size() == size_t(n);
        if (shape_valid)
            for (int i = 0; i < n; i++)
                shape_valid =
                        shape_valid
                        && dispute_control_state.disp.at(i).size()
                            == size_t(n);

#ifndef NDEBUG
        assert(shape_valid);
#endif
        if (not shape_valid)
            return finish_inconsistent();

        corr = dispute_control_state.corr;
        disp = dispute_control_state.disp;
    }
    else
    {
        corr.assign(n, false);
        disp.assign(n, vector<bool>(n, false));
    }

    auto party_in_range = [&](int party)
    {
        return 0 <= party && party < n;
    };

    auto local_dispute_count = [&](int party)
    {
        assert(party_in_range(party));
        int res = 0;
        for (int i = 0; i < n; i++)
            if (disp.at(party).at(i))
                res++;
        return res;
    };

    auto local_state_valid = [&]()
    {
        if (corr.size() != size_t(n) || disp.size() != size_t(n))
            return false;

        for (int i = 0; i < n; i++)
        {
            if (disp.at(i).size() != size_t(n))
                return false;
            if (disp.at(i).at(i))
                return false;
            for (int j = 0; j < n; j++)
                if (disp.at(i).at(j) != disp.at(j).at(i))
                    return false;
        }

        for (int i = 0; i < n; i++)
        {
            if (corr.at(i))
            {
                for (int j = 0; j < n; j++)
                    if (i != j && not disp.at(i).at(j))
                        return false;
            }
            else if (local_dispute_count(i) > t)
                return false;
        }

        return true;
    };

#ifndef NDEBUG
    assert(local_state_valid());
#endif
    if (not local_state_valid())
        return finish_inconsistent();

    auto local_is_active = [&](int party)
    {
        assert(party_in_range(party));
        return party_in_range(party) && not corr.at(party);
    };

    auto append_new_disputed_pair = [&](int a, int b)
    {
        assert(party_in_range(a));
        assert(party_in_range(b));
        assert(a != b);

        int x = min(a, b);
        int y = max(a, b);
        if (disp.at(x).at(y))
            return false;

        disp.at(x).at(y) = true;
        disp.at(y).at(x) = true;
        plan.newly_disputed_pairs.push_back(make_pair(x, y));
        plan.state_updated = true;
        return true;
    };

    auto mark_corrupted = [&](int party)
    {
        assert(party_in_range(party));

        bool changed = false;
        if (not corr.at(party))
        {
            corr.at(party) = true;
            plan.newly_corrupted_parties.push_back(party);
            if (plan.corrupted_party < 0)
                plan.corrupted_party = party;
            plan.state_updated = true;
            changed = true;
        }

        for (int other = 0; other < n; other++)
        {
            if (other == party)
                continue;
            changed |= append_new_disputed_pair(party, other);
        }

        assert(not disp.at(party).at(party));
        return changed;
    };

    auto close_corruption_promotions = [&]()
    {
        bool changed;
        do
        {
            changed = false;
            for (int i = 0; i < n; i++)
                if (not corr.at(i)
                        && local_dispute_count(i) >= threshold)
                    changed |= mark_corrupted(i);
        }
        while (changed);
    };

    auto normalize_disputed_pair = [&]()
    {
        int primary = outcome.primary_party;
        int counterparty = outcome.counterparty;
        plan.primary_party = primary;
        plan.counterparty = counterparty;

        if (not party_in_range(primary)
                || not party_in_range(counterparty)
                || primary == counterparty)
            return false;

        int x = min(primary, counterparty);
        int y = max(primary, counterparty);

        if ((outcome.disputed_party_a >= 0
                    || outcome.disputed_party_b >= 0)
                && (outcome.disputed_party_a != x
                    || outcome.disputed_party_b != y))
            return false;

        plan.disputed_party_a = x;
        plan.disputed_party_b = y;
        return true;
    };

    if (not outcome.valid)
        return finish_inconsistent();

    switch (outcome.action)
    {
    case FaultLocalizationAction::needs_analyze_sharing:
        if (outcome.sharing_to_analyze != SharingToAnalyze::alpha
                && outcome.sharing_to_analyze != SharingToAnalyze::beta)
            return finish_inconsistent();
        return finish(
                DisputeControlUpdatePlanAction::needs_analyze_sharing);

    case FaultLocalizationAction::identify_corrupted_party:
        if (not party_in_range(outcome.corrupted_party))
            return finish_inconsistent();

        if (corr.at(outcome.corrupted_party))
            return finish(
                    DisputeControlUpdatePlanAction::already_recorded);

        mark_corrupted(outcome.corrupted_party);
        close_corruption_promotions();

#ifndef NDEBUG
        assert(local_state_valid());
#endif
        if (not local_state_valid())
            return finish_inconsistent();

        return finish(
                DisputeControlUpdatePlanAction::
                    would_record_corrupted_party);

    case FaultLocalizationAction::identify_disputed_pair:
        if (not normalize_disputed_pair())
            return finish_inconsistent();

        if (not local_is_active(outcome.primary_party)
                || not local_is_active(outcome.counterparty))
            return finish_inconsistent();

        if (disp.at(plan.disputed_party_a).at(plan.disputed_party_b))
            return finish(
                    DisputeControlUpdatePlanAction::already_recorded);

        append_new_disputed_pair(
                outcome.primary_party, outcome.counterparty);
        close_corruption_promotions();

#ifndef NDEBUG
        assert(local_state_valid());
#endif
        if (not local_state_valid())
            return finish_inconsistent();

        return finish(
                DisputeControlUpdatePlanAction::
                    would_record_disputed_pair);

    case FaultLocalizationAction::none:
        return finish(DisputeControlUpdatePlanAction::no_action);
    }

    return finish_inconsistent();
}

template<class T>
typename AtlasGsz<T>::DisputeControlUpdatePlan
AtlasGsz<T>::inspect_current_dispute_control_update_plan() const
{
    if (have_ultimate_failure_context)
    {
        if (ultimate_failure_context.valid
                && ultimate_failure_context.fault_localization.valid)
            return inspect_dispute_control_update_plan(
                    ultimate_failure_context.fault_localization);

        return inspect_dispute_control_update_plan(
                ultimate_failure_context.fault_localization);
    }

    FaultLocalizationOutcome no_current_outcome{};
    no_current_outcome.valid = true;
    no_current_outcome.action = FaultLocalizationAction::none;
    no_current_outcome.source = FaultLocalizationSource::none;
    return inspect_dispute_control_update_plan(no_current_outcome);
}

template<class T>
void AtlasGsz<T>::validate_dispute_control_update_plan(
        const DisputeControlUpdatePlan& plan) const
{
    assert(plan.valid);
    assert(plan.action != DisputeControlUpdatePlanAction::none);

    int n = P.num_players();
    auto party_in_range = [&](int party)
    {
        return 0 <= party && party < n;
    };

    auto has_corrupted_party = [&]()
    {
        return party_in_range(plan.corrupted_party);
    };

    auto has_disputed_pair = [&]()
    {
        return party_in_range(plan.disputed_party_a)
                && party_in_range(plan.disputed_party_b)
                && plan.disputed_party_a < plan.disputed_party_b;
    };

    for (size_t i = 0; i < plan.newly_corrupted_parties.size(); i++)
    {
        int party = plan.newly_corrupted_parties.at(i);
        assert(party_in_range(party));
        for (size_t j = i + 1;
                j < plan.newly_corrupted_parties.size(); j++)
            assert(party != plan.newly_corrupted_parties.at(j));
    }

    for (size_t i = 0; i < plan.newly_disputed_pairs.size(); i++)
    {
        auto disputed_pair = plan.newly_disputed_pairs.at(i);
        assert(party_in_range(disputed_pair.first));
        assert(party_in_range(disputed_pair.second));
        assert(disputed_pair.first < disputed_pair.second);
        for (size_t j = i + 1;
                j < plan.newly_disputed_pairs.size(); j++)
            assert(disputed_pair != plan.newly_disputed_pairs.at(j));
    }

    switch (plan.action)
    {
    case DisputeControlUpdatePlanAction::no_action:
        assert(plan.fault_action == FaultLocalizationAction::none);
        assert(not plan.state_updated);
        assert(plan.newly_corrupted_parties.empty());
        assert(plan.newly_disputed_pairs.empty());
        break;

    case DisputeControlUpdatePlanAction::needs_analyze_sharing:
        assert(plan.fault_action
                == FaultLocalizationAction::needs_analyze_sharing);
        assert(plan.sharing_to_analyze == SharingToAnalyze::alpha
                || plan.sharing_to_analyze == SharingToAnalyze::beta);
        assert(not plan.state_updated);
        assert(plan.newly_corrupted_parties.empty());
        assert(plan.newly_disputed_pairs.empty());
        break;

    case DisputeControlUpdatePlanAction::
            would_record_corrupted_party:
        assert(plan.fault_action
                == FaultLocalizationAction::identify_corrupted_party);
        assert(has_corrupted_party());
        assert(plan.state_updated);
        assert(not plan.newly_corrupted_parties.empty());
        assert(std::find(plan.newly_corrupted_parties.begin(),
                plan.newly_corrupted_parties.end(),
                plan.corrupted_party)
                != plan.newly_corrupted_parties.end());
        break;

    case DisputeControlUpdatePlanAction::
            would_record_disputed_pair:
    {
        assert(plan.fault_action
                == FaultLocalizationAction::identify_disputed_pair);
        assert(party_in_range(plan.primary_party));
        assert(party_in_range(plan.counterparty));
        assert(plan.primary_party != plan.counterparty);
        assert(has_disputed_pair());
        assert(plan.disputed_party_a
                == min(plan.primary_party, plan.counterparty));
        assert(plan.disputed_party_b
                == max(plan.primary_party, plan.counterparty));
        assert(plan.state_updated);
        pair<int, int> disputed_pair = make_pair(
                plan.disputed_party_a, plan.disputed_party_b);
        assert(std::find(plan.newly_disputed_pairs.begin(),
                plan.newly_disputed_pairs.end(),
                disputed_pair)
                != plan.newly_disputed_pairs.end());
        break;
    }

    case DisputeControlUpdatePlanAction::already_recorded:
        assert(plan.fault_action
                == FaultLocalizationAction::identify_corrupted_party
                || plan.fault_action
                    == FaultLocalizationAction::identify_disputed_pair);
        if (plan.fault_action
                == FaultLocalizationAction::identify_corrupted_party)
            assert(has_corrupted_party());
        else
        {
            assert(party_in_range(plan.primary_party));
            assert(party_in_range(plan.counterparty));
            assert(plan.primary_party != plan.counterparty);
            assert(has_disputed_pair());
        }
        assert(not plan.state_updated);
        assert(plan.newly_corrupted_parties.empty());
        assert(plan.newly_disputed_pairs.empty());
        break;

    case DisputeControlUpdatePlanAction::inconsistent_state:
        assert(not plan.state_updated);
        assert(plan.newly_corrupted_parties.empty());
        assert(plan.newly_disputed_pairs.empty());
        break;

    case DisputeControlUpdatePlanAction::none:
        assert(false);
        break;
    }
}

template<class T>
typename AtlasGsz<T>::DisputeControlUpdateApplicationResult
AtlasGsz<T>::apply_dispute_control_update_once(
        const FaultLocalizationOutcome& outcome)
{
    int n = P.num_players();

    DisputeControlUpdatePlan plan =
            inspect_dispute_control_update_plan(outcome);

    bool initialized_before = dispute_control_state.initialized;
    auto raw_corr_before = dispute_control_state.corr;
    auto raw_disp_before = dispute_control_state.disp;

    auto raw_state_unchanged = [&]()
    {
        return dispute_control_state.initialized == initialized_before
                && dispute_control_state.corr == raw_corr_before
                && dispute_control_state.disp == raw_disp_before;
    };

    auto restore_raw_state = [&]()
    {
        dispute_control_state.initialized = initialized_before;
        dispute_control_state.corr = raw_corr_before;
        dispute_control_state.disp = raw_disp_before;
#ifndef NDEBUG
        assert(raw_state_unchanged());
#endif
    };

    auto read_logical_state = [&](bool initialized,
            const vector<bool>& raw_corr,
            const vector<vector<bool>>& raw_disp,
            vector<bool>& corr,
            vector<vector<bool>>& disp)
    {
        corr.assign(n, false);
        disp.assign(n, vector<bool>(n, false));

        if (not initialized)
            return true;

        if (raw_corr.size() != size_t(n)
                || raw_disp.size() != size_t(n))
            return false;

        for (int i = 0; i < n; i++)
            if (raw_disp.at(i).size() != size_t(n))
                return false;

        corr = raw_corr;
        disp = raw_disp;
        return true;
    };

    auto read_current_logical_state = [&](
            vector<bool>& corr,
            vector<vector<bool>>& disp)
    {
        return read_logical_state(
                dispute_control_state.initialized,
                dispute_control_state.corr,
                dispute_control_state.disp,
                corr,
                disp);
    };

    vector<bool> corr_before;
    vector<vector<bool>> disp_before;
    bool before_state_valid = read_logical_state(
            initialized_before,
            raw_corr_before,
            raw_disp_before,
            corr_before,
            disp_before);

    DisputeControlUpdateApplicationResult result{};
    result.valid = true;
    result.plan_action = plan.action;
    result.fault_action = plan.fault_action;
    result.source = plan.source;
    result.sharing_to_analyze = plan.sharing_to_analyze;
    result.corrupted_party = plan.corrupted_party;
    result.disputed_party_a = plan.disputed_party_a;
    result.disputed_party_b = plan.disputed_party_b;
    result.primary_party = plan.primary_party;
    result.counterparty = plan.counterparty;

    auto sorted_parties = [](vector<int> parties)
    {
        sort(parties.begin(), parties.end());
        return parties;
    };

    auto sorted_disputed_pairs = [](vector<pair<int, int>> pairs)
    {
        for (auto& disputed_pair : pairs)
            if (disputed_pair.second < disputed_pair.first)
                swap(disputed_pair.first, disputed_pair.second);
        sort(pairs.begin(), pairs.end());
        return pairs;
    };

    auto finish = [&](DisputeControlUpdateApplicationAction action)
            -> DisputeControlUpdateApplicationResult
    {
        result.action = action;
        validate_dispute_control_update_application_result(result);
        return result;
    };

    auto finish_inconsistent = [&]()
            -> DisputeControlUpdateApplicationResult
    {
        result.state_updated = false;
        result.newly_corrupted_parties.clear();
        result.newly_disputed_pairs.clear();
        return finish(
                DisputeControlUpdateApplicationAction::inconsistent_state);
    };

    auto mismatch = [&](bool restore_state)
            -> DisputeControlUpdateApplicationResult
    {
        if (restore_state)
            restore_raw_state();
#ifndef NDEBUG
        if (restore_state)
            assert(raw_state_unchanged());
        assert(false);
#endif
        return finish_inconsistent();
    };

    auto finish_without_mutation =
            [&](DisputeControlUpdateApplicationAction action)
                -> DisputeControlUpdateApplicationResult
    {
        if (not raw_state_unchanged())
            return mismatch(true);

#ifndef NDEBUG
        assert(raw_state_unchanged());
#endif
        result.state_updated = false;
        result.newly_corrupted_parties.clear();
        result.newly_disputed_pairs.clear();
        return finish(action);
    };

    auto derive_actual_delta = [&]()
    {
        vector<bool> corr_after;
        vector<vector<bool>> disp_after;
        if (not before_state_valid
                || not read_current_logical_state(corr_after, disp_after))
            return false;

        result.newly_corrupted_parties.clear();
        result.newly_disputed_pairs.clear();

        for (int i = 0; i < n; i++)
        {
            if (corr_before.at(i) && not corr_after.at(i))
                return false;
            if (not corr_before.at(i) && corr_after.at(i))
                result.newly_corrupted_parties.push_back(i);

            if (disp_after.at(i).at(i))
                return false;
        }

        for (int i = 0; i < n; i++)
        {
            for (int j = i + 1; j < n; j++)
            {
                if (disp_after.at(i).at(j)
                        != disp_after.at(j).at(i))
                    return false;
                if (disp_before.at(i).at(j)
                        && not disp_after.at(i).at(j))
                    return false;
                if (not disp_before.at(i).at(j)
                        && disp_after.at(i).at(j))
                    result.newly_disputed_pairs.push_back(
                            make_pair(i, j));
            }
        }

        result.state_updated =
                not result.newly_corrupted_parties.empty()
                || not result.newly_disputed_pairs.empty();
        return true;
    };

    auto actual_delta_matches_plan = [&]()
    {
        return result.state_updated == plan.state_updated
                && sorted_parties(result.newly_corrupted_parties)
                    == sorted_parties(plan.newly_corrupted_parties)
                && sorted_disputed_pairs(result.newly_disputed_pairs)
                    == sorted_disputed_pairs(plan.newly_disputed_pairs);
    };

    switch (plan.action)
    {
    case DisputeControlUpdatePlanAction::no_action:
        return finish_without_mutation(
                DisputeControlUpdateApplicationAction::no_action);

    case DisputeControlUpdatePlanAction::needs_analyze_sharing:
        return finish_without_mutation(
                DisputeControlUpdateApplicationAction::
                    pending_analyze_sharing);

    case DisputeControlUpdatePlanAction::already_recorded:
        return finish_without_mutation(
                DisputeControlUpdateApplicationAction::already_recorded);

    case DisputeControlUpdatePlanAction::inconsistent_state:
        return finish_without_mutation(
                DisputeControlUpdateApplicationAction::
                    inconsistent_state);

    case DisputeControlUpdatePlanAction::
            would_record_corrupted_party:
    {
        if (not before_state_valid)
            return mismatch(false);

        FaultLocalizationApplication application{};
        record_corrupted_party(plan.corrupted_party, application);
        if (not derive_actual_delta()
                || not actual_delta_matches_plan())
            return mismatch(true);

        validate_dispute_control_state();
        return finish(
                DisputeControlUpdateApplicationAction::
                    recorded_corrupted_party);
    }

    case DisputeControlUpdatePlanAction::
            would_record_disputed_pair:
    {
        if (not before_state_valid)
            return mismatch(false);

        FaultLocalizationApplication application{};
        record_disputed_pair(
                plan.primary_party, plan.counterparty, application);
        if (not derive_actual_delta()
                || not actual_delta_matches_plan())
            return mismatch(true);

        validate_dispute_control_state();
        return finish(
                DisputeControlUpdateApplicationAction::
                    recorded_disputed_pair);
    }

    case DisputeControlUpdatePlanAction::none:
        break;
    }

    return mismatch(false);
}

template<class T>
typename AtlasGsz<T>::DisputeControlUpdateApplicationResult
AtlasGsz<T>::apply_current_dispute_control_update_once()
{
    if (have_ultimate_failure_context)
        return apply_dispute_control_update_once(
                ultimate_failure_context.fault_localization);

    FaultLocalizationOutcome no_current_outcome{};
    no_current_outcome.valid = true;
    no_current_outcome.action = FaultLocalizationAction::none;
    no_current_outcome.source = FaultLocalizationSource::none;
    return apply_dispute_control_update_once(no_current_outcome);
}

template<class T>
void AtlasGsz<T>::validate_dispute_control_update_application_result(
        const DisputeControlUpdateApplicationResult& result) const
{
    assert(result.valid);
    assert(result.action
            != DisputeControlUpdateApplicationAction::none);
    assert(result.plan_action != DisputeControlUpdatePlanAction::none);

    int n = P.num_players();
    auto party_in_range = [&](int party)
    {
        return 0 <= party && party < n;
    };

    auto has_corrupted_party = [&]()
    {
        return party_in_range(result.corrupted_party);
    };

    auto has_disputed_pair = [&]()
    {
        return party_in_range(result.disputed_party_a)
                && party_in_range(result.disputed_party_b)
                && result.disputed_party_a < result.disputed_party_b;
    };

    for (size_t i = 0; i < result.newly_corrupted_parties.size(); i++)
    {
        int party = result.newly_corrupted_parties.at(i);
        assert(party_in_range(party));
        if (i > 0)
            assert(result.newly_corrupted_parties.at(i - 1) < party);
    }

    for (size_t i = 0; i < result.newly_disputed_pairs.size(); i++)
    {
        auto disputed_pair = result.newly_disputed_pairs.at(i);
        assert(party_in_range(disputed_pair.first));
        assert(party_in_range(disputed_pair.second));
        assert(disputed_pair.first < disputed_pair.second);
        if (i > 0)
            assert(result.newly_disputed_pairs.at(i - 1)
                    < disputed_pair);
    }

    assert(result.state_updated
            == (not result.newly_corrupted_parties.empty()
                || not result.newly_disputed_pairs.empty()));

    switch (result.action)
    {
    case DisputeControlUpdateApplicationAction::no_action:
        assert(result.plan_action
                == DisputeControlUpdatePlanAction::no_action);
        assert(result.fault_action == FaultLocalizationAction::none);
        assert(not result.state_updated);
        break;

    case DisputeControlUpdateApplicationAction::
            pending_analyze_sharing:
        assert(result.plan_action
                == DisputeControlUpdatePlanAction::
                    needs_analyze_sharing);
        assert(result.fault_action
                == FaultLocalizationAction::needs_analyze_sharing);
        assert(result.sharing_to_analyze == SharingToAnalyze::alpha
                || result.sharing_to_analyze == SharingToAnalyze::beta);
        assert(not result.state_updated);
        break;

    case DisputeControlUpdateApplicationAction::
            recorded_corrupted_party:
        assert(result.plan_action
                == DisputeControlUpdatePlanAction::
                    would_record_corrupted_party);
        assert(result.fault_action
                == FaultLocalizationAction::identify_corrupted_party);
        assert(has_corrupted_party());
        assert(result.state_updated);
        assert(find(result.newly_corrupted_parties.begin(),
                result.newly_corrupted_parties.end(),
                result.corrupted_party)
                != result.newly_corrupted_parties.end());
        break;

    case DisputeControlUpdateApplicationAction::
            recorded_disputed_pair:
    {
        assert(result.plan_action
                == DisputeControlUpdatePlanAction::
                    would_record_disputed_pair);
        assert(result.fault_action
                == FaultLocalizationAction::identify_disputed_pair);
        assert(party_in_range(result.primary_party));
        assert(party_in_range(result.counterparty));
        assert(result.primary_party != result.counterparty);
        assert(has_disputed_pair());
        assert(result.disputed_party_a
                == min(result.primary_party, result.counterparty));
        assert(result.disputed_party_b
                == max(result.primary_party, result.counterparty));
        assert(result.state_updated);
        pair<int, int> disputed_pair = make_pair(
                result.disputed_party_a, result.disputed_party_b);
        assert(find(result.newly_disputed_pairs.begin(),
                result.newly_disputed_pairs.end(),
                disputed_pair)
                != result.newly_disputed_pairs.end());
        break;
    }

    case DisputeControlUpdateApplicationAction::already_recorded:
        assert(result.plan_action
                == DisputeControlUpdatePlanAction::already_recorded);
        assert(result.fault_action
                == FaultLocalizationAction::identify_corrupted_party
                || result.fault_action
                    == FaultLocalizationAction::identify_disputed_pair);
        if (result.fault_action
                == FaultLocalizationAction::identify_corrupted_party)
            assert(has_corrupted_party());
        else
        {
            assert(party_in_range(result.primary_party));
            assert(party_in_range(result.counterparty));
            assert(result.primary_party != result.counterparty);
            assert(has_disputed_pair());
        }
        assert(not result.state_updated);
        break;

    case DisputeControlUpdateApplicationAction::inconsistent_state:
        break;

    case DisputeControlUpdateApplicationAction::none:
        assert(false);
        break;
    }

    if (result.action
            != DisputeControlUpdateApplicationAction::
                inconsistent_state)
    {
        assert(result.plan_action
                != DisputeControlUpdatePlanAction::inconsistent_state);
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

    auto update = apply_dispute_control_update_once(outcome);
#ifndef NDEBUG
    assert(update.valid);
#endif
    if (not update.valid)
        return application;

    switch (update.action)
    {
    case DisputeControlUpdateApplicationAction::
            pending_analyze_sharing:
#ifndef NDEBUG
        assert(update.fault_action
                == FaultLocalizationAction::needs_analyze_sharing);
#endif
        application.valid = true;
        application.action =
                FaultLocalizationApplicationAction::
                    pending_analyze_sharing;
        return application;

    case DisputeControlUpdateApplicationAction::
            recorded_corrupted_party:
#ifndef NDEBUG
        assert(update.fault_action
                == FaultLocalizationAction::identify_corrupted_party);
#endif
        application.valid = true;
        application.action =
                FaultLocalizationApplicationAction::
                    recorded_corrupted_party;
        application.state_updated = update.state_updated;
        application.corrupted_party = update.corrupted_party;
        application.newly_corrupted_parties =
                update.newly_corrupted_parties;
        return application;

    case DisputeControlUpdateApplicationAction::
            recorded_disputed_pair:
#ifndef NDEBUG
        assert(update.fault_action
                == FaultLocalizationAction::identify_disputed_pair);
#endif
        application.valid = true;
        application.action =
                FaultLocalizationApplicationAction::
                    recorded_disputed_pair;
        application.state_updated = update.state_updated;
        application.corrupted_party = update.corrupted_party;
        application.disputed_party_a = update.disputed_party_a;
        application.disputed_party_b = update.disputed_party_b;
        application.primary_party = update.primary_party;
        application.counterparty = update.counterparty;
        application.newly_corrupted_parties =
                update.newly_corrupted_parties;
        return application;

    case DisputeControlUpdateApplicationAction::already_recorded:
        if (update.fault_action
                == FaultLocalizationAction::identify_corrupted_party)
        {
            application.valid = true;
            application.action =
                    FaultLocalizationApplicationAction::
                        recorded_corrupted_party;
            application.state_updated = false;
            application.corrupted_party = update.corrupted_party;
            return application;
        }

        if (update.fault_action
                == FaultLocalizationAction::identify_disputed_pair)
        {
            application.valid = true;
            application.action =
                    FaultLocalizationApplicationAction::
                        recorded_disputed_pair;
            application.state_updated = false;
            application.disputed_party_a = update.disputed_party_a;
            application.disputed_party_b = update.disputed_party_b;
            application.primary_party = update.primary_party;
            application.counterparty = update.counterparty;
            return application;
        }
        break;

    case DisputeControlUpdateApplicationAction::no_action:
    case DisputeControlUpdateApplicationAction::inconsistent_state:
    case DisputeControlUpdateApplicationAction::none:
        break;
    }

#ifndef NDEBUG
    assert(false);
#endif
    return application;
}

template<class T>
void AtlasGsz<T>::maybe_run_consumed_provenance_transfer_test(
        const PartialMultTranscriptRecord& record)
{
    const char* auth_test = getenv("ATLAS_GSZ_AUTH_TEST");
    if (auth_test == 0
            || string(auth_test) != "consumed-provenance-transfer"
            || consumed_provenance_transfer_test_hook_ran)
        return;

    auto fail = [] (const string& reason) {
        throw logic_error(
                "AtlasGsz: consumed-provenance-transfer test failed: "
                + reason);
    };
    const auto& state = optimistic_authentication_state;
    auto assert_no_authentication_artifacts = [&] {
        if (not state.keys.empty() || not state.dealer_batches.empty()
                || not state.nu_material.empty()
                || not state.holder_tags.empty()
                || not state.checkpoints.empty()
                || not state.global_invocations.empty()
                || state.key_establishment_runs != 0
                || state.total_ftag_chunks != 0
                || state.global_check_tag_challenges != 0
                || state.next_batch_id != 1
                || state.next_checkpoint_id != 1
                || state.next_global_invocation_id != 1
                || not verifiable_registry.sharings.empty()
                || not verifiable_registry.checkpoints.empty())
            fail("unexpected authentication or checkpoint artifact");
        for (const auto& batch : state.dealer_batches)
            if (not batch.authenticated_handles.empty())
                fail("unexpected authenticated source handle");
    };
    assert_no_authentication_artifacts();

    const auto& atlas_reference =
            honest.get_last_double_sharing_producer_reference();
    const auto& reference = record.producer_reference;
    if (reference.producer_provenance
                != atlas_reference.producer_provenance
            || reference.producer_output_ordinal
                != atlas_reference.producer_output_ordinal)
        fail("AtlasGsz did not retain Atlas's exact producer reference");
    if (not reference.producer_provenance)
        fail("completed operation has null producer provenance");

    const auto& paired = *reference.producer_provenance;
    const auto& degree_t = paired.degree_t;
    const auto& degree_2t = paired.degree_2t;
    if (degree_t.source_groups.size() != degree_2t.source_groups.size())
        fail("degree source-group counts differ");
    if (degree_t.output_derivations.size()
            != degree_2t.output_derivations.size())
        fail("degree output-derivation counts differ");
    if (reference.producer_output_ordinal
            >= degree_t.output_derivations.size())
        fail("producer output ordinal is out of range");

    for (size_t group_index = 0;
            group_index < degree_t.source_groups.size(); group_index++)
    {
        const auto& t_group = degree_t.source_groups.at(group_index);
        const auto& two_t_group = degree_2t.source_groups.at(group_index);
        if (t_group.input_batch_ordinal != group_index
                || two_t_group.input_batch_ordinal != group_index
                || t_group.sources.size() != size_t(P.num_players())
                || two_t_group.sources.size() != t_group.sources.size())
            fail("producer source-group layout mismatch");
        for (size_t dealer = 0; dealer < t_group.sources.size(); dealer++)
        {
            const auto& t_source = t_group.sources.at(dealer);
            const auto& two_t_source = two_t_group.sources.at(dealer);
            if (t_source.dealer != int(dealer)
                    || two_t_source.dealer != int(dealer)
                    || t_source.input_batch_ordinal != group_index
                    || two_t_source.input_batch_ordinal != group_index)
                fail("producer dealer ordering is not canonical ascending");
        }
    }

    for (size_t output_index = 0;
            output_index < degree_t.output_derivations.size(); output_index++)
    {
        const auto& t_derivation =
                degree_t.output_derivations.at(output_index);
        const auto& two_t_derivation =
                degree_2t.output_derivations.at(output_index);
        if (t_derivation.output_ordinal != output_index
                || two_t_derivation.output_ordinal != output_index
                || t_derivation.input_batch_ordinal
                    != two_t_derivation.input_batch_ordinal
                || t_derivation.terms.size() != size_t(P.num_players())
                || two_t_derivation.terms.size()
                    != t_derivation.terms.size())
            fail("paired producer derivation layout mismatch");
        for (size_t term_index = 0;
                term_index < t_derivation.terms.size(); term_index++)
        {
            const auto& t_term = t_derivation.terms.at(term_index);
            const auto& two_t_term =
                    two_t_derivation.terms.at(term_index);
            if (t_term.source_index != term_index
                    || two_t_term.source_index != term_index
                    || t_term.coefficient != two_t_term.coefficient)
                fail("paired producer coefficient layout mismatch");
        }
    }

    const auto ordinal = reference.producer_output_ordinal;
    const auto& t_derivation = degree_t.output_derivations.at(ordinal);
    const auto& two_t_derivation =
            degree_2t.output_derivations.at(ordinal);
    if (t_derivation.input_batch_ordinal >= degree_t.source_groups.size())
        fail("selected producer source-group ordinal is out of range");
    const auto& t_sources = degree_t.source_groups.at(
            t_derivation.input_batch_ordinal).sources;
    const auto& two_t_sources = degree_2t.source_groups.at(
            two_t_derivation.input_batch_ordinal).sources;
    const auto& decomposition = record.transcript.r_decomposition;
    if (decomposition.dealer_components.size() != size_t(P.num_players()))
        fail("transcript dealer decomposition has wrong width");

    T evaluated_t{};
    T evaluated_2t{};
    for (size_t dealer = 0; dealer < size_t(P.num_players()); dealer++)
    {
        const auto& t_term = t_derivation.terms.at(dealer);
        const auto& two_t_term = two_t_derivation.terms.at(dealer);
        T contribution_t = t_term.coefficient
                * t_sources.at(t_term.source_index).local_share;
        T contribution_2t = two_t_term.coefficient
                * two_t_sources.at(two_t_term.source_index).local_share;
        const auto& existing = decomposition.dealer_components.at(dealer);
        if (contribution_t != existing.r_t
                || contribution_2t != existing.r_2t)
            fail("producer evaluation disagrees with dealer decomposition");
        evaluated_t += contribution_t;
        evaluated_2t += contribution_2t;
    }
    if (evaluated_t != record.transcript.r_t)
        fail("degree-t producer evaluation disagrees with transcript r_t");
    if (evaluated_2t != record.transcript.r_2t)
        fail("degree-2t producer evaluation disagrees with transcript r_2t");

    consumed_provenance_transfer_test_hook_ran = true;
    assert_no_authentication_artifacts();
    if (P.my_num() == 0)
        cout << "ATLAS_GSZ_AUTH_TEST consumed-provenance-transfer"
             << " PASS operation=ordinary-scalar-or-dot"
             << " producer_record=shared producer_output_ordinal="
             << ordinal
             << " dealer_order=ascending degree_layouts=paired"
             << " evaluations=exact decomposition=exact"
             << " dealer_batches=0 handles=0 ftag_chunks=0"
             << " checkpoints=0 authentication_invocations=0"
             << endl;
}

template<class T>
void AtlasGsz<T>::init(Preprocessing<T>& prep, typename T::MAC_Check& MC) {
    honest.init(prep, MC);

    if constexpr (not T::characteristic_two)
    {
        const char* auth_test = getenv("ATLAS_GSZ_AUTH_TEST");
        if (auth_test != 0)
        {
            string mode(auth_test);
            if (mode == "producer-provenance")
            {
                if (not producer_provenance_test_hook_ran)
                {
                    const auto& state = optimistic_authentication_state;
                    auto assert_no_authentication_artifacts = [&] {
                        assert(state.keys.empty());
                        assert(state.dealer_batches.empty());
                        assert(state.nu_material.empty());
                        assert(state.holder_tags.empty());
                        assert(state.checkpoints.empty());
                        assert(state.global_invocations.empty());
                        assert(state.key_establishment_runs == 0);
                        assert(state.total_ftag_chunks == 0);
                        assert(state.global_check_tag_challenges == 0);
                        assert(verifiable_registry.sharings.empty());
                        assert(verifiable_registry.checkpoints.empty());
                    };
                    assert_no_authentication_artifacts();

                    auto summary =
                            honest.run_double_sharing_provenance_test();
                    producer_provenance_test_hook_ran = true;

                    assert_no_authentication_artifacts();
                    if (P.my_num() == 0)
                        cout << "ATLAS_GSZ_AUTH_TEST producer-provenance"
                             << " PASS input_generation_groups="
                             << summary.input_generation_groups
                             << " output_derivations="
                             << summary.output_derivations
                             << " sources_per_group="
                             << summary.sources_per_group
                             << " dealer_order=ascending"
                             << " output_order=generation-then-hyper-row"
                             << " degree_layouts=paired"
                             << " decomposition=exact"
                             << " padding_sources=0"
                             << " malformed_candidate=atomically-rejected"
                             << " dealer_batches=0 handles=0 ftag_chunks=0"
                             << " checkpoints=0 authentication_invocations=0"
                             << endl;
                }
            }
            else if (mode == "consumed-provenance-transfer")
            {
                // This focused check runs only after a normal wrapper record
                // has finalized and pulled the exact Atlas reference.
            }
            else if (mode.rfind("honest-batch-integration", 0) == 0)
            {
                if (not honest_batch_integration_test_mode.empty())
                    throw logic_error(
                        "AtlasGsz: honest batch integration mode initialized twice");
                honest_batch_integration_test_mode = mode;
                if (mode == "honest-batch-integration-fixed-king")
                {
                    const size_t communication_before =
                            P.total_comm().sent;
                    bool rejected = false;
                    try
                    {
                        set_fixed_king(1);
                    }
                    catch (const invalid_argument&)
                    {
                        rejected = true;
                    }
                    set_fixed_king(0);
                    if (not rejected
                            || P.total_comm().sent
                                    != communication_before)
                        throw logic_error(
                                "AtlasGsz: nonzero fixed king was not rejected locally");
                    if (P.my_num() == 0)
                        cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-fixed-king"
                             << " PASS fixed_king_0=accepted"
                             << " nonzero=rejected communication=0"
                             << endl;
                }
            }
            else if (mode == "special-e-t")
            {
                if (not no_authentication_or_checkpoint_artifacts())
                    throw logic_error(
                            "AtlasGsz: special-e-t test did not start from empty state");
                run_special_e_t_malformed_support_test();
                special_e_t_test_enabled = true;
            }
            else if (mode == "tentative-double-rand-capture"
                    || mode == "tentative-double-rand-adapter-honest"
                    || mode == "tentative-double-rand-adapter-malformed"
                    || mode
                            == "tentative-double-rand-adapter-e-t-malformed"
                    || mode
                            == "tentative-double-rand-adapter-verify-failure"
                    || mode == "tentative-double-rand-adapter-tag-failure")
            {
                if (not tentative_double_rand_capture_test_enabled)
                {
                    const bool adapter_mode =
                            mode != "tentative-double-rand-capture";
                    if (not no_authentication_or_checkpoint_artifacts()
                            || tentative_double_rand_capture_state.active
                            || tentative_double_rand_capture_state
                                    .finalized_candidate
                            || not tentative_double_rand_capture_state
                                    .producer_records.empty()
                            || not tentative_double_rand_capture_state
                                    .consumptions.empty())
                        throw logic_error(
                                "AtlasGsz: tentative capture test did not start from empty state");

                    if (adapter_mode)
                    {
                        auto& auth = optimistic_authentication_state;
                        const uint64_t next_batch_id = auth.next_batch_id;
                        const uint64_t next_invocation_id =
                                auth.next_global_invocation_id;
                        const size_t communication = P.total_comm().sent;
                        SeededPRNG expected_prng =
                                optimistic_authentication_prng;
                        const auto absent =
                                adapt_finalized_tentative_double_rand_candidate();
                        if (not begin_tentative_double_rand_capture())
                            throw logic_error(
                                    "AtlasGsz: tentative adapter test could not begin real round");
                        const auto active =
                                adapt_finalized_tentative_double_rand_candidate();
                        SeededPRNG actual_prng =
                                optimistic_authentication_prng;
                        bool same_prng = true;
                        for (size_t i = 0; i < 4; i++)
                            same_prng &= expected_prng.get_word()
                                    == actual_prng.get_word();
                        if (absent.authenticated
                                || absent.authentication_invocation_id != 0
                                || not absent.dealer_batches.empty()
                                || not absent.source_handles.empty()
                                || not absent.converted_r_t_derivations.empty()
                                || not absent.authenticated_e_t_sources.empty()
                                || active.authenticated
                                || active.authentication_invocation_id != 0
                                || not active.dealer_batches.empty()
                                || not active.source_handles.empty()
                                || not active.converted_r_t_derivations.empty()
                                || not active.authenticated_e_t_sources.empty()
                                || not tentative_double_rand_capture_state.active
                                || auth.next_batch_id != next_batch_id
                                || auth.next_global_invocation_id
                                        != next_invocation_id
                                || not auth.dealer_batches.empty()
                                || not auth.global_invocations.empty()
                                || P.total_comm().sent != communication
                                || not same_prng)
                            throw logic_error(
                                    "AtlasGsz: absent/active tentative adapter rejection mutated protocol state");
                        tentative_double_rand_adapter_test_mode = mode;
                    }
                    else
                    {
                        if (not begin_tentative_double_rand_capture())
                            throw logic_error(
                                    "AtlasGsz: tentative capture test could not begin empty negative round");
                        if (finalize_tentative_double_rand_capture()
                                || tentative_double_rand_capture_state.active
                                || tentative_double_rand_capture_state
                                        .finalized_candidate
                                || not tentative_double_rand_capture_state
                                        .producer_records.empty()
                                || not tentative_double_rand_capture_state
                                        .consumptions.empty())
                            throw logic_error(
                                    "AtlasGsz: empty tentative capture was not rejected cleanly");
                        if (not begin_tentative_double_rand_capture())
                            throw logic_error(
                                    "AtlasGsz: tentative capture test could not begin real round");
                    }
                    tentative_double_rand_capture_test_enabled = true;
                }
            }
            else if (not optimistic_authentication_state.test_hook_ran
                    && (mode == "honest" || mode == "singleton-honest"
                    || mode == "source-only-honest"))
            {
                if (not run_optimistic_authentication_test_hook(mode))
                    throw mac_fail(
                            "AtlasGsz: optimistic authentication test failed");
            }
            else if (not optimistic_authentication_state.test_hook_ran
                    && (mode == "failure" || mode == "ordinary-failure"
                    || mode == "base-contribution-failure"
                    || mode == "verify-failure"
                    || mode == "base-failure"
                    || mode == "duplicate-batch"
                    || mode == "duplicate-dealer"
                    || mode == "omission"
                    || mode == "missing-chunk"
                    || mode == "duplicate-chunk"
                    || mode == "epoch-mismatch"
                    || mode == "source-only-verify-failure"
                    || mode == "source-only-failure"))
            {
                bool accepted = run_optimistic_authentication_test_hook(mode);
                assert(not accepted);
                throw mac_fail(
                        "AtlasGsz: RecoveryNotImplemented after authentication failure");
            }
            else if (not optimistic_authentication_state.test_hook_ran)
                throw invalid_argument(
                        "ATLAS_GSZ_AUTH_TEST selected an unknown focused test mode");
        }
    }
}

template<class T>
void AtlasGsz<T>::init_mul()
{
    enter_verification_operation(
            OrdinaryDoubleRandOperationKind::scalar_multiplication);
    honest.init_mul();
}

template<class T>
void AtlasGsz<T>::prepare_mul(const T& x, const T& y, int)
{
    integrated_ordinary_batch_state.wrapper_pending_results++;
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
    record.operation_kind =
            OrdinaryDoubleRandOperationKind::scalar_multiplication;
    record.verification_batch_serial =
            integrated_ordinary_batch_state
                    .current_verification_batch_serial;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.producer_reference =
            honest.get_last_double_sharing_producer_reference();
    record.has_king_evidence = honest.has_last_king_partial_mult_evidence();
    if (record.has_king_evidence)
        record.king_evidence = honest.get_last_king_partial_mult_evidence();
    assert(record.has_king_evidence == (P.my_num() == record.transcript.king));
    if (record.has_king_evidence)
        assert(record.king_evidence.king == record.transcript.king);
    partial_mult_transcripts.push_back(record);
    assert(partial_mult_transcripts.size() == n_records + 1);
    z_verify.push_back(res);
    maybe_run_special_e_t_test(
            partial_mult_transcripts.back(),
            OrdinaryDoubleRandOperationKind::scalar_multiplication,
            res);
    maybe_run_consumed_provenance_transfer_test(
            partial_mult_transcripts.back());
    if (tentative_double_rand_capture_state.active)
    {
        if (not capture_completed_ordinary_double_rand(
                partial_mult_transcripts.back(),
                partial_mult_transcripts.size() - 1,
                OrdinaryDoubleRandOperationKind::scalar_multiplication))
            throw logic_error(
                    "AtlasGsz: completed ordinary scalar capture failed");
        maybe_complete_tentative_double_rand_capture_test();
    }
    finish_verification_operation(
            OrdinaryDoubleRandOperationKind::scalar_multiplication, 1);
    maybe_flush_honest_batch_integration_residual();
    return res;
}

template<class T>
void AtlasGsz<T>::set_fixed_king(int king)
{
    if (king != 0)
        throw invalid_argument(
                "AtlasGsz: this milestone supports only fixed king 0");
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
    enter_verification_operation(
            OrdinaryDoubleRandOperationKind::dot_product);
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
    integrated_ordinary_batch_state.wrapper_pending_results++;
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
    record.operation_kind = OrdinaryDoubleRandOperationKind::dot_product;
    record.verification_batch_serial =
            integrated_ordinary_batch_state
                    .current_verification_batch_serial;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.producer_reference =
            honest.get_last_double_sharing_producer_reference();
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
    maybe_run_special_e_t_test(
            partial_mult_transcripts.back(),
            OrdinaryDoubleRandOperationKind::dot_product,
            res);
    maybe_run_consumed_provenance_transfer_test(
            partial_mult_transcripts.back());
    if (tentative_double_rand_capture_state.active)
    {
        if (not capture_completed_ordinary_double_rand(
                partial_mult_transcripts.back(),
                partial_mult_transcripts.size() - 1,
                OrdinaryDoubleRandOperationKind::dot_product))
            throw logic_error(
                    "AtlasGsz: completed ordinary dot-product capture failed");
        maybe_complete_tentative_double_rand_capture_test();
    }
    finish_verification_operation(
            OrdinaryDoubleRandOperationKind::dot_product, size_t(length));
    maybe_flush_honest_batch_integration_residual();
    return res;
}

template<class T>
void AtlasGsz<T>::init_mul_pub()
{
    ensure_wrapper_entry_allowed("mul-public operation");
    auto& integrated = integrated_ordinary_batch_state;
    if (integrated.wrapper_operation_active
            && not replace_empty_preprocessing_initialization_wrapper())
        throw logic_error(
                "AtlasGsz: preprocessing mul-public reentry encountered a real pending operation");
    enter_verification_operation(
            OrdinaryDoubleRandOperationKind::noneligible);
    honest.init_mul_pub();
}

template<class T>
void AtlasGsz<T>::prepare_mul_pub(T x, T y)
{
    auto& integrated = integrated_ordinary_batch_state;
    integrated.wrapper_pending_results++;
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
    auto& integrated = integrated_ordinary_batch_state;
    size_t n_records = partial_mult_transcripts.size();
    T res = honest.finalize_mul_pub();

    PartialMultTranscriptRecord record{};
    record.offset = z_verify.size();
    record.length = 1;
    record.operation_kind = OrdinaryDoubleRandOperationKind::noneligible;
    record.verification_batch_serial =
            integrated_ordinary_batch_state
                    .current_verification_batch_serial;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.producer_reference =
            honest.get_last_double_sharing_producer_reference();
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
    integrated.preprocessing_mul_public_records++;

    z_verify.push_back(res);
    finish_verification_operation(
            OrdinaryDoubleRandOperationKind::noneligible, 1);
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
    enter_verification_operation(
            OrdinaryDoubleRandOperationKind::noneligible);
    honest.init_mul_trunc(length);
}

template<class T>
void AtlasGsz<T>::prepare_mul_trunc(const T& x, const T& y)
{
    integrated_ordinary_batch_state.wrapper_pending_results++;
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
    record.operation_kind = OrdinaryDoubleRandOperationKind::noneligible;
    record.verification_batch_serial =
            integrated_ordinary_batch_state
                    .current_verification_batch_serial;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.producer_reference =
            honest.get_last_double_sharing_producer_reference();
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

    finish_verification_operation(
            OrdinaryDoubleRandOperationKind::noneligible, 1);

    return res;
}

template<class T>
void AtlasGsz<T>::init_dotprod_trunc()
{
    enter_verification_operation(
            OrdinaryDoubleRandOperationKind::noneligible);
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
    integrated_ordinary_batch_state.wrapper_pending_results++;
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
    record.operation_kind = OrdinaryDoubleRandOperationKind::noneligible;
    record.verification_batch_serial =
            integrated_ordinary_batch_state
                    .current_verification_batch_serial;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.producer_reference =
            honest.get_last_double_sharing_producer_reference();
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

    finish_verification_operation(
            OrdinaryDoubleRandOperationKind::noneligible,
            size_t(length));

    return res;
}

template<class T>
void AtlasGsz<T>::prepare_with_solved_bits(const typename T::open_type& product)
{
    honest.prepare_with_solved_bits(product);
}

template<class T>
void AtlasGsz<T>::cleanup_successful_integrated_batch(
        size_t dealer_batch_start,
        size_t nu_material_start,
        size_t holder_tag_start,
        size_t global_invocation_start,
        IntegratedBatchReport& report)
{
    auto& auth = optimistic_authentication_state;
    if (dealer_batch_start > auth.dealer_batches.size()
            || nu_material_start > auth.nu_material.size()
            || holder_tag_start > auth.holder_tags.size()
            || global_invocation_start > auth.global_invocations.size())
        throw logic_error(
                "AtlasGsz: integrated cleanup range is invalid");
    auth.dealer_batches.resize(dealer_batch_start);
    auth.nu_material.resize(nu_material_start);
    auth.holder_tags.resize(holder_tag_start);
    auth.global_invocations.resize(global_invocation_start);
    report.post_cleanup_dealer_batches =
            auth.dealer_batches.size() - dealer_batch_start;
    report.post_cleanup_nu_material =
            auth.nu_material.size() - nu_material_start;
    report.post_cleanup_holder_tags =
            auth.holder_tags.size() - holder_tag_start;
    report.post_cleanup_global_invocations =
            auth.global_invocations.size() - global_invocation_start;
    report.retained_dealer_batches = auth.dealer_batches.size();
    report.retained_nu_material = auth.nu_material.size();
    report.retained_holder_tags = auth.holder_tags.size();
    report.retained_global_invocations = auth.global_invocations.size();
}

template<class T>
void AtlasGsz<T>::print_integrated_batch_report(
        const IntegratedBatchReport& report) const
{
    if (P.my_num() != 0 || not report.valid)
        return;
    auto reason = [&] {
        switch (report.flush_reason)
        {
        case VerificationBatchFlushReason::threshold:
            return "threshold";
        case VerificationBatchFlushReason::eligibility_boundary:
            return "eligibility-boundary";
        case VerificationBatchFlushReason::explicit_test_residual:
            return "explicit-residual";
        case VerificationBatchFlushReason::destructor:
            return "destructor";
        case VerificationBatchFlushReason::none:
            return "none";
        }
        return "invalid";
    };
    cout << "ATLAS_GSZ_INTEGRATED_BATCH"
         << " serial=" << report.verification_batch_serial
         << " reason=" << reason()
         << " scalar_ops=" << report.ordinary_scalar_operations
         << " dot_ops=" << report.ordinary_dot_operations
         << " total_ops=" << report.operation_shapes.size()
         << " coordinates=" << report.x_verify_coordinates
         << " transcripts=" << report.partial_transcripts
         << " shape=";
    for (size_t i = 0; i < report.operation_shapes.size(); i++)
    {
        if (i != 0)
            cout << ',';
        cout << (report.operation_shapes.at(i).kind
                        == OrdinaryDoubleRandOperationKind::
                                scalar_multiplication
                        ? "scalar"
                        : "dot")
             << ':' << report.operation_shapes.at(i).length;
    }
    cout << " dealer_sources=";
    for (size_t i = 0; i < report.per_dealer_source_counts.size(); i++)
    {
        if (i != 0)
            cout << ',';
        cout << report.per_dealer_source_counts.at(i);
    }
    cout << " dealer_chunks=";
    for (size_t i = 0; i < report.per_dealer_ftag_chunk_counts.size(); i++)
    {
        if (i != 0)
            cout << ',';
        cout << report.per_dealer_ftag_chunk_counts.at(i);
    }
    cout << " handles=" << report.committed_handles
         << " r_t=" << report.r_t_derivations
         << " e_t=" << report.direct_e_t_handles
         << " z_t=" << report.z_t_derivations
         << " local_eval=" << report.r_t_local_evaluations << '/'
         << report.e_t_local_evaluations << '/'
         << report.z_t_local_evaluations
         << " verify_sharing=" << report.verify_sharing_invocations
         << " key_setup=" << report.check_key_setup_runs
         << " check_key=" << report.check_key_runs
         << " base_sharing=" << report.checked_base_sharings
         << " ordinary_relations=" << report.ordinary_tag_nu_relations
         << " base_relations=" << report.base_tag_nu_relations
         << " check_tag_challenges="
         << report.global_check_tag_challenges
         << " gs20_challenges="
         << report.gs20_de_linearization_challenges << '/'
         << report.gs20_dimension_reduction_challenges << '/'
         << report.gs20_randomization_logical_challenges << '/'
         << report.gs20_randomization_raw_samples
         << " comm_gs20=" << report.gs20_communication
         << " comm_verify=" << report.verify_sharing_communication
         << " comm_key=" << report.key_check_communication
         << " comm_base=" << report.base_sharing_communication
         << " comm_ordinary_tag=" << report.ordinary_tag_communication
         << " comm_base_tag=" << report.base_tag_communication
         << " comm_check_tag=" << report.check_tag_communication
         << " comm_auth=" << report.total_authentication_communication
         << " comm_total=" << report.total_integrated_communication
         << " authentication="
         << report.authentication_invocations_started << '/'
         << report.authentication_invocations_completed << '/'
         << report.authentication_invocations_accepted
         << " runtime=unavailable"
         << " cleanup_verify=" << report.post_cleanup_x_verify << '/'
         << report.post_cleanup_y_verify << '/'
         << report.post_cleanup_z_verify << '/'
         << report.post_cleanup_partial_transcripts
         << " cleanup_virtual="
         << report.post_cleanup_virtual_transcripts << '/'
         << report.post_cleanup_virtual_king_evidence
         << " cleanup_capture="
         << report.post_cleanup_capture_active << '/'
         << report.post_cleanup_capture_finalized << '/'
         << report.post_cleanup_capture_producers << '/'
         << report.post_cleanup_capture_consumptions << '/'
         << report.post_cleanup_capture_producer_indices << '/'
         << report.post_cleanup_capture_output_indices
         << " cleanup_frozen=" << report.post_cleanup_frozen_batches
         << " cleanup_receipt="
         << report.post_cleanup_receipt_dealer_batches << '/'
         << report.post_cleanup_receipt_source_handles << '/'
         << report.post_cleanup_receipt_r_t << '/'
         << report.post_cleanup_receipt_e_t << '/'
         << report.post_cleanup_receipt_z_t
         << " cleanup_auth=" << report.post_cleanup_dealer_batches << '/'
         << report.post_cleanup_nu_material << '/'
         << report.post_cleanup_holder_tags << '/'
         << report.post_cleanup_global_invocations
         << " retained_auth=" << report.retained_dealer_batches << '/'
         << report.retained_nu_material << '/'
         << report.retained_holder_tags << '/'
         << report.retained_global_invocations
         << " persistent_keys=" << report.persistent_reusable_keys
         << " key_epoch=" << report.persistent_key_epoch
         << endl;
}

template<class T>
void AtlasGsz<T>::print_communication_audit_batch(
        const IntegratedBatchReport& report) const
{
    if (not communication_audit_enabled() || not report.valid)
        return;

    auto reason = [&] {
        switch (report.flush_reason)
        {
        case VerificationBatchFlushReason::threshold:
            return "threshold";
        case VerificationBatchFlushReason::eligibility_boundary:
            return "eligibility-boundary";
        case VerificationBatchFlushReason::explicit_test_residual:
            return "explicit-residual";
        case VerificationBatchFlushReason::destructor:
            return "destructor";
        case VerificationBatchFlushReason::none:
            return "direct-check";
        }
        return "invalid";
    };
    const size_t total_source_chunks = accumulate(
            report.per_dealer_ftag_chunk_counts.begin(),
            report.per_dealer_ftag_chunk_counts.end(), size_t(0));

    cout << "ATLAS_GSZ_COMM_AUDIT_BATCH"
         << " party=" << P.my_num()
         << " communication_scope=party-local-sent-bytes"
         << " serial=" << report.verification_batch_serial
         << " reason=" << reason()
         << " operations=" << report.operation_shapes.size()
         << " scalar_operations=" << report.ordinary_scalar_operations
         << " dot_operations=" << report.ordinary_dot_operations
         << " x_verify_coordinates=" << report.x_verify_coordinates
         << " transcripts=" << report.partial_transcripts
         << " contributing_dealers="
         << report.per_dealer_source_counts.size()
         << " dealer_sources=";
    for (size_t dealer = 0;
            dealer < report.per_dealer_source_counts.size(); dealer++)
    {
        if (dealer != 0)
            cout << ',';
        cout << dealer << ':'
             << report.per_dealer_source_counts.at(dealer);
    }
    cout << " dealer_chunks=";
    for (size_t dealer = 0;
            dealer < report.per_dealer_ftag_chunk_counts.size(); dealer++)
    {
        if (dealer != 0)
            cout << ',';
        cout << dealer << ':'
             << report.per_dealer_ftag_chunk_counts.at(dealer);
    }
    cout << " total_source_chunks=" << total_source_chunks
         << " persistent_verifier_holder_keys="
         << report.persistent_reusable_keys
         << " ordinary_key_chunk_relations="
         << report.ordinary_tag_nu_relations
         << " base_key_chunk_relations="
         << report.base_tag_nu_relations
         << " comm_gs20=" << report.gs20_communication
         << " comm_verify_sharing="
         << report.verify_sharing_communication
         << " comm_width_and_check_key="
         << report.key_check_communication
         << " comm_base_sharing="
         << report.base_sharing_communication
         << " comm_ordinary_tags="
         << report.ordinary_tag_communication
         << " comm_base_tags=" << report.base_tag_communication
         << " comm_check_tag=" << report.check_tag_communication
         << " comm_authentication="
         << report.total_authentication_communication
         << endl;
}

template<class T>
void AtlasGsz<T>::print_communication_audit_summary() const
{
    if (not communication_audit_enabled())
        return;

    const auto& integrated = integrated_ordinary_batch_state;
    const auto& auth = optimistic_authentication_state;
    const size_t accounted_authentication_communication =
            auth.verify_sharing_communication
            + auth.base_field_ftag_chunk_width_agreement_communication
            + auth.key_establishment_communication
            + auth.base_sharing_communication
            + auth.ordinary_tag_generation_communication
            + auth.base_tag_generation_communication
            + auth.tag_checking_communication;
    const bool accounting_consistent =
            integrated.total_authentication_communication
                    >= accounted_authentication_communication;
    const size_t unattributed_authentication_communication =
            accounting_consistent
            ? integrated.total_authentication_communication
                    - accounted_authentication_communication
            : 0;

    cout << "ATLAS_GSZ_COMM_AUDIT_TOTAL"
         << " party=" << P.my_num()
         << " communication_scope=party-local-sent-bytes"
         << " chunk_width=" << base_field_ftag_chunk_width()
         << " batches=" << integrated.authentication_invocations
         << " reason_threshold=" << integrated.threshold_batches
         << " reason_eligibility_boundary="
         << integrated.eligibility_boundary_batches
         << " reason_explicit_residual="
         << integrated.explicit_residual_batches
         << " reason_destructor=" << integrated.destructor_batches
         << " reason_direct_check=" << integrated.direct_check_batches
         << " operations=" << integrated.ordinary_operations
         << " scalar_operations="
         << integrated.ordinary_scalar_operations
         << " dot_operations=" << integrated.ordinary_dot_operations
         << " x_verify_coordinates="
         << integrated.x_verify_coordinates
         << " transcripts=" << integrated.partial_transcripts
         << " persistent_verifier_holder_keys=" << auth.keys.size()
         << " total_source_chunks=" << auth.total_ftag_chunks
         << " ordinary_key_chunk_relations="
         << integrated.ordinary_tag_nu_relations
         << " base_key_chunk_relations="
         << integrated.base_tag_nu_relations
         << " authentication_started="
         << integrated.authentication_invocations
         << " authentication_completed="
         << integrated.authentication_invocations_completed
         << " authentication_accepted="
         << integrated.authentication_invocations_accepted
         << " comm_gs20=" << integrated.gs20_communication
         << " comm_verify_sharing="
         << auth.verify_sharing_communication
         << " comm_width_and_check_key="
         << auth.base_field_ftag_chunk_width_agreement_communication
                    + auth.key_establishment_communication
         << " comm_base_sharing=" << auth.base_sharing_communication
         << " comm_ordinary_tags="
         << auth.ordinary_tag_generation_communication
         << " comm_base_tags="
         << auth.base_tag_generation_communication
         << " comm_check_tag=" << auth.tag_checking_communication
         << " comm_authentication="
         << integrated.total_authentication_communication
         << " comm_authentication_accounted="
         << accounted_authentication_communication
         << " comm_authentication_unattributed="
         << unattributed_authentication_communication
         << " authentication_accounting_consistent="
         << accounting_consistent
         << " comm_player_total=" << P.total_comm().sent
         << endl;
}

template<class T>
void AtlasGsz<T>::maybe_flush_honest_batch_integration_residual()
{
    auto& integrated = integrated_ordinary_batch_state;
    if (honest_batch_integration_test_mode.empty()
            || honest_batch_integration_test_hook_ran)
        return;
    const size_t operations = integrated.ordinary_operations;
    if (operations == 2 || operations == 12)
        request_check(VerificationBatchFlushReason::explicit_test_residual);
    if (operations != 12)
        return;

    auto& auth = optimistic_authentication_state;
    const uint64_t next_batch_id = auth.next_batch_id;
    const uint64_t next_invocation_id = auth.next_global_invocation_id;
    const size_t communication = P.total_comm().sent;
    const size_t gs20_checks = integrated.gs20_checks;
    const size_t auth_invocations = integrated.authentication_invocations;
    const size_t auth_completed =
            integrated.authentication_invocations_completed;
    const size_t auth_accepted =
            integrated.authentication_invocations_accepted;
    check();
    if (auth.next_batch_id != next_batch_id
            || auth.next_global_invocation_id != next_invocation_id
            || P.total_comm().sent != communication
            || integrated.gs20_checks != gs20_checks
            || integrated.authentication_invocations != auth_invocations
            || integrated.authentication_invocations_completed
                    != auth_completed
            || integrated.authentication_invocations_accepted
                    != auth_accepted
            || not x_verify.empty() || not y_verify.empty()
            || not z_verify.empty() || not partial_mult_transcripts.empty()
            || integrated.lifecycle != OrdinaryBatchLifecycle::idle
            || integrated.threshold_batches != 4
            || integrated.eligibility_boundary_batches != 1
            || integrated.explicit_residual_batches != 2
            || integrated.gs20_checks != 8
            || integrated.authentication_invocations != 7
            || integrated.authentication_invocations_completed != 7
            || integrated.authentication_invocations_accepted != 7
            || integrated.ordinary_scalar_operations != 7
            || integrated.ordinary_dot_operations != 5
            || integrated.ordinary_operations != 12
            || integrated.x_verify_coordinates != 23
            || integrated.partial_transcripts != 12
            || auth.keys.size()
                    != size_t(P.num_players() * (P.num_players() - 1))
            || auth.key_epoch != 1
            || auth.verify_sharing_invocations
                    != size_t(7 * P.num_players())
            || auth.base_sharing_checks
                    != size_t(7 * P.num_players())
            || auth.global_check_tag_challenges != 7
            || integrated.committed_handles
                    != size_t(P.num_players() == 3 ? 36 : 52)
            || integrated.r_t_derivations != 12
            || integrated.direct_e_t_handles != 12
            || integrated.z_t_derivations != 12
            || integrated.ordinary_tag_nu_relations
                    != size_t(P.num_players() == 3 ? 126 : 700)
            || integrated.base_tag_nu_relations
                    != size_t(P.num_players() == 3 ? 126 : 700)
            || auth.verify_sharing_communication == 0
            || auth.key_establishment_communication == 0
            || auth.base_sharing_communication == 0
            || auth.ordinary_tag_generation_communication == 0
            || auth.base_tag_generation_communication == 0
            || auth.tag_checking_communication == 0
            || not integrated.latest_batch.valid
            || integrated.latest_batch.post_cleanup_dealer_batches != 0
            || integrated.latest_batch.post_cleanup_nu_material != 0
            || integrated.latest_batch.post_cleanup_holder_tags != 0
            || integrated.latest_batch.post_cleanup_global_invocations != 0
            || integrated.latest_batch.post_cleanup_virtual_transcripts != 0
            || integrated.latest_batch
                    .post_cleanup_virtual_king_evidence != 0
            || integrated.latest_batch.post_cleanup_capture_active != 0
            || integrated.latest_batch.post_cleanup_capture_finalized != 0
            || integrated.latest_batch.post_cleanup_capture_producers != 0
            || integrated.latest_batch.post_cleanup_capture_consumptions != 0
            || integrated.latest_batch
                    .post_cleanup_capture_producer_indices != 0
            || integrated.latest_batch
                    .post_cleanup_capture_output_indices != 0
            || integrated.latest_batch.post_cleanup_frozen_batches != 0
            || integrated.latest_batch
                    .post_cleanup_receipt_dealer_batches != 0
            || integrated.latest_batch
                    .post_cleanup_receipt_source_handles != 0
            || integrated.latest_batch.post_cleanup_receipt_r_t != 0
            || integrated.latest_batch.post_cleanup_receipt_e_t != 0
            || integrated.latest_batch.post_cleanup_receipt_z_t != 0)
        throw logic_error(
                "AtlasGsz: honest batch integration cumulative test failed");

    honest_batch_integration_test_hook_ran = true;
    if (P.my_num() == 0)
        cout << "ATLAS_GSZ_AUTH_TEST "
             << honest_batch_integration_test_mode
             << " PASS production_threshold="
             << AtlasConfig::max_before_check
             << " effective_threshold=" << effective_max_before_check()
             << " scalar_ops=" << integrated.ordinary_scalar_operations
             << " dot_ops=" << integrated.ordinary_dot_operations
             << " total_ops=" << integrated.ordinary_operations
             << " coordinates=" << integrated.x_verify_coordinates
             << " transcripts=" << integrated.partial_transcripts
             << " threshold_batches=" << integrated.threshold_batches
             << " boundary_batches="
             << integrated.eligibility_boundary_batches
             << " residual_batches=" << integrated.explicit_residual_batches
             << " gs20_checks=" << integrated.gs20_checks
             << " authentication_invocations="
             << integrated.authentication_invocations
             << " authentication_completed="
             << integrated.authentication_invocations_completed
             << " authentication_accepted="
             << integrated.authentication_invocations_accepted
             << " committed_handles=" << integrated.committed_handles
             << " r_t=" << integrated.r_t_derivations
             << " e_t=" << integrated.direct_e_t_handles
             << " z_t=" << integrated.z_t_derivations
             << " ordinary_relations="
             << integrated.ordinary_tag_nu_relations
             << " base_relations=" << integrated.base_tag_nu_relations
             << " ftag_chunks=" << auth.total_ftag_chunks
             << " verify_sharing=" << auth.verify_sharing_invocations
             << " check_key_setup=" << auth.key_establishment_runs
             << " check_key=" << auth.check_key_runs
             << " base_sharing=" << auth.base_sharing_checks
             << " check_tag_challenges="
             << auth.global_check_tag_challenges
             << " gs20_challenges="
             << integrated.gs20_de_linearization_challenges << '/'
             << integrated.gs20_dimension_reduction_challenges << '/'
             << integrated.gs20_randomization_logical_challenges << '/'
             << integrated.gs20_randomization_raw_samples
             << " comm_gs20=" << integrated.gs20_communication
             << " comm_verify=" << auth.verify_sharing_communication
             << " comm_key="
             << auth.base_field_ftag_chunk_width_agreement_communication
                        + auth.key_establishment_communication
             << " comm_base=" << auth.base_sharing_communication
             << " comm_ordinary_tag="
             << auth.ordinary_tag_generation_communication
             << " comm_base_tag=" << auth.base_tag_generation_communication
             << " comm_check_tag=" << auth.tag_checking_communication
             << " comm_auth="
             << integrated.total_authentication_communication
             << " comm_total=" << integrated.total_integrated_communication
             << " runtime=unavailable"
             << " empty_check=no-op"
             << " post_cleanup=bounded-zero"
             << " persistent_keys=" << auth.keys.size()
             << " key_epoch=" << auth.key_epoch
             << endl;
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
    auto& integrated = integrated_ordinary_batch_state;
    if (integrated.lifecycle == OrdinaryBatchLifecycle::checking_gs20
            || integrated.lifecycle
                    == OrdinaryBatchLifecycle::authenticating_sources)
    {
        integrated.lifecycle = OrdinaryBatchLifecycle::failed;
        throw logic_error("AtlasGsz: recursive check during GS20/authentication");
    }
    if (integrated.lifecycle == OrdinaryBatchLifecycle::failed)
        throw logic_error("AtlasGsz: check attempted after fatal batch failure");

    assert(not have_ultimate_failure_context);
    assert(not ultimate_failure_context.valid);
    validate_dispute_control_state();
#ifndef NDEBUG
    validate_verifiable_registry();
    validate_segment_lifecycle();
    validate_authentication_plan();
    validate_authentication_material();
#endif
    if (x_verify.empty())
        return;
    if (integrated.wrapper_operation_active)
    {
        integrated.lifecycle = OrdinaryBatchLifecycle::failed;
        throw logic_error(
                "AtlasGsz: check entered with an incomplete wrapper operation");
    }

    validate_partial_mult_transcript_coverage();
    const bool integrated_ordinary =
            automatic_ordinary_integration_enabled()
            && integrated.lifecycle
                    == OrdinaryBatchLifecycle::capturing_ordinary;
    if (integrated_ordinary)
    {
        try
        {
        if (not verification_batch_is_eligible_ordinary()
                || not tentative_double_rand_capture_state.active
                || tentative_double_rand_capture_state
                        .consumptions.size()
                        != partial_mult_transcripts.size()
                || not finalize_tentative_double_rand_capture())
        {
            integrated.lifecycle = OrdinaryBatchLifecycle::failed;
            throw logic_error(
                    "AtlasGsz: malformed ordinary batch rejected before GS20");
        }
        if (honest_batch_integration_test_mode
                        == "honest-batch-integration-preflight-rejections"
                && integrated.current_verification_batch_serial == 1)
        {
            const auto* valid = inspect_tentative_double_rand_capture();
            if (valid == 0 || valid->consumed_outputs.size() < 2)
                throw logic_error(
                        "AtlasGsz: preflight rejection test lacks two operations");
            const size_t communication_before = P.total_comm().sent;
            const uint64_t batch_id_before =
                    optimistic_authentication_state.next_batch_id;
            const uint64_t invocation_id_before =
                    optimistic_authentication_state
                            .next_global_invocation_id;
            TentativeDoubleRandCaptureCandidate missing = *valid;
            missing.consumed_outputs.pop_back();
            TentativeDoubleRandCaptureCandidate duplicate = *valid;
            duplicate.consumed_outputs.at(1) =
                    duplicate.consumed_outputs.at(0);
            TentativeDoubleRandCaptureCandidate reordered = *valid;
            swap(reordered.consumed_outputs.at(0),
                    reordered.consumed_outputs.at(1));
            TentativeDoubleRandCaptureCandidate substituted = *valid;
            substituted.consumed_outputs.at(0)
                    .producer_output_ordinal++;
            TentativeDoubleRandCaptureCandidate malformed = *valid;
            malformed.dealer_sources.front().sources.pop_back();
            const uint64_t serial =
                    partial_mult_transcripts.front()
                            .verification_batch_serial;
            partial_mult_transcripts.front().verification_batch_serial =
                    serial + 1;
            const bool accepted_cross_batch =
                    validate_exact_ordinary_batch_correspondence(*valid);
            partial_mult_transcripts.front().verification_batch_serial =
                    serial;
            if (validate_exact_ordinary_batch_correspondence(missing)
                    || validate_exact_ordinary_batch_correspondence(
                            duplicate)
                    || validate_exact_ordinary_batch_correspondence(
                            reordered)
                    || validate_exact_ordinary_batch_correspondence(
                            substituted)
                    || validate_exact_ordinary_batch_correspondence(
                            malformed)
                    || accepted_cross_batch
                    || not validate_exact_ordinary_batch_correspondence(
                            *valid)
                    || P.total_comm().sent != communication_before
                    || optimistic_authentication_state.next_batch_id
                            != batch_id_before
                    || optimistic_authentication_state
                            .next_global_invocation_id
                            != invocation_id_before)
                throw logic_error(
                        "AtlasGsz: malformed ordinary preflight was not communication-free and atomic");
            if (P.my_num() == 0)
                cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-preflight-rejections"
                     << " PASS malformed=reject missing=reject duplicate=reject"
                     << " reordered=reject substituted=reject cross-batch=reject"
                     << " communication=0 authentication_invocations=0"
                     << endl;
        }
        integrated.frozen_batch =
                freeze_finalized_tentative_double_rand_candidate();
        if (not integrated.frozen_batch)
        {
            integrated.lifecycle = OrdinaryBatchLifecycle::failed;
            throw logic_error(
                    "AtlasGsz: exact ordinary freeze/preflight failed before GS20");
        }
        integrated.lifecycle = OrdinaryBatchLifecycle::checking_gs20;
        }
        catch (...)
        {
            integrated.lifecycle = OrdinaryBatchLifecycle::failed;
            throw;
        }
    }
    else if (automatic_ordinary_integration_enabled()
            && (tentative_double_rand_capture_state.active
                    || tentative_double_rand_capture_state
                            .finalized_candidate
                    || integrated.frozen_batch))
    {
        integrated.lifecycle = OrdinaryBatchLifecycle::failed;
        throw logic_error(
                string("AtlasGsz: unsupported-only GS20 batch retained ordinary capture state active=")
                + to_string(tentative_double_rand_capture_state.active)
                + " finalized="
                + to_string(bool(tentative_double_rand_capture_state
                        .finalized_candidate))
                + " frozen=" + to_string(bool(integrated.frozen_batch))
                + " records=" + to_string(partial_mult_transcripts.size())
                + " coordinates=" + to_string(x_verify.size()));
    }

    // Every nonempty verification batch, eligible or unsupported-only, is
    // guarded by the same fatal GS20 lifecycle.
    integrated.lifecycle = OrdinaryBatchLifecycle::checking_gs20;
    integrated.inject_unsupported_gs20_failure =
            not integrated_ordinary
            && honest_batch_integration_test_mode
                    == "honest-batch-integration-unsupported-gs20-failure";

#ifndef NDEBUG
    bool dispute_state_was_initialized =
            dispute_control_state.initialized;
    auto corr_before_check = dispute_control_state.corr;
    auto disp_before_check = dispute_control_state.disp;
#endif

    IntegratedBatchReport report{};
    bool report_successful_unsupported_batch = false;
    size_t successful_unsupported_coordinates = 0;
    size_t successful_unsupported_transcripts = 0;
    bool report_preprocessing_mul_public_batch = false;
    size_t preprocessing_mul_public_transcripts = 0;
    if (integrated_ordinary)
    {
        report.valid = true;
        report.verification_batch_serial =
                integrated.current_verification_batch_serial;
        report.flush_reason = integrated.pending_flush_reason;
        report.x_verify_coordinates = x_verify.size();
        report.partial_transcripts = partial_mult_transcripts.size();
        report.operation_shapes.reserve(partial_mult_transcripts.size());
        for (const auto& record : partial_mult_transcripts)
        {
            OrdinaryBatchOperationShape shape{};
            shape.kind = record.operation_kind;
            shape.length = size_t(record.length);
            report.operation_shapes.push_back(shape);
            if (record.operation_kind
                    == OrdinaryDoubleRandOperationKind::scalar_multiplication)
                report.ordinary_scalar_operations++;
            else if (record.operation_kind
                    == OrdinaryDoubleRandOperationKind::dot_product)
                report.ordinary_dot_operations++;
        }
        if (report.flush_reason == VerificationBatchFlushReason::threshold)
            integrated.threshold_batches++;
        else if (report.flush_reason
                == VerificationBatchFlushReason::eligibility_boundary)
            integrated.eligibility_boundary_batches++;
        else if (report.flush_reason
                == VerificationBatchFlushReason::explicit_test_residual)
            integrated.explicit_residual_batches++;
        else if (report.flush_reason
                == VerificationBatchFlushReason::destructor)
            integrated.destructor_batches++;
        else
            integrated.direct_check_batches++;
    }

    const size_t gs20_communication_before = P.total_comm().sent;
    const size_t de_linearization_before =
            integrated.gs20_de_linearization_challenges;
    const size_t dimension_reduction_before =
            integrated.gs20_dimension_reduction_challenges;
    const size_t randomization_logical_before =
            integrated.gs20_randomization_logical_challenges;
    const size_t randomization_raw_before =
            integrated.gs20_randomization_raw_samples;
    const size_t gs20_checks_before = integrated.gs20_checks;
    const size_t authentication_invocations_before =
            integrated.authentication_invocations;
    try
    {
        integrated.gs20_checks++;
        integrated.gs20_de_linearization_challenges++;
        de_linearization();
        while (x_verify.size() > 1)
        {
            integrated.gs20_dimension_reduction_challenges++;
            dimension_reduction();
        }
        integrated.gs20_randomization_logical_challenges++;
        randomization();
    }
    catch (...)
    {
        const size_t gs20_communication =
                P.total_comm().sent - gs20_communication_before;
        integrated.gs20_communication += gs20_communication;
        if (integrated_ordinary)
            integrated.total_integrated_communication +=
                    gs20_communication;
        integrated.inject_unsupported_gs20_failure = false;
        integrated.lifecycle = OrdinaryBatchLifecycle::failed;
        if (integrated_ordinary
                && honest_batch_integration_test_mode
                        == "honest-batch-integration-gs20-failure"
                && P.my_num() == 0)
            cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-gs20-failure"
                 << " PASS gs20_checks=1 authentication_invocations=0"
                 << " gs20_comm=" << gs20_communication
                 << " handles=0 frozen_batch=retained lifecycle=failed"
                 << endl;
        if (not integrated_ordinary
                && honest_batch_integration_test_mode
                        == "honest-batch-integration-unsupported-gs20-failure")
        {
            const size_t second_check_communication_before =
                    P.total_comm().sent;
            const size_t second_check_count_before = integrated.gs20_checks;
            bool second_check_rejected = false;
            try
            {
                check();
            }
            catch (const logic_error&)
            {
                second_check_rejected = true;
            }
            if (not second_check_rejected
                    || integrated.gs20_checks - gs20_checks_before != 1
                    || integrated.authentication_invocations
                            != authentication_invocations_before
                    || integrated.gs20_checks != second_check_count_before
                    || P.total_comm().sent
                            != second_check_communication_before
                    || gs20_communication == 0
                    || integrated.lifecycle
                            != OrdinaryBatchLifecycle::failed)
                throw logic_error(
                        "AtlasGsz: unsupported GS20 failure did not remain communication-free and fatal");
            if (P.my_num() == 0)
                cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-unsupported-gs20-failure"
                     << " PASS current_batch_gs20_checks=1"
                     << " current_batch_authentication_started=0"
                     << " gs20_comm=" << gs20_communication
                     << " second_check_comm=0 lifecycle=failed"
                     << endl;
        }
        throw;
    }
    const size_t gs20_communication =
            P.total_comm().sent - gs20_communication_before;
    integrated.gs20_communication += gs20_communication;
    if (integrated_ordinary)
        integrated.total_integrated_communication += gs20_communication;
    integrated.inject_unsupported_gs20_failure = false;

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

    const char* selected_test_mode = getenv("ATLAS_GSZ_AUTH_TEST");
    if (not integrated_ordinary
            && selected_test_mode != 0
            && string(selected_test_mode)
                    == "honest-batch-integration-nested-preprocessing"
            && integrated.preprocessing_initialization_wrappers_replaced > 0
            && not integrated.preprocessing_mul_public_test_reported)
    {
        bool all_mul_public_records = not partial_mult_transcripts.empty();
        for (const auto& record : partial_mult_transcripts)
            all_mul_public_records &= record.operation_kind
                    == OrdinaryDoubleRandOperationKind::noneligible
                    && record.length == 1;
        if (not all_mul_public_records
                || integrated.preprocessing_mul_public_records
                        < partial_mult_transcripts.size()
                || integrated.authentication_invocations
                        != authentication_invocations_before)
            throw logic_error(
                    "AtlasGsz: real preprocessing mul-public branch was not GS20-only verified");
        integrated.preprocessing_mul_public_test_reported = true;
        report_preprocessing_mul_public_batch = true;
        preprocessing_mul_public_transcripts =
                partial_mult_transcripts.size();
    }
    if (not integrated_ordinary
            && not honest_batch_integration_test_mode.empty())
    {
        if (integrated.authentication_invocations
                != authentication_invocations_before)
            throw logic_error(
                    "AtlasGsz: unsupported-only GS20 batch started authentication");
        report_successful_unsupported_batch = true;
        successful_unsupported_coordinates = x_verify.size();
        successful_unsupported_transcripts =
                partial_mult_transcripts.size();
    }

    if (integrated_ordinary)
    {
        try
        {
        auto& auth = optimistic_authentication_state;
        report.gs20_communication = gs20_communication;
        report.gs20_de_linearization_challenges =
                integrated.gs20_de_linearization_challenges
                - de_linearization_before;
        report.gs20_dimension_reduction_challenges =
                integrated.gs20_dimension_reduction_challenges
                - dimension_reduction_before;
        report.gs20_randomization_logical_challenges =
                integrated.gs20_randomization_logical_challenges
                - randomization_logical_before;
        report.gs20_randomization_raw_samples =
                integrated.gs20_randomization_raw_samples
                - randomization_raw_before;

        const size_t dealer_batch_start = auth.dealer_batches.size();
        const size_t nu_material_start = auth.nu_material.size();
        const size_t holder_tag_start = auth.holder_tags.size();
        const size_t global_invocation_start =
                auth.global_invocations.size();
        const size_t auth_communication_before = P.total_comm().sent;
        const size_t verify_invocations_before =
                auth.verify_sharing_invocations;
        const size_t key_setup_before = auth.key_establishment_runs;
        const size_t check_key_before = auth.check_key_runs;
        const size_t base_checks_before = auth.base_sharing_checks;
        const size_t verify_comm_before =
                auth.verify_sharing_communication;
        const size_t width_comm_before =
                auth.base_field_ftag_chunk_width_agreement_communication;
        const size_t key_comm_before =
                auth.key_establishment_communication;
        const size_t base_comm_before = auth.base_sharing_communication;
        const size_t ordinary_tag_comm_before =
                auth.ordinary_tag_generation_communication;
        const size_t base_tag_comm_before =
                auth.base_tag_generation_communication;
        const size_t check_tag_comm_before =
                auth.tag_checking_communication;
        const size_t challenge_before =
                auth.global_check_tag_challenges;

        integrated.lifecycle =
                OrdinaryBatchLifecycle::authenticating_sources;
        GlobalAuthenticationTestFault test_fault =
                GlobalAuthenticationTestFault::none;
        int bad_verify_dealer = -1;
        if (honest_batch_integration_test_mode
                == "honest-batch-integration-auth-rejection")
            bad_verify_dealer = 0;
        bool authentication_communication_recorded = false;
        size_t auth_communication = 0;
        auto record_authentication_communication = [&] {
            if (authentication_communication_recorded)
                return;
            auth_communication =
                    P.total_comm().sent - auth_communication_before;
            integrated.total_authentication_communication +=
                    auth_communication;
            integrated.total_integrated_communication +=
                    auth_communication;
            authentication_communication_recorded = true;
        };
        integrated.authentication_invocations++;
        report.authentication_invocations_started = 1;
        try
        {
            integrated.adapter_receipt =
                    authenticate_frozen_tentative_double_rand_candidate(
                            *integrated.frozen_batch, test_fault,
                            bad_verify_dealer);
        }
        catch (...)
        {
            record_authentication_communication();
            integrated.lifecycle = OrdinaryBatchLifecycle::failed;
            throw;
        }
        integrated.authentication_invocations_completed++;
        report.authentication_invocations_completed = 1;
        record_authentication_communication();

        if (not integrated.adapter_receipt.authenticated)
        {
            if (honest_batch_integration_test_mode
                    == "honest-batch-integration-auth-rejection"
                    && P.my_num() == 0)
                cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-auth-rejection"
                     << " PASS gs20_checks=1 authentication_started=1"
                     << " authentication_completed=1 authentication_accepted=0"
                     << " auth_comm=" << auth_communication
                     << " handles=0 lifecycle=failed"
                     << endl;
            integrated.lifecycle = OrdinaryBatchLifecycle::failed;
            throw mac_fail(
                    "AtlasGsz: RecoveryNotImplemented after integrated ordinary-source authentication failure");
        }
        integrated.authentication_invocations_accepted++;
        report.authentication_invocations_accepted = 1;

        report.verify_sharing_invocations =
                auth.verify_sharing_invocations - verify_invocations_before;
        report.check_key_setup_runs =
                auth.key_establishment_runs - key_setup_before;
        report.check_key_runs = auth.check_key_runs - check_key_before;
        report.checked_base_sharings =
                auth.base_sharing_checks - base_checks_before;
        report.verify_sharing_communication =
                auth.verify_sharing_communication - verify_comm_before;
        report.key_check_communication =
                auth.base_field_ftag_chunk_width_agreement_communication
                        - width_comm_before
                + auth.key_establishment_communication - key_comm_before;
        report.base_sharing_communication =
                auth.base_sharing_communication - base_comm_before;
        report.ordinary_tag_communication =
                auth.ordinary_tag_generation_communication
                        - ordinary_tag_comm_before;
        report.base_tag_communication =
                auth.base_tag_generation_communication
                        - base_tag_comm_before;
        report.check_tag_communication =
                auth.tag_checking_communication - check_tag_comm_before;
        report.global_check_tag_challenges =
                auth.global_check_tag_challenges - challenge_before;
        report.total_authentication_communication = auth_communication;
        report.total_integrated_communication =
                gs20_communication + auth_communication;
        report.r_t_derivations =
                integrated.adapter_receipt
                        .converted_r_t_derivations.size();
        report.direct_e_t_handles =
                integrated.adapter_receipt
                        .authenticated_e_t_sources.size();
        report.z_t_derivations =
                integrated.adapter_receipt
                        .converted_z_t_derivations.size();
        report.r_t_local_evaluations = report.r_t_derivations;
        report.e_t_local_evaluations = report.direct_e_t_handles;
        report.z_t_local_evaluations = report.z_t_derivations;

        const size_t integrated_batch_count =
                auth.dealer_batches.size() - dealer_batch_start;
        report.per_dealer_source_counts.reserve(integrated_batch_count);
        report.per_dealer_ftag_chunk_counts.reserve(
                integrated_batch_count);
        for (size_t index = dealer_batch_start;
                index < auth.dealer_batches.size(); index++)
        {
            const auto& batch = auth.dealer_batches.at(index);
            report.per_dealer_source_counts.push_back(
                    batch.local_source_shares.size());
            report.per_dealer_ftag_chunk_counts.push_back(
                    batch.ftag_chunk_count);
            report.committed_handles +=
                    batch.authenticated_handles.size();
        }
        report.ordinary_tag_nu_relations = 0;
        report.base_tag_nu_relations = 0;
        for (size_t index = nu_material_start;
                index < auth.nu_material.size(); index++)
            if (auth.nu_material.at(index).check_mask)
                report.base_tag_nu_relations++;
            else
                report.ordinary_tag_nu_relations++;
        integrated.committed_handles += report.committed_handles;
        integrated.r_t_derivations += report.r_t_derivations;
        integrated.direct_e_t_handles += report.direct_e_t_handles;
        integrated.z_t_derivations += report.z_t_derivations;
        integrated.ordinary_tag_nu_relations +=
                report.ordinary_tag_nu_relations;
        integrated.base_tag_nu_relations +=
                report.base_tag_nu_relations;

        cleanup_successful_integrated_batch(
                dealer_batch_start, nu_material_start, holder_tag_start,
                global_invocation_start, report);
        }
        catch (...)
        {
            integrated.lifecycle = OrdinaryBatchLifecycle::failed;
            throw;
        }
    }

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

    if (integrated_ordinary)
    {
        integrated.adapter_receipt =
                TentativeDoubleRandAuthenticationReceipt{};
        integrated.frozen_batch.reset();
        integrated.lifecycle = OrdinaryBatchLifecycle::idle;
        integrated.current_verification_batch_serial = 0;
        integrated.pending_flush_reason =
                VerificationBatchFlushReason::none;
        report.post_cleanup_x_verify = x_verify.size();
        report.post_cleanup_y_verify = y_verify.size();
        report.post_cleanup_z_verify = z_verify.size();
        report.post_cleanup_partial_transcripts =
                partial_mult_transcripts.size();
        report.post_cleanup_virtual_transcripts =
                have_current_virtual_transcript ? 1 : 0;
        report.post_cleanup_virtual_king_evidence =
                have_current_virtual_king_evidence ? 1 : 0;
        report.post_cleanup_capture_active =
                tentative_double_rand_capture_state.active ? 1 : 0;
        report.post_cleanup_capture_finalized =
                tentative_double_rand_capture_state.finalized_candidate
                        ? 1 : 0;
        report.post_cleanup_capture_producers =
                tentative_double_rand_capture_state.producer_records.size();
        report.post_cleanup_capture_consumptions =
                tentative_double_rand_capture_state.consumptions.size();
        report.post_cleanup_capture_producer_indices =
                tentative_double_rand_capture_state
                        .producer_record_ordinals.size();
        for (const auto& output_indices :
                tentative_double_rand_capture_state
                        .consumed_outputs_by_producer)
            report.post_cleanup_capture_output_indices +=
                    output_indices.size();
        report.post_cleanup_frozen_batches =
                integrated.frozen_batch ? 1 : 0;
        report.post_cleanup_receipt_dealer_batches =
                integrated.adapter_receipt.dealer_batches.size();
        report.post_cleanup_receipt_source_handles =
                integrated.adapter_receipt.source_handles.size();
        report.post_cleanup_receipt_r_t = integrated.adapter_receipt
                .converted_r_t_derivations.size();
        report.post_cleanup_receipt_e_t = integrated.adapter_receipt
                .authenticated_e_t_sources.size();
        report.post_cleanup_receipt_z_t = integrated.adapter_receipt
                .converted_z_t_derivations.size();
        report.persistent_reusable_keys =
                optimistic_authentication_state.keys.size();
        report.persistent_key_epoch =
                optimistic_authentication_state.key_epoch;
        integrated.latest_batch = report;
        print_communication_audit_batch(report);
        if (not honest_batch_integration_test_mode.empty())
            print_integrated_batch_report(report);
    }
    else
    {
        integrated.lifecycle = OrdinaryBatchLifecycle::idle;
        integrated.current_verification_batch_serial = 0;
        integrated.pending_flush_reason =
                VerificationBatchFlushReason::none;
        if (report_successful_unsupported_batch && P.my_num() == 0)
            cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-unsupported-boundary"
                 << " PASS coordinates="
                 << successful_unsupported_coordinates
                 << " transcripts="
                 << successful_unsupported_transcripts
                 << " gs20_checks=1 authentication_started=0"
                 << " gs20_comm=" << gs20_communication
                 << " lifecycle=idle cleanup=complete"
                 << endl;
        if (report_preprocessing_mul_public_batch && P.my_num() == 0)
            cout << "ATLAS_GSZ_AUTH_TEST honest-batch-integration-nested-preprocessing"
                 << " PASS empty_init_wrappers_replaced="
                 << integrated.preprocessing_initialization_wrappers_replaced
                 << " real_mul_public_records="
                 << preprocessing_mul_public_transcripts
                 << " gs20_checks="
                 << integrated.gs20_checks - gs20_checks_before
                 << " authentication_started=0"
                 << " gs20_comm=" << gs20_communication
                 << " lifecycle=idle cleanup=complete"
                 << endl;
    }

    if (x_verify.capacity() > AtlasConfig::max_before_shrink)
    {
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
    current_virtual_transcript.special_sharing_support =
            partial_mult_transcripts.front().transcript
                    .special_sharing_support;

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
        if (record.transcript.special_sharing_support
                != current_virtual_transcript.special_sharing_support)
            current_virtual_transcript.special_sharing_support.clear();
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
    if (input_transcript.special_sharing_support
            == transcript_0.special_sharing_support)
        transcript_1.special_sharing_support =
                input_transcript.special_sharing_support;
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
        vector<int> reconstruction_support =
                transcript_1.special_sharing_support;
        if (reconstruction_support.empty())
            for (int i = 0; i < t + 1; i++)
                reconstruction_support.push_back(i);
        auto reconstruction = Shamir<T>::get_rec_factors(
                reconstruction_support);
        for (size_t i = 0; i < reconstruction_support.size(); i++)
            evidence_1_distributed_secret +=
                    evidence_1.distributed_e_t.at(
                            reconstruction_support.at(i))
                    * reconstruction.at(i);
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
    if (transcript_0.special_sharing_support
                    == transcript_1.special_sharing_support
            && transcript_0.special_sharing_support
                    == transcript_2.special_sharing_support)
        next_virtual_transcript.special_sharing_support =
                transcript_0.special_sharing_support;
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
    integrated_ordinary_batch_state.gs20_randomization_raw_samples++;
    typename T::open_type q = sample_agreed_challenge();
    while (q == zero || q == one)
    {
        integrated_ordinary_batch_state.gs20_randomization_raw_samples++;
        q = sample_agreed_challenge();
    }

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
    if (transcript_0.special_sharing_support
                    == transcript_1.special_sharing_support
            && transcript_0.special_sharing_support
                    == transcript_2.special_sharing_support)
        ultimate_transcript.special_sharing_support =
                transcript_0.special_sharing_support;
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

    if (honest_batch_integration_test_mode
                    == "honest-batch-integration-gs20-failure"
            || integrated_ordinary_batch_state
                    .inject_unsupported_gs20_failure)
        ultimate_z += typename T::open_type(1);

    vector<T> ultimate_tuple;
    ultimate_tuple.reserve(3);
    ultimate_tuple.push_back(ultimate_x);
    ultimate_tuple.push_back(ultimate_y);
    ultimate_tuple.push_back(ultimate_z);

    bool ultimate_tuple_passes = false;
    vector<typename T::open_type> opened_ultimate;
    try
    {
        malicious_mc.POpen(opened_ultimate, ultimate_tuple, P);
        assert(opened_ultimate.size() == 3);
        ultimate_tuple_passes =
                opened_ultimate.at(0) * opened_ultimate.at(1)
                == opened_ultimate.at(2);
    }
    catch (const mac_fail&)
    {
        ultimate_tuple_passes = false;
    }

    if (ultimate_tuple_passes)
    {
        ultimate_failure_context = UltimateFailureContext{};
        have_ultimate_failure_context = false;
        return;
    }

    auto published_ultimate = broadcast_local_shares(ultimate_tuple);
    assert(published_ultimate.size() == 3);
    auto alpha = classify_degree_t_sharing(published_ultimate.at(0));
    auto beta = classify_degree_t_sharing(published_ultimate.at(1));
    auto gamma = classify_degree_t_sharing(published_ultimate.at(2));

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

    auto analyze_enqueue_result =
            enqueue_current_ultimate_failure_analyze_request_once();
    ultimate_failure_context.analyze_enqueue_result =
            analyze_enqueue_result;
    ultimate_failure_context.has_analyze_enqueue_result = true;
    validate_ultimate_failure_analyze_enqueue_result(
            ultimate_failure_context.analyze_enqueue_result);

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
