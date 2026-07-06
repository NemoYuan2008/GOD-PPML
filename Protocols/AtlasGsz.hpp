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
    vector<typename T::open_type> opened;
    malicious_mc.POpen(opened, ultimate_tuple, P);
    assert(opened.size() == 3);

    if (opened.at(0) * opened.at(1) != opened.at(2))
        throw mac_fail("AtlasGsz: Verification failed");
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
