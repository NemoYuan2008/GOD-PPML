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

    size_t expected_offset = 0;
    for (const auto& record : partial_mult_transcripts)
    {
        assert(record.length > 0);
        assert(record.offset == expected_offset);
        assert(record.offset + size_t(record.length) <= x_verify.size());

        T product{};
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
            assert(record.king_evidence.king == record.transcript.king);
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
    dotprod_info[offset] = length;
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
    record.has_king_evidence = false;
    assert(record.transcript.king == 0);
    assert(record.transcript.r_t == T{0});
    assert(record.transcript.e_t - record.transcript.r_t == res);
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
    record.has_king_evidence = false;
    assert(record.transcript.king == 0);
    assert(record.transcript.e_t - record.transcript.r_t == pre_trunc);
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
    dotprod_info[offset] = length;
    T pre_trunc;
    T res = honest.finalize_dotprod_trunc(length, &pre_trunc);
    PartialMultTranscriptRecord record{};
    record.offset = offset;
    record.length = length;
    record.transcript = honest.get_last_partial_mult_transcript();
    record.has_king_evidence = false;
    assert(record.transcript.king == 0);
    assert(record.transcript.e_t - record.transcript.r_t == pre_trunc);
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
    dotprod_info.clear();
    partial_mult_transcripts.clear();

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
    z_de_linearized = 0;

    // Random coin
    typename T::open_type r = local_mc_2t.POpen(get_random(), this->P);

    vector<typename T::open_type> random_coeffs(x_verify.size());
    random_coeffs[0] = r;

    // We compute and store the random coefficients, not compute it on the fly, 
    // to enable the use of std algorithms, which may be faster
    
    // Special case for the first element
    int i;
    if (const auto it = dotprod_info.find(0); it != dotprod_info.end()) {
        // Use the same random coefficient for one dot product
        std::fill_n(random_coeffs.begin(), it->second, r);
        i = it->second;
    } else {
        i = 1;
    }
    // Compute the rest of the coefficients
    for (; i < static_cast<int>(x_verify.size()); ++i) {
        auto it = dotprod_info.find(i);
        if (it != dotprod_info.end()) {
            // Use the same random coefficient for one dot product
            std::fill_n(random_coeffs.begin() + i, it->second, random_coeffs[i - 1] * r);
            i += it->second - 1;
        } else {
            random_coeffs[i] = random_coeffs[i - 1] * r;
        }
    }
    dotprod_info.clear();

    // x_verify = (x_0 r^0, x_1 r^1, ..., x_n r^n); y_verify is unchanged
    std::transform(x_verify.begin(), x_verify.end(), random_coeffs.begin(), x_verify.begin(),
                    std::multiplies<typename T::open_type>());
    
    // z_de_linearized = z_0 r^0 + z_1 r^1 + ... + z_n r^n
    z_de_linearized = std::inner_product(z_verify.begin(), z_verify.end(), random_coeffs.begin(), T{0});
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
    cerr << "random_coeffs: ";
    for (auto c: random_coeffs) {
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
}

/**
 * Protocol 14 and 12 in https://ia.cr/2020/134
 */
template<class T>
void AtlasGsz<T>::dimension_reduction()
{
    if (x_verify.size() & 1) {
        x_verify.emplace_back(0);
        y_verify.emplace_back(0);
    }
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

    T c_0 = honest.finalize_dotprod();
    T c_1 = z_de_linearized - c_0;
    T c_2 = honest.finalize_dotprod();

    // Let h(0) = c_0, h(1) = c_1, h(2) = c_2, we compute the coefficients
    static const typename T::clear two_inverse = (typename T::clear(2)).invert();
    vector<typename T::clear> h_coeffs(3);
    h_coeffs[0] = c_0;
    h_coeffs[1] = c_1 * 2 - two_inverse * (c_0 * 3 + c_2);
    h_coeffs[2] = (c_0 + c_2) * two_inverse - c_1;


    T random_point = local_mc_2t.POpen(get_random(), this->P);

    // Evaluate f_i(random_point) and g_i(random_point), just put them in x_verify and y_verify
    for (int i = 0; i < half_size; ++i) {
        x_verify.push_back(f_coeffs[i][0] + f_coeffs[i][1] * random_point);
        y_verify.push_back(g_coeffs[i][0] + g_coeffs[i][1] * random_point);
    }
    // Evaluate h(random_point), put it in z_de_linearized
    z_de_linearized = h_coeffs[0] + h_coeffs[1] * random_point + h_coeffs[2] * random_point * random_point;


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
    auto h_0_open = debug_mc.POpen(h_coeffs[0], this->P);
    auto h_1_open = debug_mc.POpen(h_coeffs[1], this->P);
    auto h_2_open = debug_mc.POpen(h_coeffs[2], this->P);
    cerr << "h(x) = " << h_0_open << " + " << h_1_open << "x + " << h_2_open << "x^2\n";

    auto c_0_open = debug_mc.POpen(c_0, this->P);
    auto c_1_open = debug_mc.POpen(c_1, this->P);
    auto c_2_open = debug_mc.POpen(c_2, this->P);
    cerr << "c_0=" << c_0_open << " c_1=" << c_1_open << " c_2=" << c_2_open << '\n';

    vector<typename T::open_type> x_verify_open, y_verify_open;
    debug_mc.POpen(x_verify_open, x_verify, this->P);
    debug_mc.POpen(y_verify_open, y_verify, this->P);
    cerr << "random_point = " << random_point << '\n';
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
}

/**
 * Verify the last triple from dimension_reduction
 * 
 * Since we have only one triple left,
 * we use the triple sacrifice technique instead of
 * the original protocol in https://ia.cr/2020/134.
 */
template<class T>
void AtlasGsz<T>::randomization()
{

    T a = get_random();
    T b = get_random();
    T c = this->mul(a, b);

    typename T::clear alpha = local_mc_2t.POpen(get_random(), P);
    T rho = alpha * x_verify[0] + a;
    T sigma = y_verify[0] + b;

    local_mc_2t.init_open(P, 2);
    local_mc_2t.prepare_open(rho);
    local_mc_2t.prepare_open(sigma);
    local_mc_2t.exchange(P);
    auto rho_open = local_mc_2t.finalize_open();
    auto sigma_open = local_mc_2t.finalize_open();

    T v = alpha * z_de_linearized - c + sigma_open * a + rho_open * b - rho_open * sigma_open;
    auto v_open = local_mc_2t.POpen(v, P);

    if (v_open != 0) {
        throw mac_fail("AtlasGsz: Verification failed");
    }
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
