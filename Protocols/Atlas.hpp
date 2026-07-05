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
array<T, 2> Atlas<T>::get_double_sharing()
{
    if (double_sharings.empty())
    {
        SeededPRNG G;
        PRNG G2 = G;
        auto random = shamir.get_randoms(G, 0);
        auto random2 = shamir2.get_randoms(G2, 0);
        assert(random.size() == random2.size());
        assert(random.size() % P.num_players() == 0);
        for (size_t i = 0; i < random.size(); i++)
            double_sharings.push_back({{random2.at(i), random.at(i)}});
    }

    auto res = double_sharings.back();
    double_sharings.pop_back();
    return res;
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
        const vector<typename Atlas<T>::share_value_type>& sharing) const
{
    int t = ShamirMachine::s().threshold;

    assert(sharing.size() == size_t(P.num_players()));
    assert(reconstruction_t.size() == size_t(t + 1));

    share_value_type res{};
    for (int i = 0; i < t + 1; i++)
        res += sharing.at(i) * reconstruction_t.at(i);
    return res;
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
    assert(next_partial_mult_transcript == pending_partial_mult_transcripts.size());
    assert(pending_king_partial_mult_evidence.empty()
            || pending_king_partial_mult_evidence.size()
                    == next_partial_mult_transcript);
    oss.reset();
    oss2.reset();
    masks.clear();
    base_king = next_king;
    pending_partial_mult_transcripts.clear();
    pending_king_partial_mult_evidence.clear();
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
    T e_2t = product + r[0];
    e_2t.pack(oss2[king]);
    if (not fixed_king_enabled)
        next_king = (next_king + 1) % P.num_players();
    masks.push_back(r[1]);

    PartialMultTranscript transcript{};
    transcript.r_t = r[1];
    transcript.r_2t = r[0];
    transcript.e_2t = e_2t;
    transcript.king = king;
    pending_partial_mult_transcripts.push_back(transcript);
}

template<class T>
void Atlas<T>::exchange()
{
    P.send_receive_all(oss2, oss);
    oss.mine = oss2.mine;
    assert(pending_partial_mult_transcripts.size() == masks.size());

    int t = ShamirMachine::s().threshold;
    if (reconstruction.empty())
        for (int i = 0; i < 2 * t + 1; i++)
            reconstruction.push_back(Shamir<T>::get_rec_factor(i, 2 * t + 1));
    if (reconstruction_t.empty())
        for (int i = 0; i < t + 1; i++)
            reconstruction_t.push_back(Shamir<T>::get_rec_factor(i, t + 1));
    resharing.reset_all(P);

    if (fixed_king_enabled)
    {
        if (P.my_num() == fixed_king)
        {
            assert(pending_king_partial_mult_evidence.empty());
            vector<share_value_type> reconstructed_e_values;
            reconstructed_e_values.reserve(masks.size());
            resharing.begin_mine_sharing_recording();

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
                pending_king_partial_mult_evidence.push_back(evidence);
                reconstructed_e_values.push_back(e);
                resharing.add_mine(e);
            }
            resharing.end_mine_sharing_recording();

            assert(resharing.num_recorded_mine_sharings() == masks.size());
            assert(pending_king_partial_mult_evidence.size() == masks.size());
            for (size_t j = 0; j < pending_king_partial_mult_evidence.size(); j++)
            {
                auto& evidence = pending_king_partial_mult_evidence.at(j);
                evidence.distributed_e_t = resharing.get_recorded_mine_sharing(j);
                assert(evidence.received_e_2t.size() == size_t(P.num_players()));
                assert(evidence.distributed_e_t.size() == size_t(P.num_players()));
                assert(evidence.king == fixed_king);
                assert(reconstruct_distributed_e_t(evidence.distributed_e_t)
                        == reconstructed_e_values.at(j));
            }
            resharing.clear_recorded_mine_sharings();
        }
        else
        {
            assert(pending_king_partial_mult_evidence.empty());
            resharing.clear_recorded_mine_sharings();
        }

        if (not masks.empty())
            resharing.add_sender(fixed_king);
    }
    else
    {
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
    }

    resharing.exchange();
}

template<class T>
T Atlas<T>::finalize_mul(int)
{
    int king = fixed_king_enabled ? fixed_king : base_king;
    T e_t = resharing.finalize(king);
    T r_t = masks.next();
    T res = e_t - r_t;
    size_t transcript_index = next_partial_mult_transcript;
    assert(transcript_index < pending_partial_mult_transcripts.size());
    auto& transcript = pending_partial_mult_transcripts.at(transcript_index);
    next_partial_mult_transcript++;
    assert(transcript.king == king);
    assert(transcript.r_t == r_t);
    transcript.e_t = e_t;
    last_partial_mult_transcript = transcript;
    have_last_partial_mult_transcript = true;
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
        share_value_type local_e_2t = transcript.e_2t;
        share_value_type local_e_t = transcript.e_t;
        assert(last_king_partial_mult_evidence.received_e_2t.at(fixed_king)
                == local_e_2t);
        assert(last_king_partial_mult_evidence.distributed_e_t.at(fixed_king)
                == local_e_t);
    }
    else
    {
        have_last_king_partial_mult_evidence = false;
    }
    if (not fixed_king_enabled)
        base_king = (base_king + 1) % P.num_players();
    return res;
}

template<class T>
void Atlas<T>::set_fixed_king(int king)
{
    if (king < 0 || king >= P.num_players())
        throw std::out_of_range("invalid Atlas fixed king");
    assert(next_partial_mult_transcript == pending_partial_mult_transcripts.size());
    fixed_king_enabled = true;
    fixed_king = king;
}

template<class T>
const typename Atlas<T>::PartialMultTranscript&
Atlas<T>::get_last_partial_mult_transcript() const
{
    assert(have_last_partial_mult_transcript);
    return last_partial_mult_transcript;
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
    local_mc_2t.init_open(P);
}

template <class T>
inline void Atlas<T>::prepare_mul_pub(T x, T y)
{
    // TODO: a zero-sharing is needed here for security
    local_mc_2t.prepare_open(x * y);
}

template <class T>
inline void Atlas<T>::exchange_mul_pub()
{
    local_mc_2t.exchange(P);
}

template <class T>
inline T Atlas<T>::finalize_mul_pub()
{
    return local_mc_2t.finalize_open();
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

    // TODO: a zero-sharing is needed here for security
    auto c = product + r;
    local_mc_2t.prepare_open(c);

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
    local_mc_2t.exchange(P);
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

    if (pre_trunc != nullptr) {
        *pre_trunc = c - r; // This is needed for verification in the maliciously secure version
    }

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

    return c_trunc - r_prime + e * (two_power_k_minus_f - 1) - two_power_k_minus_f_minus_two;
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
