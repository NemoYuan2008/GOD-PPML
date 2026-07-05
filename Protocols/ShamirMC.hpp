/*
 * ShamirMC.cpp
 *
 */

#ifndef PROTOCOLS_SHAMIRMC_HPP_
#define PROTOCOLS_SHAMIRMC_HPP_

#include "ShamirMC.h"

#include "MAC_Check_Base.hpp"
#include "Shamir.hpp"

#include "AtlasConfig.h"

template<class T>
ShamirMC<T>::ShamirMC(int t) :
        os(0), player(0), threshold()
{
    if (t > 0)
        threshold = t;
    else
        threshold = ShamirMachine::s().threshold;
}

template<class T>
ShamirMC<T>::~ShamirMC()
{
    if (os)
        delete os;
}

template<class T>
void ShamirMC<T>::POpen_Begin(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    (void) values;
    prepare(S, P);
    P.send_all(os->mine);
}

template<class T>
vector<typename T::open_type::Scalar> ShamirMC<T>::get_reconstruction(
        const Player& P, int n_relevant_players)
{
    if (n_relevant_players == 0)
        n_relevant_players = threshold + 1;
    vector<rec_type> reconstruction(n_relevant_players);
    vector<int> points(n_relevant_players);
    for (int i = 0; i < n_relevant_players; i++)
        points[i] = P.get_player(i);
    return Shamir<T>::get_rec_factors(points);
}

template<class T>
void ShamirMC<T>::init_open(const Player& P, int n)
{
    if (reconstruction.empty())
    {
        reconstruction = get_reconstruction(P);
    }

    if (not os)
        os = new Bundle<octetStream>(P);

    for (auto& o : *os)
        o.reset_write_head();
    os->mine.reserve(n * T::size());
    this->player = &P;
}

template<class T>
void ShamirMC<T>::prepare(const vector<T>& S, const Player& P)
{
    init_open(P, S.size());
    for (auto& share : S)
        prepare_open(share);
}

template<class T>
void ShamirMC<T>::prepare_open(const T& share, int)
{
    share.pack(os->mine);
}

template<class T>
void ShamirMC<T>::POpen(vector<typename T::open_type>& values, const vector<T>& S,
        const Player& P)
{
    prepare(S, P);
    exchange(P);
    finalize(values, S);
}

template<class T>
void ShamirMC<T>::exchange(const Player& P)
{
    vector<bool> my_senders(P.num_players()), my_receivers(P.num_players());
    for (int i = 0; i < P.num_players(); i++)
    {
        my_senders[i] = P.get_offset(i) <= threshold;
        my_receivers[i] = P.get_offset(i) >= P.num_players() - threshold;
    }
    P.partial_broadcast(my_senders, my_receivers, *os);
}

template<class T>
void ShamirMC<T>::POpen_End(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    P.receive_all(*os);
    finalize(values, S);
}

template<class T>
void ShamirMC<T>::finalize(vector<typename T::open_type>& values,
        const vector<T>& S)
{
    values.clear();
    for (size_t i = 0; i < S.size(); i++)
        values.push_back(finalize_raw());
}

template<class T>
array<typename T::open_type*, 2> ShamirMC<T>::finalize_several(size_t n)
{
    this->values.clear();
    finalize(this->values, vector<T>(n));
    return MAC_Check_Base<T>::finalize_several(n);
}

template<class T>
typename T::open_type ShamirMC<T>::finalize_raw()
{
    assert(reconstruction.size());
    typename T::open_type res;
    for (size_t j = 0; j < reconstruction.size(); j++)
    {
        res +=
                (*os)[player->get_player(j)].template get<typename T::open_type>()
                        * reconstruction[j];
    }

    return res;
}

template<class T>
typename T::open_type ShamirMC<T>::reconstruct(const vector<open_type>& shares)
{
    assert(reconstruction.size());
    typename T::open_type res;
    for (size_t j = 0; j < reconstruction.size(); j++)
    {
        res += shares[j] * reconstruction[j];
    }

    return res;
}

template<class T>
void IndirectShamirMC<T>::exchange(const Player& P)
{
    oss.resize(P.num_players());
    static const int threshold = ShamirMachine::s().threshold;
    static auto my_rec_factor = P.my_num() <= threshold ? 
        Shamir<T>::get_rec_factor(P.my_num(), threshold + 1) : T();
    static vector<vector<bool>> channels;
    static bool init = false;
    if (!init)
    {
        channels.resize(P.num_players());
        for (int i = 0; i < P.num_players(); i++)
        {
            channels[i].resize(P.num_players());
            if (i <= threshold)
                channels[i][0] = true;
        }
        init = true;
    }

    if (P.my_num() <= threshold)
    {
        oss[0].reset_write_head();
        for (auto& x : this->secrets)
            (x * my_rec_factor).pack(oss[0]);
        P.send_receive_all(channels, oss, oss);
    }

    if (P.my_num() == 0)
    {
        os.reset_write_head();
        while (oss[0].left())
        {
            T sum;
            for (int i = 0; i <= threshold; i++)
                sum += oss[i].template get<T>();
            sum.pack(os);
        }
        P.send_all(os);
    }

    if (P.my_num() != 0)
        P.receive_player(0, os);

    while (os.left())
        this->values.push_back(os.get<T>());
}

template<class T>
void IndirectShamirMC_2t<T>::begin_received_sharing_recording()
{
    assert(not record_received_sharings);
    recorded_received_sharings.clear();
    record_received_sharings = true;
}

template<class T>
void IndirectShamirMC_2t<T>::end_received_sharing_recording()
{
    assert(record_received_sharings);
    record_received_sharings = false;
}

template<class T>
void IndirectShamirMC_2t<T>::clear_recorded_received_sharings()
{
    assert(not record_received_sharings);
    recorded_received_sharings.clear();
}

template<class T>
size_t IndirectShamirMC_2t<T>::num_recorded_received_sharings() const
{
    return recorded_received_sharings.size();
}

template<class T>
const vector<typename T::open_type>&
IndirectShamirMC_2t<T>::get_recorded_received_sharing(size_t index) const
{
    return recorded_received_sharings.at(index);
}

template<class T>
void IndirectShamirMC_2t<T>::exchange(const Player& P)
{
    this->oss.resize(P.num_players());

    if (inverse_rec_factors.empty())
    {
        opening_rec_factors.reserve(P.num_players());
        inverse_rec_factors.reserve(P.num_players());
        for (int i = 0; i < P.num_players(); i++)
        {
            auto factor = Shamir<T>::get_rec_factor(i, P.num_players());
            opening_rec_factors.push_back(factor);
            inverse_rec_factors.push_back(factor.invert());
        }
    }
    assert(opening_rec_factors.size() == size_t(P.num_players()));
    assert(inverse_rec_factors.size() == size_t(P.num_players()));

    static const auto my_rec_factor = Shamir<T>::get_rec_factor(P.my_num(), P.num_players());
    static vector<vector<bool>> channels;
    static bool init = false;
    if (!init)
    {
        channels.resize(P.num_players());
        for (int i = 0; i < P.num_players(); i++)
        {
            channels[i].resize(P.num_players());
            channels[i][0] = true;
        }
        init = true;
    }

    this->oss[0].reset_write_head();
    for (auto& x : this->secrets) {
        (x * my_rec_factor).pack(this->oss[0]);
    }

    P.send_receive_all(channels, this->oss, this->oss);

    if (P.my_num() == 0)
    {
        this->os.reset_write_head();
        size_t opening_index = 0;
        while (this->oss[0].left())
        {
            T sum{};
            vector<typename T::open_type> raw_sharing;
            if (record_received_sharings)
                raw_sharing.resize(P.num_players());
            for (int i = 0; i < P.num_players(); i++)
            {
                auto weighted = this->oss[i].template get<T>();
                sum += weighted;
                if (record_received_sharings)
                {
                    typename T::open_type weighted_value = weighted;
                    raw_sharing.at(i) =
                            weighted_value * inverse_rec_factors.at(i);
                }
            }
            if (record_received_sharings)
            {
                assert(raw_sharing.size() == size_t(P.num_players()));
                typename T::open_type reconstructed{};
                for (int i = 0; i < P.num_players(); i++)
                    reconstructed += raw_sharing.at(i)
                            * opening_rec_factors.at(i);
                typename T::open_type sum_value = sum;
                assert(reconstructed == sum_value);
                assert(opening_index < this->secrets.size());
                typename T::open_type local_secret =
                        this->secrets.at(opening_index);
                assert(raw_sharing.at(0) == local_secret);
                recorded_received_sharings.push_back(raw_sharing);
            }
            sum.pack(this->os);
            opening_index++;
        }
        P.send_all(this->os);
    }

    if (P.my_num() != 0)
        P.receive_player(0, this->os);

    while (this->os.left())
        this->values.push_back(this->os.template get<T>());
}


/**
 * Prepare opening of a secret at a specific point
 * 
 * The corresponding rec_factor is multiplied to the secret
 */
template <class T>
void IndirectShamirMC_2t<T>::prepare_open_at_point(const T &secret, int target, const Player &P)
{
    static bool init = false;
    // stores my rec factor to the points -1, 0, 1, ..., num_players - 1
    static vector<typename T::open_type::Scalar> rec_factors;
    if (!init) {
        vector<int> points(P.num_players());
        std::iota(points.begin(), points.end(), 0);
        rec_factors.reserve(P.num_players() + 1);
        rec_factors.push_back(Shamir<T>::get_rec_factor(P.my_num(), points, -1));
        for (int target_point = 0; target_point < P.num_players(); ++target_point) {
            rec_factors.push_back(Shamir<T>::get_rec_factor(P.my_num(), points, target_point));
        }
        init = true;
    }

    this->secrets.push_back(secret * rec_factors[target + 1]);
}

/**
 * Exchange secrets and open them
 * 
 * Unlike exchange, this function does not multiply the secrets by rec_factor,
 * since the rec_factor is already multiplied in prepare_open_at_point
 */
template <class T>
void IndirectShamirMC_2t<T>::exchange_no_rec_factor(const Player &P)
{
    this->oss.resize(P.num_players());

    static vector<vector<bool>> channels;
    static bool init = false;
    if (!init)
    {
        channels.resize(P.num_players());
        for (int i = 0; i < P.num_players(); i++)
        {
            channels[i].resize(P.num_players());
            channels[i][0] = true;
        }
        init = true;
    }

    this->oss[0].reset_write_head();
    for (auto& x : this->secrets) {
        x.pack(this->oss[0]);
    }

    P.send_receive_all(channels, this->oss, this->oss);

    if (P.my_num() == 0)
    {
        this->os.reset_write_head();
        while (this->oss[0].left())
        {
            T sum;
            for (int i = 0; i < P.num_players(); i++)
                sum += this->oss[i].template get<T>();
            sum.pack(this->os);
        }
        P.send_all(this->os);
    }

    if (P.my_num() != 0)
        P.receive_player(0, this->os);

    while (this->os.left())
        this->values.push_back(this->os.template get<T>());
}

template<class T>
void CheckedIndirectShamirMC_2t<T>::exchange(const Player& P)
{
    IndirectShamirMC_2t<T>::exchange(P);

    this->stored_values.reserve(AtlasConfig::max_openings_before_check);
    this->stored_secrets.reserve(AtlasConfig::max_openings_before_check);

    // We do not use push_back or back_inserter
    // since Mersenne is as small as uint64_t, and we hope that
    // the compiler can optimize the copy
    this->stored_values.resize(this->stored_values.size() + this->values.size());
    std::copy(this->values.begin(), this->values.end(), this->stored_values.end() - this->values.size());
    
    this->stored_secrets.resize(this->stored_secrets.size() + this->secrets.size());
    std::copy(this->secrets.begin(), this->secrets.end(), this->stored_secrets.end() - this->secrets.size());
}

#endif
