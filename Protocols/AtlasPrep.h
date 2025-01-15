/*
 * AtlasPrep.h
 *
 */

#ifndef PROTOCOLS_ATLASPREP_H_
#define PROTOCOLS_ATLASPREP_H_

#include "ReplicatedPrep.h"

/**
 * ATLAS preprocessing.
 */
template<class T>
class AtlasPrep : public ReplicatedPrep<T>
{
public:
    AtlasPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            ReplicatedRingPrep<T>(proc, usage),
            RingPrep<T>(proc, usage),
            SemiHonestRingPrep<T>(proc, usage),
            ReplicatedPrep<T>(proc, usage)
    {
    }

    /// Input tuples from random sharings
    void buffer_inputs(int player)
    {
        assert(this->protocol and this->proc);
        int batch_size = OnlineOptions::singleton.batch_size;
        typename T::MAC_Check MC;
        vector<T> shares;
        for (int i = 0; i < batch_size; i++)
            shares.push_back(this->protocol->get_random());
        vector<typename T::open_type> opened;
        this->proc->MC.POpen(opened, shares, this->proc->P);
        for (int i = 0; i < batch_size; i++)
            this->inputs.at(player).push_back({shares[i], opened[i]});
    }

    void buffer_bits()
    {
        buffer_bits(T::clear::prime_field, T::clear::characteristic_two);
    }

    template<int = 0>
    void buffer_bits(false_type, false_type) 
    { 
        throw runtime_error("Sorry, AtlasPrep::buffer_bits only implemented "
            "for Mersenne prime fields"); 
    }

    template<int = 0>
    void buffer_bits(false_type, true_type) 
    { 
        throw runtime_error("Sorry, AtlasPrep::buffer_bits only implemented "
            "for Mersenne prime fields"); 
    }

    template<int = 0>
    void buffer_bits(true_type, false_type)
    {
        auto buffer_size = BaseMachine::batch_size<T>(DATA_BIT, this->buffer_size);
        vector<T> randoms(buffer_size);
        std::generate(randoms.begin(), randoms.end(), [this]{return this->protocol->get_random();});

        vector<T> square_opened(buffer_size);

        this->protocol->init_mul_pub();
        for (auto x : randoms) {
            this->protocol->prepare_mul_pub(x, x);
        }
        this->protocol->exchange_mul_pub();
        for (int i = 0; i < buffer_size; i++) {
            square_opened[i] = this->protocol->finalize_mul_pub();
        }

        T one(1); // Assuming T is Mersenne
        T two_inverse = T(2).invert();
        for (int i = 0; i < buffer_size; i++) {
            if (square_opened[i] != 0) {
                this->bits.push_back((randoms[i] / square_opened[i].sqrRoot() + one) * two_inverse);
            }
        }
        if (this->bits.empty()) {
            throw runtime_error("All squares were zero");
        }
    }

    void buffer_inverses() 
    {
        buffer_inverses<0>(T::clear::invertible);
    }

    template<int>
    void buffer_inverses(false_type) 
    { 
        throw runtime_error("Why using Atlas with non-field ring?"); 
    }

    template<int>
    void buffer_inverses(true_type)
    {
        cerr << "AtlasPrep::buffer_inverses\n";
        auto buffer_size = BaseMachine::batch_size<T>(DATA_BIT, this->buffer_size);
        vector<T> a(buffer_size), b(buffer_size);
        std::generate(a.begin(), a.end(), [this]{return this->protocol->get_random();});
        std::generate(b.begin(), b.end(), [this]{return this->protocol->get_random();});

        this->protocol->init_mul_pub();
        for (int i = 0; i < buffer_size; i++) {
            this->protocol->prepare_mul_pub(a[i], b[i]);
        }
        this->protocol->exchange_mul_pub();
        for (int i = 0; i < buffer_size; i++) {
            T c = this->protocol->finalize_mul_pub();
            if (c != 0) {
                this->inverses.push_back({a[i], b[i] / c});
            }
        }
        if (this->inverses.empty()) {
            throw runtime_error("All products were zero");
        }
    }
};

#endif /* PROTOCOLS_ATLASPREP_H_ */
