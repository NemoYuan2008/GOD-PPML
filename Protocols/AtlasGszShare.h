/*
 * AtlasGszShare.h
 *
 */

#ifndef PROTOCOLS_ATLASGSZSHARE_H_
#define PROTOCOLS_ATLASGSZSHARE_H_

#include "ShamirShare.h"
#include "ShamirMC.h"

template<class T> class AtlasGsz;
// template<class T> class AtlasGszPrep;

namespace GC
{
class AtlasGszSecret;
}

template<class T>
class AtlasGszShare : public ShamirShare<T>
{
    typedef AtlasGszShare This;
    typedef ShamirShare<T> super;

public:
    typedef AtlasGsz<This> Protocol;
    typedef ShamirInput<This> Input;
    typedef IndirectShamirMC<This> MAC_Check;
    typedef IndirectShamirMC_2t<This> MAC_Check_2t;
    typedef ShamirMC<This> Direct_MC;
    typedef ::PrivateOutput<This> PrivateOutput;
    // typedef AtlasGszPrep<This> LivePrep;
    typedef AtlasPrep<This> LivePrep; // TODO
    typedef LivePrep TriplePrep;

#ifndef NO_MIXED_CIRCUITS
    typedef GC::AtlasSecret bit_type; // TODO
#endif

    const static int bit_generation_threshold = 2;

    static string alt()
    {
        return "";
    }

    AtlasGszShare()
    {
    }

    template<class U>
    AtlasGszShare(const U& other) :
            super(other)
    {
    }
};

#endif /* PROTOCOLS_ATLASGSZSHARE_H_ */
