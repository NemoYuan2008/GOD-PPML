/*
 * AtlasBginShare.h
 */

#ifndef PROTOCOLS_ATLASBGINSHARE_H_
#define PROTOCOLS_ATLASBGINSHARE_H_

#include "ShamirShare.h"
#include "ShamirMC.h"

template<class T> class AtlasBgin;

namespace GC
{
class AtlasBginSecret;
}

template<class T>
class AtlasBginShare : public ShamirShare<T>
{
    typedef AtlasBginShare This;
    typedef ShamirShare<T> super;

public:
    typedef AtlasBgin<This> Protocol;
    typedef ShamirInput<This> Input;
    typedef IndirectShamirMC<This> MAC_Check;
    typedef IndirectShamirMC_2t<This> MAC_Check_2t;
    typedef ShamirMC<This> Direct_MC;
    typedef ::PrivateOutput<This> PrivateOutput;
    typedef AtlasPrep<This> LivePrep;
    typedef LivePrep TriplePrep;

#ifndef NO_MIXED_CIRCUITS
    typedef GC::AtlasSecret bit_type;
#endif

    const static int bit_generation_threshold = 2;

    static string alt()
    {
        return "";
    }

    AtlasBginShare()
    {
    }

    template<class U>
    AtlasBginShare(const U& other) :
            super(other)
    {
    }
};

#endif /* PROTOCOLS_ATLASBGINSHARE_H_ */
