#ifndef PROTOCOLS_ATLASCONFIG_H
#define PROTOCOLS_ATLASCONFIG_H

namespace AtlasConfig
{
    /**
     * Notes on the choice of AtlasConfig::max_before_check:
     *  
     * SpdzWise chooses OnlineOptions::singleton.batch_size,
     * which defaults to 10000.
     * 
     * We choose a smaller value, because we need to store all triples,
     * which consumes more memory.
     * Ideally, the batch size here should be a power of 2,
     * but we choose it to be slighly smaller than 8192,
     * since multiplcations are executed in batches,
     * it may happen that after a batch, the size exceeds max_before_check.
     */
    static constexpr int max_before_check = 8000;

    /**
     * The maximum openings before the check.
     * 
     */
    static constexpr int max_openings_before_check = 8000;
}

#endif