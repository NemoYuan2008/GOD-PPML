#ifndef PROTOCOLS_ATLASCONFIG_H
#define PROTOCOLS_ATLASCONFIG_H

// TODO: make these parameters Options

namespace AtlasConfig
{
    /**
     * The maximum number of stored triples before the check.
     * This parameter was set to 400,000 when collecting the data for the paper.
     */
    static constexpr int max_before_check = 10000;

    /**
     * The maximum number of stored triples before calling shrink_to_fit().
     * This parameter was set to 400,000 when collecting the data for the paper.
     */
    static constexpr int max_before_shrink = 40000;

    /**
     * The maximum openings before the check.
     */
    static constexpr int max_openings_before_check = 10000;

    /**
     * The fix-point precision
     * must match the sfix.set_precision() in the compiler
     */
    static constexpr int fixed_point_precision = 16;
}

#endif