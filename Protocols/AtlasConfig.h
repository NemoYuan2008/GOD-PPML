#ifndef PROTOCOLS_ATLASCONFIG_H

/**
 * Notes on the choice of ATLAS_MAX_BEFORE_CHECK:
 *  
 * SpdzWise chooses OnlineOptions::singleton.batch_size,
 * which defaults to 10000.
 * 
 * We choose a smaller value, because we need to store all triples,
 * which consumes more memory.
 * Ideally, the batch size here should be a power of 2,
 * but we choose it to be slighly smaller than 8192.
 */

#define ATLAS_MAX_BEFORE_CHECK 8000

#endif