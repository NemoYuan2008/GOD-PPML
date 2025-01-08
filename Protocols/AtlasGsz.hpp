/*
 * AtlasGsz.hpp
 *
 */

#ifndef PROTOCOLS_ATLASGSZ_HPP_
#define PROTOCOLS_ATLASGSZ_HPP_

#include "AtlasGsz.h"



// Core multiplication operations
template<class T>
void AtlasGsz<T>::init_mul()
{
    super::init_mul();
}

template<class T>
void AtlasGsz<T>::prepare_mul(const T& x, const T& y, int n)
{
    super::prepare_mul(x, y, n);
}

template<class T>
void AtlasGsz<T>::prepare(const typename T::open_type& product)
{
    super::prepare(product);
}

template<class T>
void AtlasGsz<T>::exchange()
{
    super::exchange();
}

template<class T>
T AtlasGsz<T>::finalize_mul(int)
{
    return super::finalize_mul();
}

// Dot product operations
template<class T>
void AtlasGsz<T>::init_dotprod()
{
    super::init_dotprod();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod(const T& x, const T& y)
{
    super::prepare_dotprod(x, y);
}

template<class T>
void AtlasGsz<T>::next_dotprod()
{
    super::next_dotprod();
}

template<class T>
T AtlasGsz<T>::finalize_dotprod(int length)
{
    return super::finalize_dotprod(length);
}

// Copied from the class Atlas to avoid making the *_mul_trunc functions virtual
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc)
{
    mul_trunc(regs, size, proc, T::characteristic_two);
}

// Copied from the class Atlas to avoid making the *_mul_trunc functions virtual
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::true_type)
{
    (void) regs; (void) size; (void) proc;
    throw runtime_error("mul_trunc not implemented for characteristic 2");
}

// Copied from the class Atlas to avoid making the *_mul_trunc functions virtual
template<class T>
void AtlasGsz<T>::mul_trunc(const vector<int>& regs, int size, SubProcessor<T>& proc, std::false_type)
{
    // Parse the arguments
    struct MultTruncInfo {
        int dest_base;       // Destination register
        int x_base;         // First operand
        int y_base;         // Second operand 
        int k;             // Bit length
        int f;             // Number of bits to truncate

        MultTruncInfo(const vector<int>& regs, int offset)
        {
            dest_base = regs[offset];
            x_base = regs[offset + 1]; 
            y_base = regs[offset + 2];
            k = regs[offset + 3];
            f = regs[offset + 4];
        }
    };

    vector<MultTruncInfo> infos;
    for (size_t i = 0; i < regs.size(); i += 5) 
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
            
            prepare_mul_trunc(x, y, info.k, info.f, proc);
        }
    }

    exchange_mul_trunc();

    for (auto& info : infos)
    {
        for (int i = 0; i < size; ++i)
        {
            proc.get_S_ref(info.dest_base + i) = finalize_mul_trunc(info.k, info.f);
        }
    }
}


template<class T>
void AtlasGsz<T>::init_mul_trunc(int length)
{
    super::init_mul_trunc(length);
}

template<class T>
void AtlasGsz<T>::prepare_mul_trunc(const T& x, const T& y, int k, int f, SubProcessor<T>& proc)
{
    super::prepare_mul_trunc(x, y, k, f, proc);
}

template<class T>
void AtlasGsz<T>::exchange_mul_trunc()
{
    super::exchange_mul_trunc();
}

template<class T>
T AtlasGsz<T>::finalize_mul_trunc(int k, int f)
{
    return super::finalize_mul_trunc(k, f);
}


// Truncated dot product operations
template<class T>
void AtlasGsz<T>::init_dotprod_trunc()
{
    super::init_dotprod_trunc();
}

template<class T>
void AtlasGsz<T>::prepare_dotprod_trunc(const T& x, const T& y)
{
    super::prepare_dotprod_trunc(x, y);
}

template<class T>
void AtlasGsz<T>::next_dotprod_trunc(int k, int f, SubProcessor<T>& proc)
{
    super::next_dotprod_trunc(k, f, proc);
}

template<class T>
void AtlasGsz<T>::exchange_dotprod_trunc()
{
    super::exchange_dotprod_trunc();
}

template<class T>
T AtlasGsz<T>::finalize_dotprod_trunc(int length, int k, int f)
{
    return super::finalize_dotprod_trunc(length, k, f);
}

template<class T>
void AtlasGsz<T>::prepare_with_solved_bits(const typename T::open_type& product, int k, int f, SubProcessor<T>& proc)
{
    super::prepare_with_solved_bits(product, k, f, proc);
}

#endif /* PROTOCOLS_ATLASGSZ_HPP_ */
