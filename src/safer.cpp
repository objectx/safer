/* -*- mode: C++ -*- */
/*
 * safer.cpp:
 *
 * AUTHOR(S): objectx
 *
 */

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include "safer.hpp"

#define NUM_ELEMENTS(X_)        (sizeof (X_) / sizeof (*(X_)))

////////////////////////////////////////////////////////////////////////

namespace Safer {
    size_t      const SK64_DEFAULT_NUM_ROUNDS  = 8 ;
    size_t      const SK128_DEFAULT_NUM_ROUNDS = 10 ;

    static inline uint8_t       rotl (uint8_t val, size_t count) {
        return static_cast<uint8_t>((val << count) | (val >> (8 - count))) ;
    }

    /**
     * The pseudo-hadamard transformation...
     * [X' Y'] = [X Y][2 1]
     *                [1 1]
     */
    static inline void  pht (uint8_t &x, uint8_t &y) {
        y = x + y ;
        x = x + y ;
    }

    /**
     * The inverted pseudo-hadamard transformation...
     * [X' Y'] = [X Y][ 1 -1]
     *                [-1  2]
     */
    static inline void  ipht (uint8_t &x, uint8_t &y) {
        x = x - y ;
        y = y - x ;
    }

    Table::Table () {
        size_t  E = 1 ;
        log_.fill (0) ;
        exp_.fill (0) ;

        for (size_t i = 0 ; i < exp_.size () ; ++i) {
            uint8_t     tmp = static_cast<uint8_t> (E) ;
            exp_ [i] = tmp ;
            log_ [tmp] = static_cast<uint8_t> (i) ;
            E = (45 * E) % 257 ;
        }
    }

    static inline size_t        check_rounds (size_t n) {
        return MAX_NUM_ROUNDS < n ? MAX_NUM_ROUNDS : n ;
    }

    static void BuildKeyBlock (block_t result [2], const void *key, size_t key_size) {
        std::memset (result, 0, 2 * sizeof (block_t)) ;

        if (key_size <= sizeof (block_t)) {
            const uint8_t *     p = static_cast<const uint8_t *> (key) ;
            for (size_t i = 0 ; i < key_size ; ++i) {
                result [0][i] = p [i] ;
            }
            std::memcpy (result [1], result [0], sizeof (block_t)) ;
        }
        else {
            std::memcpy (result, key, std::min (key_size, 2 * sizeof (block_t))) ;
        }
    }

    Key::Key (const Table &tab, const void *key, size_t key_size, size_t nRounds) : nRounds_ (check_rounds (nRounds)) {
        block_t K [2] ;
        BuildKeyBlock (K, key, key_size) ;
        Initialize (tab, K [0], K [1]) ;
    }

    Key::Key (const Table &tab, const void *key, size_t key_size) {
        if (key_size <= sizeof (block_t)) {
            nRounds_ = SK64_DEFAULT_NUM_ROUNDS ;
        }
        else {
            nRounds_ = SK128_DEFAULT_NUM_ROUNDS ;
        }
        block_t K [2] ;
        BuildKeyBlock (K, key, key_size) ;
        Initialize (tab, K [0], K [1]) ;
    }

    Key::Key (const Key &src) : nRounds_ (src.nRounds_) {
        std::memcpy (values_, src.values_, sizeof (values_)) ;
    }

    Key &       Key::Assign (const Key &src) {
        nRounds_ = src.nRounds_ ;
        std::memcpy (values_, src.values_, sizeof (values_)) ;
        return *this ;
    }

    void        Key::Initialize (const Table &tab, const block_t &key1, const block_t &key2) {
        uint8_t ka [BLOCK_LEN + 1] ;
        uint8_t kb [BLOCK_LEN + 1] ;

        std::memset (values_, 0, sizeof (values_)) ;
        std::memset (ka, 0, sizeof (ka)) ;
        std::memset (kb, 0, sizeof (kb)) ;

        size_t    idx = 0 ;
        {
            size_t  i ;
            for (i = 0 ; i < BLOCK_LEN ; ++i) {
                uint8_t tmp ;

                tmp = rotl (key1 [i], 5) ;
                ka [i] = tmp ;
                ka [BLOCK_LEN] ^= tmp ;

                tmp = key2 [i] ;
                values_ [idx++] = tmp ;
                kb [i] = tmp ;
                kb [BLOCK_LEN] ^= tmp ;
            }
            for (i = 1 ; i <= nRounds_ ; ++i) {
                size_t  j ;
                for (j = 0 ; j <= BLOCK_LEN ; ++j) {
                    ka [j] = rotl (ka [j], 6) ;
                    kb [j] = rotl (kb [j], 6) ;
                }
                for (j = 0 ; j < BLOCK_LEN ; ++j) {
                    values_ [idx++] = (ka [(j + 2 * i - 1) % (BLOCK_LEN + 1)] + tab.Exp (tab.Exp (18 * i + j +  1))) ;
                }
                for (j = 0 ; j < BLOCK_LEN ; ++j) {
                    values_ [idx++] = (kb [(j + 2 * i - 0) % (BLOCK_LEN + 1)] + tab.Exp (tab.Exp (18 * i + j + 10))) ;
                }
            }
        }
        // Nukes working area...
        std::memset (ka, 0, sizeof (ka)) ;
        std::memset (kb, 0, sizeof (kb)) ;
    }

    void        EncryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) {
        uint8_t a, b, c, d, e, f, g, h ;

        a = input [0] ; b = input [1] ; c = input [2] ; d = input [3] ;
        e = input [4] ; f = input [5] ; g = input [6] ; h = input [7] ;

        size_t  idx = 0 ;
        for (size_t r = 0 ; r < key.RoundCount () ; ++r) {
            a = tab.Exp (a ^ key [idx + 0]) + key [idx +  8] ;
            b = tab.Log (b + key [idx + 1]) ^ key [idx +  9] ;
            c = tab.Log (c + key [idx + 2]) ^ key [idx + 10] ;
            d = tab.Exp (d ^ key [idx + 3]) + key [idx + 11] ;
            e = tab.Exp (e ^ key [idx + 4]) + key [idx + 12] ;
            f = tab.Log (f + key [idx + 5]) ^ key [idx + 13] ;
            g = tab.Log (g + key [idx + 6]) ^ key [idx + 14] ;
            h = tab.Exp (h ^ key [idx + 7]) + key [idx + 15] ;

            pht (a, b) ; pht (c, d) ; pht (e, f) ; pht (g, h) ;
            pht (a, c) ; pht (e, g) ; pht (b, d) ; pht (f, h) ;
            pht (a, e) ; pht (b, f) ; pht (c, g) ; pht (d, h) ;
            uint8_t   tmp ;
            tmp = b ; b = e ; e = c ; c = tmp ;
            tmp = d ; d = f ; f = g ; g = tmp ;
            idx += 16 ;
        }
        output [0] = a ^ key [idx + 0] ;
        output [1] = b + key [idx + 1] ;
        output [2] = c + key [idx + 2] ;
        output [3] = d ^ key [idx + 3] ;
        output [4] = e ^ key [idx + 4] ;
        output [5] = f + key [idx + 5] ;
        output [6] = g + key [idx + 6] ;
        output [7] = h ^ key [idx + 7] ;
    }

    void    DecryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) {
        uint8_t a, b, c, d, e, f, g, h ;
        size_t  idx = BLOCK_LEN * (1 + 2 * key.RoundCount ()) - 1 ;

        h = input [7] ^ key [idx - 0] ;
        g = input [6] - key [idx - 1] ;
        f = input [5] - key [idx - 2] ;
        e = input [4] ^ key [idx - 3] ;
        d = input [3] ^ key [idx - 4] ;
        c = input [2] - key [idx - 5] ;
        b = input [1] - key [idx - 6] ;
        a = input [0] ^ key [idx - 7] ;
        idx -= 8 ;

        for (size_t r = 0 ; r < key.RoundCount () ; ++r) {
            uint8_t   tmp ;
            tmp = e ; e = b ; b = c ; c = tmp ;
            tmp = f ; f = d ; d = g ; g = tmp ;
            ipht (a, e) ; ipht (b, f) ; ipht (c, g) ; ipht (d, h) ;
            ipht (a, c) ; ipht (e, g) ; ipht (b, d) ; ipht (f, h) ;
            ipht (a, b) ; ipht (c, d) ; ipht (e, f) ; ipht (g, h) ;
            h = tab.Log (h - key [idx - 0]) ^ key [idx -  8] ;
            g = tab.Exp (g ^ key [idx - 1]) - key [idx -  9] ;
            f = tab.Exp (f ^ key [idx - 2]) - key [idx - 10] ;
            e = tab.Log (e - key [idx - 3]) ^ key [idx - 11] ;
            d = tab.Log (d - key [idx - 4]) ^ key [idx - 12] ;
            c = tab.Exp (c ^ key [idx - 5]) - key [idx - 13] ;
            b = tab.Exp (b ^ key [idx - 6]) - key [idx - 14] ;
            a = tab.Log (a - key [idx - 7]) ^ key [idx - 15] ;
            idx -= 16 ;
        }
        output [0] = a ; output [1] = b ; output [2] = c ; output [3] = d ;
        output [4] = e ; output [5] = f ; output [6] = g ; output [7] = h ;
    }
}   /* end of namespace Safer */
/*
 * [END of FILE]
 */
