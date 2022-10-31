// Copyright (c) 2015 Masashi Fujita. All rights reserved.

#include "safer.hpp"

#include <cstring>
#include <cstdlib>
#include <algorithm>

#ifdef HAVE_CONFIG_H
#   include "config.h"
#endif

namespace Safer {
    namespace {
        constexpr uint8_t rotl (uint8_t val, size_t count) noexcept {
            return static_cast<uint8_t> ((val << count) | (val >> (8u - count)));
        }

        /**
         * The pseudo-hadamard transformation...
         * [X' Y'] = [X Y][2 1]
         *                [1 1]
         */
        constexpr void pht (uint8_t& x, uint8_t& y) noexcept {
            y = x + y;
            x = x + y;
        }

        /**
         * The inverted pseudo-hadamard transformation...
         * [X' Y'] = [X Y][ 1 -1]
         *                [-1  2]
         */
        constexpr void ipht (uint8_t& x, uint8_t& y) noexcept {
            x = x - y;
            y = y - x;
        }

        auto BuildKeyBlock (const void* key, size_t key_size) noexcept -> std::array<block_t, 2> {
            std::array<block_t, 2>  result;
            std::memset (result.data(), 0, sizeof (result));

            if (key_size <= sizeof (block_t)) {
                auto const *p = static_cast<const uint8_t*> (key);
                for (size_t i = 0; i < key_size; ++i) {
                    result[0][i] = p[i];
                }
                result[1] = result[0];
            }
            else {
                std::memcpy (result.data (), key, std::min (key_size, 2 * sizeof (block_t)));
            }
            return result;
        }
    }

    Key::Key (const Table &tab, const void *key, size_t key_size, size_t nRounds) noexcept
            : nRounds_ (std::min<size_t> (nRounds, MAX_NUM_ROUNDS)) {
        auto K = BuildKeyBlock (key, key_size);
        Initialize (tab, K [0], K [1]) ;
    }

    void        Key::Initialize (const Table &tab, const block_t &key1, const block_t &key2) noexcept {
        std::array<uint8_t, BLOCK_LEN + 1>  ka;
        std::array<uint8_t, BLOCK_LEN + 1>  kb;

        values_.fill (0);
        ka.fill (0);
        kb.fill (0);

        auto const &exptab = tab.getExpTable () ;

        size_t    idx = 0 ;
        {
            size_t  i ;
            for (i = 0 ; i < BLOCK_LEN ; ++i) {
                uint8_t tmp ;

                tmp = rotl (key1 [i], 5u) ;
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
                    ka [j] = rotl (ka [j], 6u) ;
                    kb [j] = rotl (kb [j], 6u) ;
                }
                for (j = 0 ; j < BLOCK_LEN ; ++j) {
                    values_ [idx++] = ka [(j + 2 * i - 1) % (BLOCK_LEN + 1u)] + exptab [exptab [(18u * i + j +  1u) & 0xFFu]] ;
                }
                for (j = 0 ; j < BLOCK_LEN ; ++j) {
                    values_ [idx++] = kb [(j + 2 * i - 0) % (BLOCK_LEN + 1u)] + exptab [exptab [(18u * i + j + 10u) & 0xFFu]] ;
                }
            }
        }
        // Nukes working area...
        ka.fill (0);
        kb.fill (0);
    }

    void        EncryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) noexcept {
        uint8_t a = input[0];
        uint8_t b = input[1];
        uint8_t c = input[2];
        uint8_t d = input[3];
        uint8_t e = input[4];
        uint8_t f = input[5];
        uint8_t g = input[6];
        uint8_t h = input[7];

        size_t  idx = 0 ;
        auto const &ltab = tab.getLogTable () ;
        auto const &etab = tab.getExpTable () ;
        for (size_t r = 0 ; r < key.RoundCount () ; ++r) {
            a = etab [(a ^ key [idx + 0u]) & 0xFFu] + key [idx +  8u] ;
            b = ltab [(b + key [idx + 1u]) & 0xFFu] ^ key [idx +  9u] ;
            c = ltab [(c + key [idx + 2u]) & 0xFFu] ^ key [idx + 10u] ;
            d = etab [(d ^ key [idx + 3u]) & 0xFFu] + key [idx + 11u] ;
            e = etab [(e ^ key [idx + 4u]) & 0xFFu] + key [idx + 12u] ;
            f = ltab [(f + key [idx + 5u]) & 0xFFu] ^ key [idx + 13u] ;
            g = ltab [(g + key [idx + 6u]) & 0xFFu] ^ key [idx + 14u] ;
            h = etab [(h ^ key [idx + 7u]) & 0xFFu] + key [idx + 15u] ;

            pht (a, b) ; pht (c, d) ; pht (e, f) ; pht (g, h) ;
            pht (a, c) ; pht (e, g) ; pht (b, d) ; pht (f, h) ;
            pht (a, e) ; pht (b, f) ; pht (c, g) ; pht (d, h) ;
            uint8_t   tmp ;
            tmp = b ; b = e ; e = c ; c = tmp ;
            tmp = d ; d = f ; f = g ; g = tmp ;
            idx += 16u ;
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

    void    DecryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) noexcept {
        size_t  idx = BLOCK_LEN * (1u + 2u * key.RoundCount ()) - 1u ;

        uint8_t h = input [7u] ^ key [idx - 0u] ;
        uint8_t g = input [6u] - key [idx - 1u] ;
        uint8_t f = input [5u] - key [idx - 2u] ;
        uint8_t e = input [4u] ^ key [idx - 3u] ;
        uint8_t d = input [3u] ^ key [idx - 4u] ;
        uint8_t c = input [2u] - key [idx - 5u] ;
        uint8_t b = input [1u] - key [idx - 6u] ;
        uint8_t a = input [0u] ^ key [idx - 7u] ;
        idx -= 8u ;

        auto const &etab = tab.getExpTable () ;
        auto const &ltab = tab.getLogTable () ;
        for (size_t r = 0 ; r < key.RoundCount () ; ++r) {
            uint8_t   tmp ;
            tmp = e ; e = b ; b = c ; c = tmp ;
            tmp = f ; f = d ; d = g ; g = tmp ;
            ipht (a, e) ; ipht (b, f) ; ipht (c, g) ; ipht (d, h) ;
            ipht (a, c) ; ipht (e, g) ; ipht (b, d) ; ipht (f, h) ;
            ipht (a, b) ; ipht (c, d) ; ipht (e, f) ; ipht (g, h) ;
            h = ltab [(h - key [idx - 0u]) & 0xFFu] ^ key [idx -  8u] ;
            g = etab [(g ^ key [idx - 1u]) & 0xFFu] - key [idx -  9u] ;
            f = etab [(f ^ key [idx - 2u]) & 0xFFu] - key [idx - 10u] ;
            e = ltab [(e - key [idx - 3u]) & 0xFFu] ^ key [idx - 11u] ;
            d = ltab [(d - key [idx - 4u]) & 0xFFu] ^ key [idx - 12u] ;
            c = etab [(c ^ key [idx - 5u]) & 0xFFu] - key [idx - 13u] ;
            b = etab [(b ^ key [idx - 6u]) & 0xFFu] - key [idx - 14u] ;
            a = ltab [(a - key [idx - 7u]) & 0xFFu] ^ key [idx - 15u] ;
            idx -= 16 ;
        }
        output [0] = a ; output [1] = b ; output [2] = c ; output [3] = d ;
        output [4] = e ; output [5] = f ; output [6] = g ; output [7] = h ;
    }
}   /* end of namespace Safer */
