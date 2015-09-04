/*
 * safer.h: definitions for block cipher algorithm SAFER (Secure And Fast Encryption Routine).
 *
 * Copyright (c) 2015 Masashi Fujita
 *
 */
/* NOTE: Only SAFER-SK64 and SAFER-SK128 was implemented... */
#pragma once
#ifndef safer_h__62b549ba_ae63_488a_bd69_a3bc55c00926
#define safer_h__62b549ba_ae63_488a_bd69_a3bc55c00926   1

#include <cstddef>
#include <cassert>
#include <cstdint>
#include <array>

namespace Safer {
    size_t      const MAX_NUM_ROUNDS = 13 ;
    size_t      const BLOCK_LEN = 8 ;

    size_t      const KEY_LEN = BLOCK_LEN * (1 + 2 * MAX_NUM_ROUNDS) ;

    size_t      const SK64_DEFAULT_NUM_ROUNDS  = 8 ;
    size_t      const SK128_DEFAULT_NUM_ROUNDS = 10 ;

    typedef uint8_t     block_t [BLOCK_LEN] ;

    /**
     * Holds pre-computed values.
     */
    class Table {
    private:
        std::array<uint8_t, 256>    log_ ;
        std::array<uint8_t, 256>    exp_ ;
    public:
        Table () ;
        decltype (log_) const & getLogTable () const {
            return log_ ;
        }
        decltype (exp_) const & getExpTable () const {
            return exp_ ;
        }
    } ;

    /**
     * Holds expanded key.
     */
    class Key {
    private:
        size_t  nRounds_ ;
        uint8_t values_ [KEY_LEN] ;
    public:
        /**
         * Construct expanded key from KEY [0..KEY_SIZE - 1].
         *
         * @param tab Pre-computed table
         * @param key Original key
         * @param key_size Key length
         * @nRounds # of rounds
         */
        Key (const Table &tab, const void *key, size_t key_size, size_t nRounds) ;
        /**
         * Construct expanded key from KEY [0..KEY_SIZE - 1].
         *
         * @param tab Pre-computed table
         * @param key Original key
         * @param key_size Key length
         */
        Key (const Table &tab, const void *key, size_t key_size)
            : Key (tab, key, key_size,
                   (key_size <= sizeof (block_t)
                        ? SK64_DEFAULT_NUM_ROUNDS
                        : SK128_DEFAULT_NUM_ROUNDS)) {
            /* NO-OP */
        }

        /**
         * The copy ctor.
         *
         * @param src
         */
        Key (const Key &src) ;
        /**
         * The Assignment Operator.
         *
         * @Param Src
         */
        Key &   Assign (const Key &src) ;
        /**
         * The Assignment Operator.
         *
         * @Param Src
         */
        Key &   operator = (const Key &src) {
            return Assign (src) ;
        }

        uint8_t At (size_t idx) const {
            assert (idx < KEY_LEN) ;
            return values_ [idx] ;
        }
        uint8_t operator [] (size_t idx) const {
            assert (idx < KEY_LEN) ;
            return values_ [idx] ;
        }
        size_t  RoundCount () const {
            return nRounds_ ;
        }
    private:
        void    Initialize (const Table &tab, const block_t &key1, const block_t &key2) ;
    } ;

    /**
     * The encryptor (output == input was allowed).
     *
     * @param output encrypted message
     * @param input plain text
     * @param tab pre-computed values for encryption
     * @param key expanded key
     */
    extern void EncryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) ;

    /**
     * The decryptor (output == input was allowed).
     *
     * @param output encrypted message
     * @param input plain text
     * @param tab pre-computed values for encryption
     * @param key expanded key
     */
    extern void DecryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) ;

}   /* end of namespace Safer */

#endif  /* safer_h__62b549ba_ae63_488a_bd69_a3bc55c00926 */
/*
 * [END of FILE]
 */
