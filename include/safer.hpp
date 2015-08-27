/*
 * safer.h: definitions for block cipher algorithm SAFER (Secure And Fast Encryption Routine).
 *
 * Author(s): objectx
 *
 */
/* NOTE: Only SAFER-SK64 and SAFER-SK128 was implemented... */
#pragma once
#ifndef safer_h__62b549ba_ae63_488a_bd69_a3bc55c00926
#define safer_h__62b549ba_ae63_488a_bd69_a3bc55c00926   1

#include <cstddef>
#include <cassert>
#include <cstdint>

namespace Safer {
    size_t      const MAX_NUM_ROUNDS = 13 ;
    size_t      const BLOCK_LEN = 8 ;

    size_t      const KEY_LEN = BLOCK_LEN * (1 + 2 * MAX_NUM_ROUNDS) ;

    typedef uint8_t     block_t [BLOCK_LEN] ;

    /// <summary>
    /// Holds pre-computed values.
    /// </summary>
    class Table {
    private:
        uint8_t log_ [256] ;
        uint8_t exp_ [256] ;
    public:
        Table () ;
        uint8_t   Exp (size_t idx) const {
            return exp_ [idx & 0xFFu] ;
        }
        uint8_t   Log (size_t idx) const {
            return log_ [idx & 0xFFu] ;
        }
    } ;

    /// <summary>
    /// Holds expanded key.
    /// </summary>
    class Key {
    private:
        size_t  nRounds_ ;
        uint8_t values_ [KEY_LEN] ;
    public:
        /// <summary>
        /// Construct expanded key from <paramref name="key"/> [0..<paramref name="key_size"/> - 1].
        /// </summary>
        /// <param name="tab">Pre-computed table</param>
        /// <param name="key">Original key</param>
        /// <param name="key_size">Key length</param>
        /// <param name="nRounds"># of rounds</param>
        Key (const Table &tab, const void *key, size_t key_size, size_t nRounds) ;
        /// <summary>
        /// Construct expanded key from <paramref name="key"/> [0..<paramref name="key_size"/> - 1] (w/ default # of rounds).
        /// </summary>
        /// <param name="tab">Pre-computed table</param>
        /// <param name="key">Original key</param>
        /// <param name="key_size">Key length</param>
        Key (const Table &tab, const void *key, size_t key_size) ;
        /// <summary>
        /// The copy ctor.
        /// </summary>
        /// <param name="src"></param>
        Key (const Key &src) ;

        /// <summary>
        /// The assignment operator.
        /// </summary>
        Key &   Assign (const Key &src) ;

        /// <summary>
        /// The assignment operator.
        /// </summary>
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

    /// <summary>
    /// The encryptor (output == input was allowed).
    /// </summary>
    /// <param name="output">encrypted message</param>
    /// <param name="input">plain text</param>
    /// <param name="tab">pre-computed values for encryption</param>
    /// <param name="key">expanded key</param>
    extern void EncryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) ;

    /// <summary>
    /// The decryptor (output == input was allowed).
    /// </summary>
    /// <param name="output">plain text</param>
    /// <param name="input">encrypted message</param>
    /// <param name="tab">pre-computed values for encryption</param>
    /// <param name="key">expanded key</param>
    extern void DecryptBlock (block_t &output, const block_t &input, const Table &tab, const Key &key) ;

}   /* end of namespace Safer */

#endif  /* safer_h__62b549ba_ae63_488a_bd69_a3bc55c00926 */
/*
 * [END of FILE]
 */

