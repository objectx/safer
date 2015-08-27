/*
 * main.cxx:
 *
 * Author(s): objectx
 *
 * $Id: main.cxx 2583 2007-11-23 09:19:30Z objectx $
 */
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include "safer.hpp"

Safer::Table    table ;

namespace {

    std::ostream &      operator << (std::ostream &output, const Safer::block_t &block) {
        std::ios::fmtflags      flag = output.setf (std::ios::dec, std::ios::basefield) ;
        output.width (3) ;
        output << static_cast<int>(block [0]) ;
        for (int i = 1 ; i < static_cast<int>(sizeof (block)) ; ++i) {
            output << ' ' ;
            output.width (3) ;
            output << static_cast<int>(block [i]) ;
        }
        output.setf (flag, std::ios::basefield) ;
        return output ;
    }

    bool        Equals (Safer::block_t &b0, const Safer::block_t &b1) {
        return (b0 [0] == b1 [0] &&
                b0 [1] == b1 [1] &&
                b0 [2] == b1 [2] &&
                b0 [3] == b1 [3] &&
                b0 [4] == b1 [4] &&
                b0 [5] == b1 [5] &&
                b0 [6] == b1 [6] &&
                b0 [7] == b1 [7]) ;
    }

    void        Check (Safer::block_t &b0, const Safer::block_t &b1) {
        if (! Equals (b0, b1)) {
            throw std::runtime_error ("Bad result") ;
        }
    }

    struct decdump {
        const void *    data_ ;
        size_t  length_ ;

        decdump (const void *data, size_t length) : data_ (data), length_ (length) {
            /* NO-OP */
        }
        std::ostream &  Write (std::ostream &output) const {
            if (0 < length_) {
                std::ios::fmtflags      flag = output.setf (std::ios::dec, std::ios::basefield) ;
                const uint8_t * p = static_cast<const uint8_t *> (data_) ;
                output.width (3) ;
                output << static_cast<uint32_t> (p [0]) ;
                for (size_t i = 1 ; i < length_ ; ++i) {
                    output << ' ' ;
                    output.width (3) ;
                    output << static_cast<uint32_t> (p [i]) ;
                }
                output.setf (flag, std::ios::basefield) ;
            }
            return output ;
        }
    } ;

    std::ostream &      operator << (std::ostream &output, const decdump &arg) {
        return arg.Write (output) ;
    }
}


static void     test64 () {
    {

        uint8_t key [8] = {  0,  0,  0,  0,  0,  0,  0,  1 } ;
        Safer::block_t  plain    = {  1,  2,   3, 4,   5,  6,   7,  8 } ;
        Safer::block_t  expected = { 21, 27, 255, 2, 173, 17, 191, 45 } ;
        Safer::block_t  output ;
        Safer::block_t  decrypted ;

        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 6)) ;
        std::cout << "Key   : " << decdump (key, sizeof (key)) << std::endl ;
        std::cout << "Plain : " << plain << std::endl ;
        std::cout << "Result: " << output << std::endl ;
        std::cout << "Expect: " << expected << std::endl ;
        Check (expected, output) ;
        Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 6)) ;
        std::cout << "Decode: " << decrypted << std::endl ;
        Check (decrypted, plain) ;
    }
    {
        uint8_t key [8] = { 1, 2,  3, 4, 5, 6, 7, 8 } ;
        Safer::block_t  plain    = { 1,   2,   3,   4, 5,   6,  7,   8 } ;
        Safer::block_t  expected = {95, 206, 155, 162, 5, 132, 56, 199 } ;
        Safer::block_t  output ;
        Safer::block_t  decrypted ;

        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 6)) ;
        std::cout << "Key   : " << decdump (key, sizeof (key)) << std::endl ;
        std::cout << "Plain : " << plain << std::endl ;
        std::cout << "Result: " << output << std::endl ;
        std::cout << "Expect: " << expected << std::endl ;
        Check (expected, output) ;
        Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 6)) ;
        std::cout << "Decode: " << decrypted << std::endl ;
        Check (decrypted, plain) ;
    }
}

static void     test128 ()
{
    {
        uint8_t key [16] = { 0, 0, 0, 0, 0, 0, 0, 1,
                             0, 0, 0, 0, 0, 0, 0, 1 } ;
        Safer::block_t  plain    = { 1,  2,  3,  4,   5,   6,  7,   8 } ;
        Safer::block_t  expected = {65, 76, 84, 90, 182, 153, 74, 247 } ;

        Safer::block_t output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 10)) ;
        std::cout << "Key   : " << decdump (key, sizeof (key)) << std::endl ;
        std::cout << "Plain : " << plain << std::endl ;
        std::cout << "Result: " << output << std::endl ;
        std::cout << "Expect: " << expected << std::endl ;
        Check (expected, output) ;
    }
    {
        uint8_t key [16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                             0, 0, 0, 0, 0, 0, 0, 0 } ;
        Safer::block_t  plain    = {  1,   2,  3,   4,   5,   6,  7,   8 } ;
        Safer::block_t  expected = {255, 120, 17, 228, 179, 167, 46, 113 } ;

        Safer::block_t output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 10)) ;
        std::cout << "Key   : " << decdump (key, sizeof (key)) << std::endl ;
        std::cout << "Plain : " << plain << std::endl ;
        std::cout << "Result: " << output << std::endl ;
        std::cout << "Expect: " << expected << std::endl ;
        Check (expected, output) ;
    }
    {
        uint8_t key [16] = {0, 0, 0, 0, 0, 0, 0, 0,
                            1, 2, 3, 4, 5, 6, 7, 8 } ;
        Safer::block_t  plain    = { 1,   2,   3,   4,   5,   6,  7, 8 } ;
        Safer::block_t  expected = {73, 201, 157, 152, 165, 188, 89, 8 } ;

        Safer::block_t output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 10)) ;
        std::cout << "Key   : " << decdump (key, sizeof (key)) << std::endl ;
        std::cout << "Plain : " << plain << std::endl ;
        std::cout << "Result: " << output << std::endl ;
        std::cout << "Expect: " << expected << std::endl ;
        Check (expected, output) ;
    }
}

int     main (int argc, char **argv)
{
    try {
        test64 () ;
        test128 () ;
    }
    catch (const std::runtime_error &e) {
        std::cerr << "ERROR: " << e.what () << std::endl ;
        return 1 ;
    }
    return 0 ;
}
/*
 * $LastChangedRevision: 2583 $
 * $LastChangedBy: objectx $
 * $HeadURL: http://svn.polyphony.scei.co.jp/developer/objectx/trunk/workspace/VS2005/Native/Safer/test_safer/main.cxx $
 */
