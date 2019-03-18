#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include "safer.hpp"

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

namespace {
    bool        Equals (Safer::block_t &b0, const Safer::block_t &b1) {
        return (  b0 [0] == b1 [0]
               && b0 [1] == b1 [1]
               && b0 [2] == b1 [2]
               && b0 [3] == b1 [3]
               && b0 [4] == b1 [4]
               && b0 [5] == b1 [5]
               && b0 [6] == b1 [6]
               && b0 [7] == b1 [7]) ;
    }
}

TEST_CASE ("Test: SK64", "[sk64]") {
    Safer::Table table ;
    SECTION ("Test encode { 1, 2, 3, 4, 5, 6, 7, 8 } with key = { 0, 0, 0, 0, 0, 0, 0, 1 }") {

        uint8_t key [8] = {  0,  0,  0,  0,  0,  0,  0,  1 } ;
        Safer::block_t  plain    = {  1,  2,   3, 4,   5,  6,   7,  8 } ;
        Safer::block_t  expected = { 21, 27, 255, 2, 173, 17, 191, 45 } ;
        Safer::block_t  output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 6)) ;
        REQUIRE (Equals (expected, output)) ;

        SECTION ("Test decode") {
            Safer::block_t  decrypted ;
            Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 6)) ;
            REQUIRE (Equals (decrypted, plain)) ;
        }
    }
    SECTION ("Test encode { 1, 2, 3, 4, 5, 6, 7, 8 } with key = { 1, 2, 3, 4, 5, 6, 7, 8 }") {
        uint8_t key [8] = { 1, 2,  3, 4, 5, 6, 7, 8 } ;
        Safer::block_t  plain    = { 1,   2,   3,   4, 5,   6,  7,   8 } ;
        Safer::block_t  expected = {95, 206, 155, 162, 5, 132, 56, 199 } ;
        Safer::block_t  output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 6)) ;
        REQUIRE (Equals (expected, output)) ;

        SECTION ("Test decode") {
            Safer::block_t  decrypted ;
            Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 6)) ;
            REQUIRE (Equals (decrypted, plain)) ;
        }
    }
}

TEST_CASE ("Test: SK128", "[sk128]") {
    Safer::Table table ;

    SECTION ("Test Encode {1, 2, 3, 4, 5, 6, 7, 8} With Key = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}") {

        uint8_t key [16] = { 0, 0, 0, 0, 0, 0, 0, 1,
                             0, 0, 0, 0, 0, 0, 0, 1 } ;
        Safer::block_t  plain    = { 1,  2,  3,  4,   5,   6,  7,   8 } ;
        Safer::block_t  expected = {65, 76, 84, 90, 182, 153, 74, 247 } ;

        Safer::block_t  output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 10)) ;
        REQUIRE (Equals (expected, output)) ;

        SECTION ("Test decode") {
            Safer::block_t  decrypted ;
            Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 10)) ;
            REQUIRE (Equals (decrypted, plain)) ;
        }
    }
    SECTION ("Test Encode {1, 2, 3, 4, 5, 6, 7, 8} With Key = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1}") {
        uint8_t key [16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                             0, 0, 0, 0, 0, 0, 0, 0 } ;
        Safer::block_t  plain    = {  1,   2,  3,   4,   5,   6,  7,   8 } ;
        Safer::block_t  expected = {255, 120, 17, 228, 179, 167, 46, 113 } ;

        Safer::block_t  output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 10)) ;
        REQUIRE (Equals (expected, output)) ;

        SECTION ("Test decode") {
            Safer::block_t  decrypted ;
            Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 10)) ;
            REQUIRE (Equals (decrypted, plain)) ;
        }
    }
    SECTION ("Test Encode {1, 2, 3, 4, 5, 6, 7, 8} With Key = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 1}") {
        uint8_t key [16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                             1, 2, 3, 4, 5, 6, 7, 8 } ;

        Safer::block_t  plain    = { 1,   2,   3,   4,   5,   6,  7, 8 } ;
        Safer::block_t  expected = {73, 201, 157, 152, 165, 188, 89, 8 } ;

        Safer::block_t  output ;
        Safer::EncryptBlock (output, plain, table, Safer::Key (table, key, sizeof (key), 10)) ;
        REQUIRE (Equals (expected, output)) ;

        SECTION ("Test decode") {
            Safer::block_t  decrypted ;
            Safer::DecryptBlock (decrypted, output, table, Safer::Key (table, key, sizeof (key), 10)) ;
            REQUIRE (Equals (decrypted, plain)) ;
        }
    }
}
