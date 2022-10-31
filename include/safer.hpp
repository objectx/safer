// Copyright (c) 2015 Masashi Fujita. All rights reserved.
// safer.h: definitions for block cipher algorithm SAFER (Secure And Fast Encryption Routine).

/* NOTE: Only SAFER-SK64 and SAFER-SK128 was implemented... */
#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

namespace Safer {
    constexpr size_t MAX_NUM_ROUNDS = 13;
    constexpr size_t BLOCK_LEN      = 8;

    constexpr size_t KEY_LEN = BLOCK_LEN * (1 + 2 * MAX_NUM_ROUNDS);

    constexpr size_t SK64_DEFAULT_NUM_ROUNDS  = 8;
    constexpr size_t SK128_DEFAULT_NUM_ROUNDS = 10;

    using block_t = std::array<uint8_t, BLOCK_LEN>;

    /// @brief Holds pre-computed values.
    class Table {
    private:
        std::array<uint8_t, 256> log_;
        std::array<uint8_t, 256> exp_;

    public:
        Table ();
        [[nodiscard]] constexpr auto getLogTable () const noexcept -> decltype (log_) const& { return log_; }
        [[nodiscard]] constexpr auto getExpTable () const noexcept -> decltype (exp_) const& { return exp_; }
    };

    /// @brief Holds expanded key.
    class Key {
    private:
        size_t                       nRounds_;
        std::array<uint8_t, KEY_LEN> values_;

    public:
        /// @brief Construct expanded key from KEY [0..KEY_SIZE - 1].
        ///
        /// @param tab Pre-computed table
        /// @param key Original key
        /// @param key_size Key length
        /// @param nRounds # of rounds
        Key (const Table& tab, const void* key, size_t key_size, size_t nRounds) noexcept;

        /// @brief Construct expanded key from KEY [0..KEY_SIZE - 1].
        ///
        /// @param tab Pre-computed table
        /// @param key Original key
        /// @param key_size Key length
        Key (const Table& tab, const void* key, size_t key_size) noexcept
                : Key (tab, key, key_size, (key_size <= sizeof (block_t) ? SK64_DEFAULT_NUM_ROUNDS : SK128_DEFAULT_NUM_ROUNDS)) {
            /* NO-OP */
        }

        Key (const Key& src) noexcept = default;

        auto operator= (const Key& src) noexcept -> Key& = default;

        auto Assign (const Key& src) noexcept -> Key& { return this->operator= (src); }

        [[nodiscard]] auto At (size_t idx) const -> uint8_t { return this->operator[] (idx); }

        [[nodiscard]] auto operator[] (size_t idx) const -> uint8_t {
            assert (idx < KEY_LEN);
            return values_[idx];
        }

        [[nodiscard]] constexpr auto RoundCount () const noexcept -> size_t { return nRounds_; }

    private:
        void Initialize (const Table& tab, const block_t& key1, const block_t& key2) noexcept;
    };

    /// @brief The encryptor (output == input was allowed).
    ///
    /// @param output encrypted message
    /// @param input plain text
    /// @param tab pre-computed values for encryption
    /// @param key expanded key
    extern void EncryptBlock (block_t& output, const block_t& input, const Table& tab, const Key& key) noexcept;

    /// @brief The decrypter (output == input was allowed).
    ///
    /// @param output decrypted message
    /// @param input encrypted text
    /// @param tab pre-computed values for encryption
    /// @param key expanded key
    extern void DecryptBlock (block_t& output, const block_t& input, const Table& tab, const Key& key) noexcept;

} /* end of namespace Safer */
