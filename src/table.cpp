/*
 * table.cpp:
 *
 * Copyright (c) 2015 Masashi Fujita
 */
#include <cstddef>
#include <cstdint>
#include "safer.hpp"

namespace Safer {

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
}
/*
 * [END of FILE]
 */