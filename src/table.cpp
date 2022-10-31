/// Copyright (c) 2015 Masashi Fujita. All rights reserved.

#include "safer.hpp"

#include <cstddef>
#include <cstdint>

namespace Safer {
    Table::Table () {
        size_t E = 1;
        log_.fill (0);
        exp_.fill (0);

        for (size_t i = 0; i < exp_.size (); ++i) {
            auto tmp  = static_cast<uint8_t> (E);
            exp_[i]   = tmp;
            log_[tmp] = static_cast<uint8_t> (i);
            E         = (45u * E) % 257u;
        }
    }
} // namespace Safer
