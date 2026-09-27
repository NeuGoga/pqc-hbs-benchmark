#pragma once
#include "internal/types.h"

Bytes fors_pk_from_sig(const Bytes &sig, size_t &sig_offset,
                       const Bytes &msg_digest, const Bytes &pub_seed,
                       Address addr, SphincsPlus::Params *p);
