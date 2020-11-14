#ifndef DIMENTIO_H
#define DIMENTIO_H

#include <mach/mach.h>
#include <CommonCrypto/CommonCrypto.h>

kern_return_t dimentio(uint64_t nonce); // Function to set nonce.
kern_return_t undimentio(); // Function to get nonce.

extern uint64_t nonce; // Nonce stored from calling undimentio(). Defaults to 0000000000000000 if undementio function isn't called.
extern uint8_t entangled_nonce[CC_SHA384_DIGEST_LENGTH]; // Entangled nonce stored after calling the dimentio() function.

#endif /* DIMENTIO_H */