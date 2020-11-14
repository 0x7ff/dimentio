#ifndef DIMENTIO_H
#define DIMENTIO_H

#include <mach/mach.h>
#include <CommonCrypto/CommonCrypto.h>

kern_return_t dimentio(uint64_t nonce, uint8_t *entangled_nonce); // Function to set nonce and get entangled_nonce.
kern_return_t undimentio(uint64_t *generator); // Function to get nonce. value will be stored at pointer

#endif /* DIMENTIO_H */