/* Copyright 2020 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIBDIMENTIO_H
#	define LIBDIMENTIO_H
#	include <CommonCrypto/CommonCrypto.h>
#	include <CoreFoundation/CoreFoundation.h>
#	include <mach/mach.h>
#	define KADDR_FMT "0x%" PRIX64
#	ifndef MIN
#		define MIN(a, b) ((a) < (b) ? (a) : (b))
#	endif
typedef uint64_t kaddr_t;
typedef kern_return_t (*kread_func_t)(kaddr_t, void *, mach_vm_size_t), (*kwrite_func_t)(kaddr_t, const void *, mach_msg_type_number_t);

void
dimentio_term(void);

kern_return_t
dimentio_init(kaddr_t, kread_func_t, kwrite_func_t);

kern_return_t
dimentio(uint64_t *, bool, uint8_t[CC_SHA384_DIGEST_LENGTH], bool *);
#endif
