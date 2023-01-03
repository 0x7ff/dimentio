/* Copyright 2023 0x7ff
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
#include "libdimentio.h"

int
main(int argc, char **argv) {
	uint8_t nonce_d[CC_SHA384_DIGEST_LENGTH];
	int ret = EXIT_FAILURE;
	size_t i, nonce_d_sz;
	uint64_t nonce;

	if(argc != 1 && argc != 2) {
		printf("Usage: %s [nonce]\n", argv[0]);
	} else if(argc == 1 || sscanf(argv[1], "0x%016" PRIx64, &nonce) == 1) {
		if(dimentio_preinit(&nonce, argc == 2, nonce_d, &nonce_d_sz) == KERN_SUCCESS || (dimentio_init(0, NULL, NULL) == KERN_SUCCESS && dimentio(&nonce, argc == 2, nonce_d, &nonce_d_sz) == KERN_SUCCESS)) {
			if(argc == 1) {
				printf("Current nonce is 0x%016" PRIX64 "\n", nonce);
			} else {
				printf("Set nonce to 0x%016" PRIX64 "\n", nonce);
			}
			if(nonce_d_sz != 0) {
				printf("nonce_d: ");
				for(i = 0; i < nonce_d_sz; ++i) {
					printf("%02" PRIX8, nonce_d[i]);
				}
				putchar('\n');
			}
			ret = 0;
		}
		dimentio_term();
	}
	return ret;
}
