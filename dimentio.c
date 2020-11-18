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
#include "libdimentio.h"

int
main(int argc, char **argv) {
	uint8_t entangled_nonce[CC_SHA384_DIGEST_LENGTH];
	bool entangled = false;
	uint64_t nonce = 0;
	size_t i;

	if(argc != 1 && argc != 2) {
		printf("Usage: %s [nonce]\n", argv[0]);
	} else if((argc == 1 || sscanf(argv[1], "0x%016" PRIx64, &nonce) == 1) && dimentio_init(0, NULL, NULL) == KERN_SUCCESS) {
		if((argc == 1 ? dementia(&nonce, entangled_nonce, &entangled) : dimentio(nonce, entangled_nonce, &entangled)) == KERN_SUCCESS) {
			if(argc == 1) {
				printf("Current nonce is 0x%016" PRIX64 "\n", nonce);
			} else {
				printf("Set nonce to 0x%016" PRIX64 "\n", nonce);
			}
			if(entangled) {
				printf("entangled_nonce: ");
				for(i = 0; i < MIN(sizeof(entangled_nonce), 32); ++i) {
					printf("%02" PRIX8, entangled_nonce[i]);
				}
				putchar('\n');
			}
		}
		dimentio_term();
	}
}
