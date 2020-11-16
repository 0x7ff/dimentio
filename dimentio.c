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

#include "dimentio.h"

#include <stdio.h>
#include <inttypes.h>

static void show_help() {
	printf("Usage: dimentio <get|nonce>\n\n");
	printf("Example:\n");
	printf("set generator: dimentio 0x1111111111111111\n");
	printf("get generator: dimentio get\n");
}

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

int main(int argc, char **argv) {
	uint64_t nonce;
	kern_return_t ret;
	uint8_t entangled_nonce[CC_SHA384_DIGEST_LENGTH];

	if (argc != 2) {
		show_help();
		return 0;
	}

	if (sscanf(argv[1], "0x%016" PRIx64, &nonce) == 1) {
		ret = dimentio(nonce, entangled_nonce);
		if (ret == KERN_SUCCESS) {
			printf("Set nonce to 0x%016" PRIX64 "\n", nonce);
			printf("entangled_nonce: ");
			for(int i = 0; i < MIN(CC_SHA384_DIGEST_LENGTH, 32); ++i) {
				printf("%02" PRIX8, entangled_nonce[i]);
			}
			putchar('\n');
		} else {
			printf("Failed to set nonce.\n");
		}
	} else if (strcmp(argv[1], "get") == 0) {
		ret = undimentio(&nonce);
		if (ret == KERN_SUCCESS) {
			printf("generator: 0x%016" PRIx64 "\n", nonce);
		} else {
			printf("Failed to get generator.\n");
		}
	} else {
		show_help();
	}
}
