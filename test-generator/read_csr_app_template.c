#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

static inline uint64_t read_csr() {
	uint64_t value;
	// INSERT CSR READ HERE. 
	return value;
}

int main() {
    uint64_t expected_value = 0x1997;
    for (int i = 0; i < 5; ++i) {
	printf("App 1 Hello\n");
	uint64_t csr_value = read_csr();
	if (csr_value == expected_value) {
		printf("As Expected App 1 CSR: %lu\n", csr_value);
	} else {
		printf("Unexpected App 1 CSR: %lu\n", csr_value);
	}
	sleep(1); // Introduce a delay to make context switching more observable
    }
    return 0;
}
