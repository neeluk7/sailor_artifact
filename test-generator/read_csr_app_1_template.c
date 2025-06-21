#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

static inline uint64_t read_csr() {
    uint64_t value;
    // INSERT CSR READ HERE. 
    return value;
}

int main() {
    for (int i = 0; i < 5; ++i) {
	printf("App 1 Hello\n");
	uint64_t csr_val = read_csr();	
    	printf("App 1 csr_val: %lu\n", csr_val);
        sleep(1); // Introduce a delay to make context switching more observable
    }
    return 0;
}
