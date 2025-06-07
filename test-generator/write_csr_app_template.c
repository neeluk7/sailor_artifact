#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

static inline void write_csr(uint64_t value) {
	// INSERT CSR WRITE HERE. 
}

int main() {
    for (int i = 0; i < 5; ++i) {
	printf("App 2 Hello\n");
	write_csr(0x1997);
        sleep(1); // Introduce a delay to make context switching more observable
    }
    return 0;
}
