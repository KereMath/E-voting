#include <iostream>
#include <chrono>
#include "setup.h"

int main() {
    using Clock = std::chrono::steady_clock;

    // 1) Setup
    auto start = Clock::now();
    TIACParams params = setupParams();
    auto end = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // 2) Bilgileri ekrana bas
    // Mertebe p
    char* str_p = mpz_get_str(nullptr, 10, params.prime_order);
    std::cout << "p = " << str_p << "\n";
    free(str_p);

    // g1, h1, g2
    {
        char buf[512];
        element_snprintf(buf, sizeof(buf), "%B", params.g1);
        std::cout << "g1 = " << buf << "\n";
        element_snprintf(buf, sizeof(buf), "%B", params.h1);
        std::cout << "h1 = " << buf << "\n";
        element_snprintf(buf, sizeof(buf), "%B", params.g2);
        std::cout << "g2 = " << buf << "\n";
    }

    // 3) Pairing testi: e(g1, g2)
    element_t testGT;
    element_init_GT(testGT, params.pairing);

    auto startPair = Clock::now();
    pairing_apply(testGT, params.g1, params.g2, params.pairing);
    auto endPair = Clock::now();
    auto pair_us = std::chrono::duration_cast<std::chrono::microseconds>(endPair - startPair).count();

    {
        char bigBuf[16384]; // veya 4096, 8192...
        element_snprintf(bigBuf, sizeof(bigBuf), "%B", testGT);
        std::cout << "e(g1, g2) = " << bigBuf << "\n";
        
    }
    element_clear(testGT);

    std::cout << "\n[INFO] Setup süresi  : " << (setup_us/1000.0) << " ms\n";
    std::cout << "[INFO] Pairing süresi: " << (pair_us/1000.0) << " ms\n";

    // 4) Temizlik
    clearParams(params);
    std::cout << "[INFO] Program bitti.\n";
    return 0;
}
