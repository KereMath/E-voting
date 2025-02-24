#include <iostream>
#include <chrono>
#include "setup.h"

int main() {
    using Clock = std::chrono::steady_clock;

    // 1. Setup aşaması ve zaman ölçümü
    auto startSetup = Clock::now();
    TIACParams params = setupParams();  // Algoritma 1'in gerçekleştiği yer
    auto endSetup = Clock::now();
    auto setupDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // 2. Kurulum sonrası parametreleri ekrana bas (debug amaçlı)
    {
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "p (Grup mertebesi) =\n" << p_str << "\n\n";
        free(p_str);
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g1);
        std::cout << "g1 (G1 uretici) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.h1);
        std::cout << "h1 (G1 ikinci uretici) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g2);
        std::cout << "g2 (G2 uretici) =\n" << buffer << "\n\n";
    }

    // 3. (İsteğe bağlı) Pairing testi - e(g1, g2) hesaplama ve zamanı
    element_t gtResult;
    element_init_GT(gtResult, params.pairing);

    auto startPairing = Clock::now();
    pairing_apply(gtResult, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairingDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();

    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", gtResult);
        std::cout << "[ZAMAN] e(g1, g2) hesabi: " << pairingDuration_us << " microseconds\n";
        std::cout << "e(g1, g2) = \n" << buffer << "\n\n";
    }

    element_clear(gtResult);

    // 4. Parametreleri bellekten temizle
    clearParams(params);

    // 5. Ölçüm sonuçlarını yazdırma (ms cinsinden)
    double setup_ms   = setupDuration_us   / 1000.0;
    double pairing_ms = pairingDuration_us / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi : " << setup_ms   << " ms\n";
    std::cout << "Pairing suresi : " << pairing_ms << " ms\n";

    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
