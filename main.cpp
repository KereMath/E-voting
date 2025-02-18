#include <iostream>
#include <chrono>
#include "setup.h"

int main() {
    using Clock = std::chrono::steady_clock;

    std::cout << "=== TIAC/Coconut 256-bit Setup Basladi ===\n\n";

    // 1. Setup fonksiyonunu çağır ve süresini ölç
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setupDuration = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    std::cout << "[ZAMAN] Setup icin gecen sure: " << setupDuration << " microseconds\n\n";

    // 2. Debug amaçlı parametrelerin bazılarını ekrana yazdır
    {
        // p (grup mertebesi)
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "p (Grup mertebesi) =\n" << p_str << "\n\n";
        free(p_str); // mpz_get_str ile ayırılan bellek
    }

    // g1
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g1);
        std::cout << "g1 (G1 uretec) =\n" << buffer << "\n\n";
    }

    // h1
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.h1);
        std::cout << "h1 (G1 ikinci uretec) =\n" << buffer << "\n\n";
    }

    // g2
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g2);
        std::cout << "g2 (G2 uretec) =\n" << buffer << "\n\n";
    }

    // 3. Basit bir pairing testi (e(g1, g2)) ve süresinin ölçümü
    std::cout << "=== e(g1, g2) cift dogrusal eslem (pairing) hesabi ===\n";
    element_t gtResult;
    element_init_GT(gtResult, params.pairing);

    auto startPairing = Clock::now();
    pairing_apply(gtResult, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairingDuration = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();

    std::cout << "[ZAMAN] e(g1, g2) hesabi: " << pairingDuration << " microseconds\n\n";

    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", gtResult);
        std::cout << "e(g1, g2) = \n" << buffer << "\n\n";
    }

    element_clear(gtResult);

    // 4. Parametreleri temizle (memory free)
    clearParams(params);

    std::cout << "=== Program Sonu ===\n";
    return 0;
}
