#include <iostream>
#include <chrono>
#include "setup.h"
#include "keygen.h"

int main() {
    using Clock = std::chrono::steady_clock;
    
    std::cout << "=== TIAC/Coconut 256-bit Setup Basladi ===\n\n";
    
    // Setup aşaması
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setupDuration = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();
    std::cout << "[ZAMAN] Setup icin gecen sure: " << setupDuration << " microseconds\n\n";
    
    // Debug: Setup parametrelerini ekrana yazdırma
    {
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "p (Grup mertebesi) =\n" << p_str << "\n\n";
        free(p_str);
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g1);
        std::cout << "g1 (G1 uretec) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.h1);
        std::cout << "h1 (G1 ikinci uretec) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g2);
        std::cout << "g2 (G2 uretec) =\n" << buffer << "\n\n";
    }
    
    // Pairing testi
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
    
    // Anahtar Üretimi (Key Generation) aşaması
    std::cout << "=== Coconut TTP ile Anahtar Uretimi (Key Generation) ===\n";
    int t = 2;    // Örneğin eşik değeri 2 (yani polinom derecesi 1)
    int ne = 3;   // EA otoritesi sayısı (örnek: 3)
    
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    std::cout << "[ZAMAN] Key Generation icin gecen sure: " << keygenDuration << " microseconds\n\n";
    
    // Master Doğrulama Anahtarı (mvk) çıktısını yazdırma
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.alpha2);
        std::cout << "mvk.alpha2 (g1^(v(0)^2)) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta2);
        std::cout << "mvk.beta2 (g1^(w(0)^2)) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta1);
        std::cout << "mvk.beta1 (g1^(w(0))) =\n" << buffer << "\n\n";
    }
    
    // EA Otoriteleri için anahtar çıktıları
    for (int i = 0; i < ne; i++) {
        std::cout << "=== EA Authority " << (i + 1) << " ===\n";
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk_x);
            std::cout << "sgk_x (v(" << (i + 1) << ")) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk_y);
            std::cout << "sgk_y (w(" << (i + 1) << ")) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].alpha2);
            std::cout << "vkm.alpha2 (g1^(v(" << (i + 1) << ")^2)) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].beta2);
            std::cout << "vkm.beta2 (g1^(w(" << (i + 1) << ")^2)) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].beta1);
            std::cout << "vkm.beta1 (g1^(w(" << (i + 1) << "))) = " << buffer << "\n";
        }
        std::cout << "\n";
    }
    
    // Bellek temizliği
    // mvk için:
    element_clear(keyOut.mvk.alpha2);
    element_clear(keyOut.mvk.beta2);
    element_clear(keyOut.mvk.beta1);
    // Her EA için:
    for (int i = 0; i < ne; i++) {
        element_clear(keyOut.eaKeys[i].sgk_x);
        element_clear(keyOut.eaKeys[i].sgk_y);
        element_clear(keyOut.eaKeys[i].alpha2);
        element_clear(keyOut.eaKeys[i].beta2);
        element_clear(keyOut.eaKeys[i].beta1);
    }
    
    // Setup parametrelerini serbest bırakma
    clearParams(params);
    
    std::cout << "=== Program Sonu ===\n";
    return 0;
}
