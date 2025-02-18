#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include "setup.h"
#include "keygen.h"
#include "DIDgen.h"

int main() {
    using Clock = std::chrono::steady_clock;
    
    // 1. Kullanıcıdan EA otoritesi sayısı (ne) ve eşik değeri (t) alınması
    int t, ne;
    std::cout << "EA otoritesi sayisi kac olacak? ";
    std::cin >> ne;
    std::cout << "Esik degeri (t) kac? (Polinom derecesi = t-1 olacak) ";
    std::cin >> t;
    std::cout << "\n";
    
    // 2. Setup aşaması: Sistem parametrelerinin oluşturulması
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setupDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();
    
    // Debug: Setup parametrelerinin çıktıları
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
    
    // 3. Pairing testi: G1 ve G2 arasında bilinear eşleme
    std::cout << "=== e(g1, g2) cift dogrusal eslem (pairing) hesabi ===\n";
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
    
    // 4. Anahtar Üretimi (Key Generation) aşaması (Coconut TTP'siz / Pedersen's DKG)
    std::cout << "=== Coconut TTP'siz Anahtar Uretimi (Pedersen's DKG) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    
    // Master doğrulama anahtarı (mvk) çıktıları
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.alpha2);
        std::cout << "mvk.alpha2 (g1^(∏ F_i(0)^2)) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta2);
        std::cout << "mvk.beta2 (g1^(∏ G_i(0)^2)) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta1);
        std::cout << "mvk.beta1 (g1^(∏ G_i(0))) =\n" << buffer << "\n\n";
    }
    
    // EA otoriteleri için anahtar çıktıları
    for (int i = 0; i < ne; i++) {
        std::cout << "=== EA Authority " << (i + 1) << " ===\n";
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk1);
            std::cout << "sgk1 (∏_{l} F_l(" << (i+1) << ")) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk2);
            std::cout << "sgk2 (∏_{l} G_l(" << (i+1) << ")) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm1);
            std::cout << "vkm.alpha2 (g1^(sgk1^2)) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm2);
            std::cout << "vkm.beta2 (g1^(sgk2^2)) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm3);
            std::cout << "vkm.beta1 (g1^(sgk2)) = " << buffer << "\n";
        }
        std::cout << "\n";
    }
    
    // 5. Seçmen (voter) sayısını kullanıcıdan alma
    int voterCount;
    std::cout << "Kac tane secmen (voter) var? ";
    std::cin >> voterCount;
    std::cout << "\n";
    
    // 6. Her seçmen için gerçek ID girilerek DID oluşturulması (SHA-512 hash)
    std::vector<DID> dids(voterCount);
    auto startDID = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        std::string realID;
        std::cout << "Secmen " << (i+1) << " icin gercek ID (11 haneli sayisal) giriniz: ";
        std::cin >> realID;
        dids[i] = createDID(params, realID);
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", dids[i].x);
            std::cout << "Secmen " << (i+1) << " icin x degeri = " << buffer << "\n";
        }
        std::cout << "Secmen " << (i+1) << " icin DID (SHA512 hash) = " << dids[i].did << "\n";
        std::cout << "Secmen " << (i+1) << " gercek ID = " << dids[i].realID << "\n\n";
    }
    auto endDID = Clock::now();
    auto didDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endDID - startDID).count();
    
    // 7. Bellek temizliği: mvk ve EA anahtar bileşenleri
    element_clear(keyOut.mvk.alpha2);
    element_clear(keyOut.mvk.beta2);
    element_clear(keyOut.mvk.beta1);
    for (int i = 0; i < ne; i++) {
        element_clear(keyOut.eaKeys[i].sgk1);
        element_clear(keyOut.eaKeys[i].sgk2);
        element_clear(keyOut.eaKeys[i].vkm1);
        element_clear(keyOut.eaKeys[i].vkm2);
        element_clear(keyOut.eaKeys[i].vkm3);
    }
    
    // 8. Setup parametrelerini temizle
    clearParams(params);
    
    // 9. Tüm ölçüm sürelerini milisaniye (ms) cinsine çevirip raporla
    double setup_ms    = setupDuration_us / 1000.0;
    double pairing_ms  = pairingDuration_us / 1000.0;
    double keygen_ms   = keygenDuration_us / 1000.0;
    double did_ms      = didDuration_us / 1000.0;
    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi: " << setup_ms << " ms\n";
    std::cout << "Pairing suresi: " << pairing_ms << " ms\n";
    std::cout << "Key Generation suresi: " << keygen_ms << " ms\n";
    std::cout << "DID Generation suresi: " << did_ms << " ms\n";
    
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
