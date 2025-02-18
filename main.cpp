#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include "setup.h"
#include "keygen.h"
#include "DIDgen.h"

int main() {
    using Clock = std::chrono::steady_clock;
    
    // 1. params.txt dosyasından parametreleri oku
    int ne, t, voterCount;
    std::ifstream infile("params.txt");
    if (!infile) {
        std::cerr << "Error: params.txt bulunamadi!" << std::endl;
        return 1;
    }
    std::string line;
    while (std::getline(infile, line)) {
        if (line.find("ea=") == 0)
            ne = std::stoi(line.substr(3));
        else if (line.find("threshold=") == 0)
            t = std::stoi(line.substr(10));
        else if (line.find("votercount=") == 0)
            voterCount = std::stoi(line.substr(11));
    }
    infile.close();
    
    std::cout << "params.txt'den okunan degerler:" << std::endl;
    std::cout << "EA otoritesi sayisi: " << ne << std::endl;
    std::cout << "Esik degeri (t): " << t << " (Polinom derecesi = t-1)" << std::endl;
    std::cout << "Secmen sayisi: " << voterCount << "\n\n";
    
    // 2. Setup aşaması: Sistem parametrelerini oluştur
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setupDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();
    
    // Debug: Setup çıktıları
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
    
    // 3. Pairing testi
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
    
    // 4. Anahtar Üretimi (Key Generation)
    std::cout << "=== Coconut TTP'siz Anahtar Uretimi (Pedersen's DKG) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    
    // Master doğrulama anahtarı çıktıları
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
    
    // EA otoriteleri çıktıları
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
    
    // 5. Seçmen (voter) sayısı params.txt'den alındı (voterCount)
    // (voterCount değişkeni params.txt'den okundu)
    std::cout << "Secmen sayisi: " << voterCount << "\n\n";
    
    // 6. Her seçmen için gerçek ID'yi kullanıcıdan sormadan rastgele 11 haneli sayisal ID oluştur ve DID üret
    std::vector<DID> dids(voterCount);
    auto startDID = Clock::now();
    
    // Random 11 haneli sayı üretimi için C++11 random kütüphanesi kullanılıyor.
    std::random_device rd;
    std::mt19937_64 gen(rd());
    // 11 haneli sayı aralığı: [10000000000, 99999999999]
    std::uniform_int_distribution<unsigned long long> dist(10000000000ULL, 99999999999ULL);
    
    for (int i = 0; i < voterCount; i++) {
        // Rastgele 11 haneli sayı oluştur ve string'e çevir
        unsigned long long randNum = dist(gen);
        std::string realID = std::to_string(randNum);
        dids[i] = createDID(params, realID);
        
        // x değeri ve DID çıktısını yazdır
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", dids[i].x);
            std::cout << "Secmen " << (i+1) << " icin x degeri = " << buffer << "\n";
        }
        std::cout << "Secmen " << (i+1) << " icin gercek ID = " << realID << "\n";
        std::cout << "Secmen " << (i+1) << " icin DID (SHA512 hash) = " << dids[i].did << "\n\n";
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
