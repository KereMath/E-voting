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
#include "prepareblindsign.h"
#include "blindsign.h"

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
    
    // 2. Setup: Sistem parametrelerini oluştur
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
    
    // 4. Key Generation (Coconut TTP'siz / Pedersen's DKG)
    std::cout << "=== Coconut TTP'siz Anahtar Uretimi (Pedersen's DKG) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    
    // Master verification key çıktıları
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
    
    std::cout << "Secmen sayisi: " << voterCount << "\n\n";
    
    // 5. ID Generation: Rastgele 11 haneli sayısal ID'ler oluşturulması
    std::vector<std::string> voterIDs(voterCount);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dist(10000000000ULL, 99999999999ULL);
    auto startIDGen = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        unsigned long long randNum = dist(gen);
        voterIDs[i] = std::to_string(randNum);
    }
    auto endIDGen = Clock::now();
    auto idGenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endIDGen - startIDGen).count();
    
    // 6. DID Generation: Her seçmenin oluşturulan ID'sini kullanarak DID üretilmesi
    std::vector<DID> dids(voterCount);
    auto startDIDGen = Clock::now();
    
    for (int i = 0; i < voterCount; i++) {
        // params gönderilmiyor; sadece gerçek ID yeterli.
        dids[i] = createDID(voterIDs[i]);
        
        std::cout << "Secmen " << (i + 1) << " icin x degeri = " << dids[i].x << "\n";
        std::cout << "Secmen " << (i + 1) << " icin olusturulan ID = " << voterIDs[i] << "\n";
        std::cout << "Secmen " << (i + 1) << " icin DID (SHA512 hash) = " << dids[i].did << "\n\n";
    }
    
    auto endDIDGen = Clock::now();
    auto didGenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endDIDGen - startDIDGen).count();
    // 7. Prepare Blind Sign: Her seçmenin kendi prepare blind sign mesajını hazırlaması
    std::vector<BlindSignOutput> bsOutputs(voterCount);
    auto startBlindSign = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        bsOutputs[i] = prepareBlindSign(params, voterIDs[i]);
        std::cout << "=== Secmen " << (i+1) << " icin Prepare Blind Sign Sonuclari ===\n";
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].comi);
            std::cout << "comi = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].h);
            std::cout << "h = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].com);
            std::cout << "com = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].pi_s.c);
            std::cout << "πs.c = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].pi_s.s1);
            std::cout << "πs.s1 = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].pi_s.s2);
            std::cout << "πs.s2 = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", bsOutputs[i].pi_s.s3);
            std::cout << "πs.s3 = " << buffer << "\n";
        }
        std::cout << "\n";
    }
    auto endBlindSign = Clock::now();
    auto blindSignDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endBlindSign - startBlindSign).count();
    
    // 8. Final Blind Signature Generation: Algoritma 12
    // Örnek: voterin secret değerleri xm, ym olarak DID üretiminde kullanılan x değeri kullanılıyor.
    std::vector<BlindSignature> finalSigs(voterCount);
    auto startFinalSign = Clock::now();
// Final blind signature: Her seçmenin hazırladığı mesajı, her EA otoritesi ayrı ayrı imzalar.
    for (int i = 0; i < voterCount; i++) {
        std::cout << "=== Secmen " << (i+1) << " için EA otoritelerinin Blind Signature sonuçları ===\n";
        for (int j = 0; j < ne; j++) {
            BlindSignature sig = blindSign(params, bsOutputs[i],
                                            keyOut.eaKeys[j].secret_x, 
                                            keyOut.eaKeys[j].secret_y);
            std::cout << "EA " << (j+1) << " imza sonuçları:\n";
            {
                char buffer[1024];
                element_snprintf(buffer, sizeof(buffer), "%B", sig.h);
                std::cout << "Final Sig h = " << buffer << "\n";
            }
            {
                char buffer[1024];
                element_snprintf(buffer, sizeof(buffer), "%B", sig.cm);
                std::cout << "Final Sig cm = " << buffer << "\n\n";
            }
        }
    }

    auto endFinalSign = Clock::now();
    auto finalSignDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endFinalSign - startFinalSign).count();
    
    // 9. Bellek temizliği: mvk ve EA anahtar bileşenleri
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
    
    // 10. Setup parametrelerini temizle
    clearParams(params);
    
    // 11. Süre ölçümleri (ms cinsinden)
    double setup_ms     = setupDuration_us / 1000.0;
    double pairing_ms   = pairingDuration_us / 1000.0;
    double keygen_ms    = keygenDuration_us / 1000.0;
    double idGen_ms     = idGenDuration_us / 1000.0;
    double didGen_ms    = didGenDuration_us / 1000.0;
    double blindSign_ms = blindSignDuration_us / 1000.0;
    double finalSign_ms = finalSignDuration_us / 1000.0;
    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi: " << setup_ms << " ms\n";
    std::cout << "Pairing suresi: " << pairing_ms << " ms\n";
    std::cout << "Key Generation suresi: " << keygen_ms << " ms\n";
    std::cout << "ID Generation suresi: " << idGen_ms << " ms\n";
    std::cout << "DID Generation suresi: " << didGen_ms << " ms\n";
    std::cout << "Prepare Blind Sign suresi: " << blindSign_ms << " ms\n";
    std::cout << "Final Blind Signature Generation suresi: " << finalSign_ms << " ms\n";
    
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
