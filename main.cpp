#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include "setup.h"
#include "keygen.h"

int main() {
    using Clock = std::chrono::steady_clock;

    // 1) params.txt dosyasından ne (EA sayısı) ve t (eşik) değerlerini oku
    int ne = 0, t = 0;
    {
        std::ifstream infile("params.txt");
        if(!infile) {
            std::cerr << "Error: params.txt acilamadi!" << std::endl;
            return 1;
        }
        std::string line;
        while (std::getline(infile, line)) {
            if (line.find("ea=") == 0) {
                ne = std::stoi(line.substr(3));
            } else if (line.find("threshold=") == 0) {
                t = std::stoi(line.substr(10));
            }
        }
        infile.close();
    }

    if(ne == 0 || t == 0) {
        std::cerr << "params.txt dosyasindan EA sayisi ya da esik degeri okunamadi!\n";
        return 1;
    }
    std::cout << "EA sayisi (ne) = " << ne << std::endl;
    std::cout << "Esik degeri (t) = " << t << std::endl << std::endl;

    // 2) Setup (Algoritma 1) ve zaman ölçümü
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setupDuration_us = 
        std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // 3) Parametreleri ekrana basma (debug amaçlı)
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

    // 4) Pairing testi (isteğe bağlı)
    element_t pairingTest;
    element_init_GT(pairingTest, params.pairing);

    auto startPairing = Clock::now();
    pairing_apply(pairingTest, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairingDuration_us = 
        std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();

    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", pairingTest);
        std::cout << "[ZAMAN] e(g1, g2) hesabi: " 
                  << pairingDuration_us << " microseconds\n";
        std::cout << "e(g1, g2) = \n" << buffer << "\n\n";
    }
    element_clear(pairingTest);

    // 5) Key Generation (Algoritma 2) ve zaman ölçümü
    std::cout << "=== TTP ile Anahtar Uretimi (KeyGen) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration_us = 
        std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();

    // 6) MasterVerKey ekrana bas
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.alpha2);
        std::cout << "mvk.alpha2 = g2^x =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta2);
        std::cout << "mvk.beta2 = g2^y =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta1);
        std::cout << "mvk.beta1 = g1^y =\n" << buffer << "\n\n";
    }

    // 7) Her bir EA otoritesinin alt anahtarlarını (sgk, vkm) ekrana bas
    for(int i = 0; i < ne; i++){
        std::cout << "=== EA Authority " << (i+1) << " ===\n";

        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk1);
            std::cout << "sgk1 (xm) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk2);
            std::cout << "sgk2 (ym) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm1);
            std::cout << "vkm1 = g2^(xm) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm2);
            std::cout << "vkm2 = g2^(ym) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm3);
            std::cout << "vkm3 = g1^(ym) = " << buffer << "\n";
        }
        std::cout << std::endl;
    }

    // 8) Bellek temizliği: keyOut içindeki element_t alanları
    // (Eğer uzun süre saklanacaksa, struct'lar bu fonk. dışında temizlenmemeli.)
    element_clear(keyOut.mvk.alpha2);
    element_clear(keyOut.mvk.beta2);
    element_clear(keyOut.mvk.beta1);
    for(int i = 0; i < ne; i++){
        element_clear(keyOut.eaKeys[i].sgk1);
        element_clear(keyOut.eaKeys[i].sgk2);
        element_clear(keyOut.eaKeys[i].vkm1);
        element_clear(keyOut.eaKeys[i].vkm2);
        element_clear(keyOut.eaKeys[i].vkm3);
    }

    // 9) Setup parametrelerini temizle
    clearParams(params);

    // 10) Zaman ölçümlerini (ms cinsinden) raporla
    double setup_ms   = setupDuration_us   / 1000.0;
    double pairing_ms = pairingDuration_us / 1000.0;
    double keygen_ms  = keygenDuration_us  / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi : " << setup_ms   << " ms\n";
    std::cout << "Pairing suresi : " << pairing_ms << " ms\n";
    std::cout << "KeyGen suresi : " << keygen_ms  << " ms\n";

    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
