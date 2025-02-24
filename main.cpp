#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include "setup.h"
#include "keygen.h"

int main() {
    using Clock = std::chrono::steady_clock;

    // 1) params.txt dosyasından n, t, voterCount gibi değerleri oku
    //    (Siz isterseniz sadece n ve t yeterli olabilir)
    int ne, t, voterCount;
    {
        std::ifstream infile("params.txt");
        if (!infile) {
            std::cerr << "Error: params.txt bulunamadi!\n";
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
    }

    std::cout << "==== Parametreler ====\n";
    std::cout << "EA (otorite) sayisi: " << ne << "\n";
    std::cout << "Esik degeri (t): " << t << "\n";
    std::cout << "Secmen sayisi: " << voterCount << "\n\n";

    // 2) Setup (Sistem parametreleri kurulumu)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setupDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // -- Debug: Basit çıktılar
    {
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "[DEBUG] p (Grup mertebesi) = " << p_str << "\n";
        free(p_str);
    }
    {
        char buf[256];
        element_snprintf(buf, 256, "%B", params.g1);
        std::cout << "[DEBUG] g1 (G1 uretici) = " << buf << "\n";
        element_snprintf(buf, 256, "%B", params.h1);
        std::cout << "[DEBUG] h1 (G1 ikinci uretici) = " << buf << "\n";
        element_snprintf(buf, 256, "%B", params.g2);
        std::cout << "[DEBUG] g2 (G2 uretici) = " << buf << "\n\n";
    }

    // 3) Pairing testi
    element_t testPair;
    element_init_GT(testPair, params.pairing);
    auto startPairing = Clock::now();
    pairing_apply(testPair, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairingDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();

    {
        char buf[256];
        element_snprintf(buf, 256, "%B", testPair);
        std::cout << "[INFO] e(g1, g2) hesaplandi. \n";
        std::cout << "       e(g1, g2) = " << buf << "\n\n";
    }
    element_clear(testPair);

    // 4) Key Generation (TTP'siz Pedersen DKG)
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();

    // -- Master Public Key
    {
        char buf[256];
        element_snprintf(buf, 256, "%B", keyOut.mvk.vk1);
        std::cout << "mvk.vk1 = g2^(∑ x_i0) = " << buf << "\n";
        element_snprintf(buf, 256, "%B", keyOut.mvk.vk2);
        std::cout << "mvk.vk2 = g2^(∑ y_i0) = " << buf << "\n";
        element_snprintf(buf, 256, "%B", keyOut.mvk.vk3);
        std::cout << "mvk.vk3 = g1^(∑ y_i0) = " << buf << "\n\n";
    }
    // -- Master Secret Key
    {
        char buf[256];
        element_snprintf(buf, 256, "%B", keyOut.msk.sk1);
        std::cout << "msk.sk1 (∑ x_i0) = " << buf << "\n";
        element_snprintf(buf, 256, "%B", keyOut.msk.sk2);
        std::cout << "msk.sk2 (∑ y_i0) = " << buf << "\n\n";
    }

    // -- EA'lerin local payları:
    for (int i = 0; i < ne; i++) {
        std::cout << "--- EA " << (i+1) << " ---\n";
        {
            char buf[256];
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].x_m);
            std::cout << " x_m (F_i(0)) = " << buf << "\n";
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].y_m);
            std::cout << " y_m (G_i(0)) = " << buf << "\n";
        }
        {
            char buf[256];
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].sgk1);
            std::cout << " sgk1 = ∑ F_l(" << (i+1) << ") = " << buf << "\n";
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].sgk2);
            std::cout << " sgk2 = ∑ G_l(" << (i+1) << ") = " << buf << "\n";
        }
        {
            char buf[256];
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].vki1);
            std::cout << " vki1 = g2^(sgk1) = " << buf << "\n";
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].vki2);
            std::cout << " vki2 = g2^(sgk2) = " << buf << "\n";
            element_snprintf(buf, 256, "%B", keyOut.eaKeys[i].vki3);
            std::cout << " vki3 = g1^(sgk2) = " << buf << "\n";
        }
        std::cout << "\n";
    }

    // 5) Süre ölçümleri
    double setup_ms   = setupDuration_us / 1000.0;
    double pairing_ms = pairingDuration_us / 1000.0;
    double keygen_ms  = keygenDuration_us / 1000.0;

    std::cout << "==== ZAMAN ÖLÇÜMLERİ ====\n";
    std::cout << "Setup süresi:     " << setup_ms   << " ms\n";
    std::cout << "Pairing süresi:   " << pairing_ms << " ms\n";
    std::cout << "KeyGen süresi:    " << keygen_ms  << " ms\n";

    // 6) Bellek temizliği
    // Master VK
    element_clear(keyOut.mvk.vk1);
    element_clear(keyOut.mvk.vk2);
    element_clear(keyOut.mvk.vk3);
    // Master SK
    element_clear(keyOut.msk.sk1);
    element_clear(keyOut.msk.sk2);

    // Her EA
    for (int i = 0; i < ne; i++) {
        element_clear(keyOut.eaKeys[i].x_m);
        element_clear(keyOut.eaKeys[i].y_m);
        element_clear(keyOut.eaKeys[i].sgk1);
        element_clear(keyOut.eaKeys[i].sgk2);
        element_clear(keyOut.eaKeys[i].vki1);
        element_clear(keyOut.eaKeys[i].vki2);
        element_clear(keyOut.eaKeys[i].vki3);
    }

    // Setup parametreleri
    clearParams(params);

    std::cout << "\n[INFO] Program sonu.\n";
    return 0;
}
