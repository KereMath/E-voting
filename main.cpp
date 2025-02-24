#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
#include "setup.h"
#include "keygen.h"

int main(){
    using Clock = std::chrono::steady_clock;

    // 1) params.txt okuma
    int ne=3, t=2, voterCount=5;
    {
        std::ifstream infile("params.txt");
        if(infile){
            std::string line;
            while(std::getline(infile, line)){
                if(line.find("ea=")==0) {
                    ne = std::stoi(line.substr(3));
                } else if(line.find("threshold=")==0) {
                    t = std::stoi(line.substr(10));
                } else if(line.find("votercount=")==0) {
                    voterCount = std::stoi(line.substr(11));
                }
            }
        }
    }
    std::cout << "[INFO] EA sayisi = " << ne << "\n";
    std::cout << "[INFO] Eşik (t) = " << t << "\n";
    std::cout << "[INFO] Seçmen sayisi = " << voterCount << "\n\n";

    // 2) Setup (Bilinear grup parametreleri)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // Debug: p, g1, h1, g2
    {
        char* p_str = mpz_get_str(nullptr,10, params.prime_order);
        std::cout << "p = " << p_str << "\n";
        free(p_str);
    }
    {
        char buf[256];
        element_snprintf(buf, 256, "%B", params.g1);
        std::cout << "g1 = " << buf << "\n";
        element_snprintf(buf, 256, "%B", params.h1);
        std::cout << "h1 = " << buf << "\n";
        element_snprintf(buf, 256, "%B", params.g2);
        std::cout << "g2 = " << buf << "\n\n";
    }

    // 3) Pairing testi
    element_t testGT;
    element_init_GT(testGT, params.pairing);

    auto startPair = Clock::now();
    pairing_apply(testGT, params.g1, params.g2, params.pairing);
    auto endPair = Clock::now();
    auto pair_us = std::chrono::duration_cast<std::chrono::microseconds>(endPair - startPair).count();

    {
        char buf[256];
        element_snprintf(buf, 256, "%B", testGT);
        std::cout << "e(g1, g2) = " << buf << "\n\n";
    }
    element_clear(testGT);

    // 4) Key Generation (Pedersen’s DKG, herkes geçerli pay üretiyor)
    auto startKG = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKG = Clock::now();
    auto kg_us = std::chrono::duration_cast<std::chrono::microseconds>(endKG - startKG).count();

    // 4.1) Master Public Key
    {
        char b1[256], b2[256], b3[256];
        element_snprintf(b1,256, "%B", keyOut.mvk.vk1);
        element_snprintf(b2,256, "%B", keyOut.mvk.vk2);
        element_snprintf(b3,256, "%B", keyOut.mvk.vk3);
        std::cout << "mvk.vk1 = g2^(∑ x_i0) = " << b1 << "\n";
        std::cout << "mvk.vk2 = g2^(∑ y_i0) = " << b2 << "\n";
        std::cout << "mvk.vk3 = g1^(∑ y_i0) = " << b3 << "\n\n";
    }

    // 4.2) Master Secret Key
    {
        char b1[256], b2[256];
        element_snprintf(b1,256, "%B", keyOut.msk.sk1);
        element_snprintf(b2,256, "%B", keyOut.msk.sk2);
        std::cout << "msk.sk1 (∑ x_i0) = " << b1 << "\n";
        std::cout << "msk.sk2 (∑ y_i0) = " << b2 << "\n\n";
    }

    // 4.3) EA payları
    for (int i=0; i<ne; i++){
        std::cout << "=== EA#" << (i+1) << " ===\n";
        char b1[256], b2[256], b3[256], b4[256], b5[256], b6[256], b7[256];
        element_snprintf(b1,256,"%B", keyOut.eaKeys[i].x_m);
        element_snprintf(b2,256,"%B", keyOut.eaKeys[i].y_m);
        element_snprintf(b3,256,"%B", keyOut.eaKeys[i].sgk1);
        element_snprintf(b4,256,"%B", keyOut.eaKeys[i].sgk2);
        element_snprintf(b5,256,"%B", keyOut.eaKeys[i].vki1);
        element_snprintf(b6,256,"%B", keyOut.eaKeys[i].vki2);
        element_snprintf(b7,256,"%B", keyOut.eaKeys[i].vki3);

        std::cout << " x_m (F_i(0)) = " << b1 << "\n";
        std::cout << " y_m (G_i(0)) = " << b2 << "\n";
        std::cout << " sgk1 = " << b3 << "\n";
        std::cout << " sgk2 = " << b4 << "\n";
        std::cout << " vki1 = g2^(sgk1) = " << b5 << "\n";
        std::cout << " vki2 = g2^(sgk2) = " << b6 << "\n";
        std::cout << " vki3 = g1^(sgk2) = " << b7 << "\n\n";
    }

    // 5) Süre ölçümleri (ms)
    double setup_ms = setup_us / 1000.0;
    double pair_ms  = pair_us  / 1000.0;
    double kg_ms    = kg_us    / 1000.0;

    std::cout << "=== ZAMAN ===\n";
    std::cout << "Setup  : " << setup_ms << " ms\n";
    std::cout << "Pairing: " << pair_ms  << " ms\n";
    std::cout << "KeyGen : " << kg_ms    << " ms\n\n";

    // 6) Bellek temizliği
    // Master VK
    element_clear(keyOut.mvk.vk1);
    element_clear(keyOut.mvk.vk2);
    element_clear(keyOut.mvk.vk3);

    // Master SK
    element_clear(keyOut.msk.sk1);
    element_clear(keyOut.msk.sk2);

    // EA payları
    for(int i=0; i<ne; i++){
        element_clear(keyOut.eaKeys[i].x_m);
        element_clear(keyOut.eaKeys[i].y_m);
        element_clear(keyOut.eaKeys[i].sgk1);
        element_clear(keyOut.eaKeys[i].sgk2);
        element_clear(keyOut.eaKeys[i].vki1);
        element_clear(keyOut.eaKeys[i].vki2);
        element_clear(keyOut.eaKeys[i].vki3);
    }

    // Setup param
    clearParams(params);

    std::cout << "[INFO] Program bitti.\n";
    return 0;
}
