#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
#include "setup.h"
#include "keygen.h"

int main(){
    using Clock = std::chrono::steady_clock;

    // 1) params.txt dosyasından ne, t, voterCount değerlerini oku
    int ne=3, t=2, voterCount=1;
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
    std::cout << "[INFO] Eşik (t)   = " << t << "\n";
    std::cout << "[INFO] Secmen sayisi = " << voterCount << "\n\n";

    // 2) Setup
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // Debug
    {
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "p = " << p_str << "\n";
        free(p_str);

        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", params.g1);
        std::cout << "g1 = " << buf << "\n";
        element_snprintf(buf, sizeof(buf), "%B", params.h1);
        std::cout << "h1 = " << buf << "\n";
        element_snprintf(buf, sizeof(buf), "%B", params.g2);
        std::cout << "g2 = " << buf << "\n\n";
    }

    // Pairing test
    element_t testGT;
    element_init_GT(testGT, params.pairing);
    auto startPair = Clock::now();
    pairing_apply(testGT, params.g1, params.g2, params.pairing);
    auto endPair = Clock::now();
    auto pair_us = std::chrono::duration_cast<std::chrono::microseconds>(endPair - startPair).count();
    {
        char buf[2048];
        element_snprintf(buf, sizeof(buf), "%B", testGT);
        std::cout << "e(g1, g2) = " << buf << "\n\n";
    }
    element_clear(testGT);

    // 3) Key Generation (Pedersen’s DKG)
    auto startKG = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKG = Clock::now();
    auto kg_us = std::chrono::duration_cast<std::chrono::microseconds>(endKG - startKG).count();

    // 3.1) Master verification key
    {
        char b1[1024], b2[1024], b3[1024];
        element_snprintf(b1, 1024, "%B", keyOut.mvk.vk1);
        element_snprintf(b2, 1024, "%B", keyOut.mvk.vk2);
        element_snprintf(b3, 1024, "%B", keyOut.mvk.vk3);
        std::cout << "mvk.vk1 = ∏(Vx_{i,0}) = " << b1 << "\n";
        std::cout << "mvk.vk2 = ∏(Vy_{i,0}) = " << b2 << "\n";
        std::cout << "mvk.vk3 = ∏(Vy'_{i,0})= " << b3 << "\n\n";
    }

    // 3.2) Master signing key
    {
        char b1[1024], b2[1024];
        element_snprintf(b1, 1024, "%B", keyOut.msgk.sk1);
        element_snprintf(b2, 1024, "%B", keyOut.msgk.sk2);
        std::cout << "msgk.sk1 (sum x_i0) = " << b1 << "\n";
        std::cout << "msgk.sk2 (sum y_i0) = " << b2 << "\n\n";
    }

    // 3.3) EA'lerin sonuçları
    for(int i=0; i<ne; i++){
        std::cout << "=== EA " << (i+1) << " ===\n";

        // x0, y0
        {
            char bx[512], by[512];
            element_snprintf(bx, 512, "%B", keyOut.eaKeys[i].x0);
            element_snprintf(by, 512, "%B", keyOut.eaKeys[i].y0);
            std::cout << " x0 = " << bx << "\n";
            std::cout << " y0 = " << by << "\n";
        }

        // Commitments [0..t]
        for(int j=0; j<=t; j++){
            char vxbuf[512], vybuf[512], vypbuf[512];
            element_snprintf(vxbuf, 512, "%B", keyOut.eaKeys[i].Vx[j]);
            element_snprintf(vybuf, 512, "%B", keyOut.eaKeys[i].Vy[j]);
            element_snprintf(vypbuf, 512, "%B", keyOut.eaKeys[i].Vyprime[j]);
            std::cout << "  j=" << j << " => Vx=" << vxbuf 
                      << ", Vy=" << vybuf 
                      << ", Vy'=" << vypbuf << "\n";
        }

        // sgk, vki
        {
            char s1[512], s2[512], v1[512], v2[512], v3[512];
            element_snprintf(s1, 512, "%B", keyOut.eaKeys[i].sgk1);
            element_snprintf(s2, 512, "%B", keyOut.eaKeys[i].sgk2);
            element_snprintf(v1, 512, "%B", keyOut.eaKeys[i].vki1);
            element_snprintf(v2, 512, "%B", keyOut.eaKeys[i].vki2);
            element_snprintf(v3, 512, "%B", keyOut.eaKeys[i].vki3);

            std::cout << " sgk1 = " << s1 << "\n";
            std::cout << " sgk2 = " << s2 << "\n";
            std::cout << " vki1 = " << v1 << "\n";
            std::cout << " vki2 = " << v2 << "\n";
            std::cout << " vki3 = " << v3 << "\n";
        }

        std::cout << "\n";
    }

    // 4) Süre ölçümleri (ms)
    double setup_ms = setup_us / 1000.0;
    double pair_ms  = pair_us  / 1000.0;
    double kg_ms    = kg_us    / 1000.0;
    std::cout << "=== ZAMAN ===\n";
    std::cout << "Setup  : " << setup_ms << " ms\n";
    std::cout << "Pairing: " << pair_ms  << " ms\n";
    std::cout << "KeyGen : " << kg_ms    << " ms\n\n";

    // 5) Bellek temizliği
    // Master VK
    element_clear(keyOut.mvk.vk1);
    element_clear(keyOut.mvk.vk2);
    element_clear(keyOut.mvk.vk3);
    // Master SK
    element_clear(keyOut.msgk.sk1);
    element_clear(keyOut.msgk.sk2);

    // EA payları
    for(int i=0; i<ne; i++){
        element_clear(keyOut.eaKeys[i].x0);
        element_clear(keyOut.eaKeys[i].y0);

        // Commitments
        for(int j=0; j<=t; j++){
            element_clear(keyOut.eaKeys[i].Vx[j]);
            element_clear(keyOut.eaKeys[i].Vy[j]);
            element_clear(keyOut.eaKeys[i].Vyprime[j]);
        }

        element_clear(keyOut.eaKeys[i].sgk1);
        element_clear(keyOut.eaKeys[i].sgk2);
        element_clear(keyOut.eaKeys[i].vki1);
        element_clear(keyOut.eaKeys[i].vki2);
        element_clear(keyOut.eaKeys[i].vki3);
    }

    // Setup parametreleri temizle
    clearParams(params);

    std::cout << "[INFO] Program bitti.\n";
    return 0;
}
