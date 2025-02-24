#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include "setup.h"
#include "keygen.h"
#include "didgen.h"
#include "prepareblindsign.h"
#include "blindsign.h"  // <-- yeni eklenen header (Alg.12)

// Not: "blindsign.h" içinde şu fonksiyonlar tanımlı olmalı:
//  - bool CheckKoR(...)
//  - BlindSignature blindSign(...)
//  - struct BlindSignature { element_t h; element_t cm; }

int main() {
    using Clock = std::chrono::steady_clock;

    // 1) params.txt içinden ne (EA sayısı), t (eşik) ve voterCount
    int ne = 0, t = 0, voterCount = 0;
    {
        std::ifstream infile("params.txt");
        if(!infile) {
            std::cerr << "Error: params.txt acilamadi!\n";
            return 1;
        }
        std::string line;
        while(std::getline(infile, line)){
            if(line.rfind("ea=",0) == 0) {
                ne = std::stoi(line.substr(3));
            } 
            else if(line.rfind("threshold=",0) == 0) {
                t = std::stoi(line.substr(10));
            }
            else if(line.rfind("votercount=",0) == 0) {
                voterCount = std::stoi(line.substr(11));
            }
        }
        infile.close();
    }

    std::cout << "EA sayisi (ne) = " << ne << "\n";
    std::cout << "Esik degeri (t) = " << t << "\n";
    std::cout << "Secmen sayisi (voterCount) = " << voterCount << "\n\n";

    // 2) Setup (Algoritma 1)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // Debug parametre bas
    {
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "p (Grup mertebesi) =\n" << p_str << "\n\n";
        free(p_str);
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g1);
        std::cout << "g1 =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.h1);
        std::cout << "h1 =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", params.g2);
        std::cout << "g2 =\n" << buffer << "\n\n";
    }

    // 3) Pairing testi
    element_t pairingTest;
    element_init_GT(pairingTest, params.pairing);

    auto startPairing = Clock::now();
    pairing_apply(pairingTest, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairing_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();

    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", pairingTest);
        std::cout << "[ZAMAN] e(g1, g2) hesabi: "
                  << pairing_us << " microseconds\n";
        std::cout << "e(g1, g2) =\n" << buffer << "\n\n";
    }
    element_clear(pairingTest);

    // 4) KeyGen (Algoritma 2)
    std::cout << "=== TTP ile Anahtar Uretimi (KeyGen) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();

    // MasterVerKey bas
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

    // EA anahtarlarini bas
    for(int i=0; i<ne; i++){
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
        std::cout << "\n";
    }

    // 5) ID Generation: 11 hanelik random ID
    auto startIDGen = Clock::now();
    std::vector<std::string> voterIDs(voterCount);
    {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<unsigned long long> dist(10000000000ULL, 99999999999ULL);

        for(int i = 0; i < voterCount; i++) {
            unsigned long long randNum = dist(gen);
            voterIDs[i] = std::to_string(randNum);
        }
    }
    auto endIDGen = Clock::now();
    auto idGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endIDGen - startIDGen).count();

    std::cout << "=== ID Generation ===\n";
    for(int i = 0; i < voterCount; i++){
        std::cout << "Secmen " << (i+1) << " ID = " << voterIDs[i] << "\n";
    }
    std::cout << "\n";

    // 6) DID Generation
    auto startDIDGen = Clock::now();
    std::vector<DID> dids(voterCount);
    for(int i = 0; i < voterCount; i++){
        dids[i] = createDID(params, voterIDs[i]);
    }
    auto endDIDGen = Clock::now();
    auto didGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endDIDGen - startDIDGen).count();

    std::cout << "=== DID Generation ===\n";
    for(int i = 0; i < voterCount; i++){
        char* x_str = mpz_get_str(nullptr, 10, dids[i].x);
        std::cout << "Secmen " << (i+1) 
                  << " icin x = " << x_str << "\n"
                  << "Secmen " << (i+1)
                  << " icin DID = " << dids[i].did << "\n\n";
        free(x_str);
    }

    // 7) Prepare Blind Sign (Algoritma 4)
    auto startBS = Clock::now();
    std::vector<PrepareBlindSignOutput> bsOutputs(voterCount);
    for(int i = 0; i < voterCount; i++) {
        bsOutputs[i] = prepareBlindSign(params, dids[i].did);

        // Ekrana yazma
        {
            char bufComi[2048], bufH[1024], bufCom[2048];
            element_snprintf(bufComi, sizeof(bufComi), "%B", bsOutputs[i].comi);
            element_snprintf(bufH,    sizeof(bufH),    "%B", bsOutputs[i].h);
            element_snprintf(bufCom,  sizeof(bufCom),  "%B", bsOutputs[i].com);
            std::cout << "Secmen " << (i+1) << ":\n"
                      << "comi = " << bufComi << "\n"
                      << "h    = " << bufH    << "\n"
                      << "com  = " << bufCom  << "\n";

            // pi_s
            char bufC[1024], bufS1[1024], bufS2[1024], bufS3[1024];
            element_snprintf(bufC,  sizeof(bufC),  "%B", bsOutputs[i].pi_s.c);
            element_snprintf(bufS1, sizeof(bufS1), "%B", bsOutputs[i].pi_s.s1);
            element_snprintf(bufS2, sizeof(bufS2), "%B", bsOutputs[i].pi_s.s2);
            element_snprintf(bufS3, sizeof(bufS3), "%B", bsOutputs[i].pi_s.s3);

            std::cout << "pi_s.c  = " << bufC  << "\n"
                      << "pi_s.s1 = " << bufS1 << "\n"
                      << "pi_s.s2 = " << bufS2 << "\n"
                      << "pi_s.s3 = " << bufS3 << "\n\n";
        }
    }
    auto endBS = Clock::now();
    auto bs_us = std::chrono::duration_cast<std::chrono::microseconds>(endBS - startBS).count();
    
    // 8) Kör İmzalama (Algoritma 12) - Her EA, her seçmen için partial signature
    std::cout << "=== Kör Imzalama (BlindSign) (Algoritma 12) ===\n";
    auto startFinalSign = Clock::now();

    for(int i = 0; i < voterCount; i++) {
        std::cout << "Secmen " << (i+1) << " icin EA otoritelerinin imzalari:\n";

        for(int m = 0; m < ne; m++) {
            // EA otoritesinin (x_m, y_m) = (sgk1, sgk2)
            mpz_t xm, ym;
            mpz_init(xm);
            mpz_init(ym);

            element_to_mpz(xm, keyOut.eaKeys[m].sgk1); // x_m
            element_to_mpz(ym, keyOut.eaKeys[m].sgk2); // y_m

            try {
                BlindSignature partialSig = blindSign(
                    params, 
                    bsOutputs[i], 
                    xm,  // x_m
                    ym   // y_m
                );
                
                // partialSig => (h, cm)
                char bufH[2048], bufCM[2048];
                element_snprintf(bufH,  sizeof(bufH),  "%B", partialSig.h);
                element_snprintf(bufCM, sizeof(bufCM), "%B", partialSig.cm);

                std::cout << "  [EA " << (m+1) << "] => h=" << bufH << "\n"
                          << "              cm=" << bufCM << "\n\n";

                // Temizlik
                element_clear(partialSig.h);
                element_clear(partialSig.cm);

            } catch(const std::exception &ex) {
                std::cerr << "  [EA " << (m+1) 
                          << "] blindSign error: " << ex.what() << "\n";
            }

            mpz_clear(xm);
            mpz_clear(ym);
        }
    }
    auto endFinalSign = Clock::now();
    auto finalSign_us = std::chrono::duration_cast<std::chrono::microseconds>(endFinalSign - startFinalSign).count();

    // 9) Bellek temizliği
    element_clear(keyOut.mvk.alpha2);
    element_clear(keyOut.mvk.beta2);
    element_clear(keyOut.mvk.beta1);
    for(int i=0; i<ne; i++){
        element_clear(keyOut.eaKeys[i].sgk1);
        element_clear(keyOut.eaKeys[i].sgk2);
        element_clear(keyOut.eaKeys[i].vkm1);
        element_clear(keyOut.eaKeys[i].vkm2);
        element_clear(keyOut.eaKeys[i].vkm3);
    }

    for(int i=0; i<voterCount; i++){
        mpz_clear(dids[i].x);
    }

    for(int i=0; i<voterCount; i++){
        element_clear(bsOutputs[i].comi);
        element_clear(bsOutputs[i].h);
        element_clear(bsOutputs[i].com);
        element_clear(bsOutputs[i].pi_s.c);
        element_clear(bsOutputs[i].pi_s.s1);
        element_clear(bsOutputs[i].pi_s.s2);
        element_clear(bsOutputs[i].pi_s.s3);
    }

    clearParams(params);

    // 10) Zaman ölçümleri (ms)
    double setup_ms     = setup_us    / 1000.0;
    double pairing_ms   = pairing_us  / 1000.0;
    double keygen_ms    = keygen_us   / 1000.0;
    double idGen_ms     = idGen_us    / 1000.0;
    double didGen_ms    = didGen_us   / 1000.0;
    double bs_ms        = bs_us       / 1000.0;
    double finalSign_ms = finalSign_us / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi       : " << setup_ms     << " ms\n";
    std::cout << "Pairing suresi     : " << pairing_ms   << " ms\n";
    std::cout << "KeyGen suresi      : " << keygen_ms    << " ms\n";
    std::cout << "ID Generation      : " << idGen_ms     << " ms\n";
    std::cout << "DID Generation     : " << didGen_ms    << " ms\n";
    std::cout << "Prepare Blind Sign : " << bs_ms        << " ms\n";
    std::cout << "Final Blind Sign   : " << finalSign_ms << " ms\n";

    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
