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
#include "blindsign.h"   // BlindSign (Alg.12)
#include "unblindsign.h" // UnblindSignature (Alg.13)

int main() {
    using Clock = std::chrono::steady_clock;

    // 1) params.txt'den ne, t, voterCount
    int ne = 0, t = 0, voterCount = 0;
    {
        std::ifstream infile("params.txt");
        if(!infile) {
            std::cerr << "Error: params.txt acilamadi!\n";
            return 1;
        }
        std::string line;
        while(std::getline(infile, line)) {
            if(line.rfind("ea=", 0) == 0)
                ne = std::stoi(line.substr(3));
            else if(line.rfind("threshold=", 0) == 0)
                t = std::stoi(line.substr(10));
            else if(line.rfind("votercount=", 0) == 0)
                voterCount = std::stoi(line.substr(11));
        }
        infile.close();
    }
    std::cout << "EA sayisi (ne) = " << ne << "\n";
    std::cout << "Esik degeri (t) = " << t << "\n";
    std::cout << "Secmen sayisi (voterCount) = " << voterCount << "\n\n";

    // 2) Setup (Alg.1)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // Parametreleri yazdır
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
        std::cout << "[ZAMAN] e(g1, g2) hesabi: " << pairing_us << " microseconds\n";
        std::cout << "e(g1, g2) =\n" << buffer << "\n\n";
    }
    element_clear(pairingTest);

    // 4) KeyGen (Alg.2)
    std::cout << "=== TTP ile Anahtar Uretimi (KeyGen) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    // Yazdırma...
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
    for(int i = 0; i < ne; i++){
        std::cout << "=== EA Authority " << (i+1) << " ===\n";
        // Yazdırma...
    }

    // 5) ID Generation
    auto startIDGen = Clock::now();
    std::vector<std::string> voterIDs(voterCount);
    {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<unsigned long long> dist(10000000000ULL, 99999999999ULL);
        for(int i = 0; i < voterCount; i++){
            unsigned long long r = dist(gen);
            voterIDs[i] = std::to_string(r);
        }
    }
    auto endIDGen = Clock::now();
    auto idGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endIDGen - startIDGen).count();
    // Yazdırma...

    // 6) DID Generation
    auto startDIDGen = Clock::now();
    std::vector<DID> dids(voterCount);
    for(int i = 0; i < voterCount; i++){
        dids[i] = createDID(params, voterIDs[i]);
    }
    auto endDIDGen = Clock::now();
    auto didGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endDIDGen - startDIDGen).count();
    // Yazdırma...

    // 7) Prepare Blind Sign (Alg.4)
    auto startBS = Clock::now();
    std::vector<PrepareBlindSignOutput> bsOutputs(voterCount);
    for(int i = 0; i < voterCount; i++){
        bsOutputs[i] = prepareBlindSign(params, dids[i].did);
        // Yazdırma...
    }
    auto endBS = Clock::now();
    auto bs_us = std::chrono::duration_cast<std::chrono::microseconds>(endBS - startBS).count();

    // 8) Kör İmzalama (Alg.12): Her EA için partial imza üretimi
    std::cout << "=== Kör İmzalama (BlindSign) (Algoritma 12) ===\n";
    auto startFinalSign = Clock::now();
    // Burada her seçmen için, her EA’dan partial imza alınıyor.
    // Saklamak için: partialSigs[i][m]
    std::vector< std::vector<BlindSignature> > partialSigs(voterCount, std::vector<BlindSignature>(ne));
    for(int i = 0; i < voterCount; i++){
        std::cout << "Secmen " << (i+1) << " için EA partial imzaları:\n";
        for(int m = 0; m < ne; m++){
            mpz_t xm, ym;
            mpz_init(xm);
            mpz_init(ym);
            element_to_mpz(xm, keyOut.eaKeys[m].sgk1);
            element_to_mpz(ym, keyOut.eaKeys[m].sgk2);
            try {
                BlindSignature partSig = blindSign(params, bsOutputs[i], xm, ym);
                // Sakla:
                partialSigs[i][m].h = element_dup(partSig.h);
                partialSigs[i][m].cm = element_dup(partSig.cm);
                // Yazdırma:
                char bufH[2048], bufCM[2048];
                element_snprintf(bufH, sizeof(bufH), "%B", partSig.h);
                element_snprintf(bufCM, sizeof(bufCM), "%B", partSig.cm);
                std::cout << "  [EA " << (m+1) << "] => h=" << bufH << "\n"
                          << "              cm=" << bufCM << "\n\n";
                element_clear(partSig.h);
                element_clear(partSig.cm);
            } catch(const std::exception &ex) {
                std::cerr << "  [EA " << (m+1) << "] blindSign error: " << ex.what() << "\n";
            }
            mpz_clear(xm);
            mpz_clear(ym);
        }
    }
    auto endFinalSign = Clock::now();
    auto finalSign_us = std::chrono::duration_cast<std::chrono::microseconds>(endFinalSign - startFinalSign).count();

    // 9) Unblind Signature (Algoritma 13):
    // Şimdi her EA partial imzası, prepare blind sign'dan gelen "o" ve EA vkm değerleriyle unblind edilecek.
    std::cout << "=== Unblind Signature (Algoritma 13) ===\n";
    auto startUnblind = Clock::now();
    // Unblind sonuçlarını saklamak için:
    std::vector< std::vector<UnblindSignature> > unblindedSigs(voterCount, std::vector<UnblindSignature>(ne));
    for(int i = 0; i < voterCount; i++){
        std::cout << "Secmen " << (i+1) << " için EA unblind imzaları:\n";
        for(int m = 0; m < ne; m++){
            // Hazırlanan input:
            UnblindSignInput in;
            // Initialize required fields:
            element_init_G1(in.comi, params.pairing);
            element_set(in.comi, bsOutputs[i].comi); // prepareBlindSign'dan
            // partial signature'dan alınan h:
            element_init_G1(in.h, params.pairing);
            element_set(in.h, partialSigs[i][m].h);
            // partial signature'dan alınan cm:
            element_init_G1(in.cm, params.pairing);
            element_set(in.cm, partialSigs[i][m].cm);
            // "o" de prepareBlindSign çıktı içerisinde saklanmalı. 
            // Bu örnekte prepareBlindSign() fonksiyonunu güncellediğinizi ve "o" alanı eklediğinizi varsayıyoruz.
            mpz_init(in.o);
            mpz_set(in.o, bsOutputs[i].o);  // prepareBlindSign'da saklanan o
            // EA doğrulama anahtarları (vkm):  
            element_init_G2(in.alpha2, params.pairing);
            element_set(in.alpha2, keyOut.eaKeys[m].vkm1);  // DEMO: alpha2 = vkm1
            element_init_G2(in.beta2, params.pairing);
            element_set(in.beta2, keyOut.eaKeys[m].vkm2);     // beta2 = vkm2
            element_init_G1(in.beta1, params.pairing);
            element_set(in.beta1, keyOut.eaKeys[m].vkm3);     // beta1 = vkm3
            // DIDi: seçmenin DID (mod p); burada dids[i].x
            mpz_init(in.DIDi);
            mpz_set(in.DIDi, dids[i].x);
            
            try {
                UnblindSignature unb = unblindSignature(params, in);
                // Yazdırma:
                char hBuf[1024], smBuf[1024];
                element_snprintf(hBuf, sizeof(hBuf), "%B", unb.h);
                element_snprintf(smBuf, sizeof(smBuf), "%B", unb.sm);
                std::cout << "  [EA " << (m+1) << "] Unblinded Sig => h=" << hBuf
                          << "\n                  sm=" << smBuf << "\n";
                // Temizlik:
                element_clear(unb.h);
                element_clear(unb.sm);
            } catch(const std::exception &ex) {
                std::cerr << "  [EA " << (m+1) << "] unblindsign error: " << ex.what() << "\n";
            }
            
            // Temizlik for UnblindSignInput
            element_clear(in.comi);
            element_clear(in.h);
            element_clear(in.cm);
            mpz_clear(in.o);
            element_clear(in.alpha2);
            element_clear(in.beta2);
            element_clear(in.beta1);
            mpz_clear(in.DIDi);
        }
    }
    auto endUnblind = Clock::now();
    auto unblind_us = std::chrono::duration_cast<std::chrono::microseconds>(endUnblind - startUnblind).count();

    // 10) Bellek temizliği
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
        mpz_clear(bsOutputs[i].o); // prepareBlindSignOutput'daki o
    }
    clearParams(params);

    // 11) Zaman ölçümleri (ms)
    double setup_ms     = setup_us    / 1000.0;
    double pairing_ms   = pairing_us  / 1000.0;
    double keygen_ms    = keygen_us   / 1000.0;
    double idGen_ms     = idGen_us    / 1000.0;
    double didGen_ms    = didGen_us   / 1000.0;
    double bs_ms        = bs_us       / 1000.0;
    double finalSign_ms = finalSign_us/ 1000.0;
    double unblind_ms   = unblind_us  / 1000.0;
    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi       : " << setup_ms     << " ms\n";
    std::cout << "Pairing suresi     : " << pairing_ms   << " ms\n";
    std::cout << "KeyGen suresi      : " << keygen_ms    << " ms\n";
    std::cout << "ID Generation      : " << idGen_ms     << " ms\n";
    std::cout << "DID Generation     : " << didGen_ms    << " ms\n";
    std::cout << "Prepare Blind Sign : " << bs_ms        << " ms\n";
    std::cout << "Final Blind Sign   : " << finalSign_ms << " ms\n";
    std::cout << "Unblind Signature  : " << unblind_ms   << " ms\n\n";

    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
