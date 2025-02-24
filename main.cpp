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
    element_clear(gtResult);}