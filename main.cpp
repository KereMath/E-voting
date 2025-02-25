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
#include "blindsign.h"   // Alg.12
#include "unblindsign.h" // Alg.13
#include <thread>
#include <future>
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <mutex>

// Yardımcı fonksiyon: element kopyalamak için (const kullanılmıyor)
void my_element_dup(element_t dest, element_t src) {
    element_init_same_as(dest, src);
    element_set(dest, src);
}

// Global logger: thread kullanımını kaydetmek için
std::mutex logMutex;
std::ofstream threadLog("threads.txt");

void logThreadUsage(const std::string &phase, const std::string &msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    threadLog << "[" << ms << " ms] " << phase << ": " << msg << "\n";
}

int main() {
    using Clock = std::chrono::steady_clock;
    
    // 1) params.txt'den EA sayısı, eşik ve seçmen sayısı okunuyor.
    int ne = 0, t = 0, voterCount = 0;
    {
        std::ifstream infile("params.txt");
        if (!infile) {
            std::cerr << "Error: params.txt acilamadi!\n";
            return 1;
        }
        std::string line;
        while (std::getline(infile, line)) {
            if (line.rfind("ea=", 0) == 0)
                ne = std::stoi(line.substr(3));
            else if (line.rfind("threshold=", 0) == 0)
                t = std::stoi(line.substr(10));
            else if (line.rfind("votercount=", 0) == 0)
                voterCount = std::stoi(line.substr(11));
        }
        infile.close();
    }
    // Simülasyon için: admin sayısı 3 ve threshold 2 olacak şekilde düzenleniyor.
    ne = 3;
    t = 2;
    
    std::cout << "EA sayisi (admin) = " << ne << "\n";
    std::cout << "Esik degeri (threshold) = " << t << "\n";
    std::cout << "Secmen sayisi (voterCount) = " << voterCount << "\n\n";
    
    // 2) Setup (Alg.1)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();
    {
        char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
        std::cout << "p (Grup mertebesi) =\n" << p_str << "\n\n";
        free(p_str);
    }
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", params.g1);
        std::cout << "g1 =\n" << buf << "\n\n";
    }
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", params.h1);
        std::cout << "h1 =\n" << buf << "\n\n";
    }
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", params.g2);
        std::cout << "g2 =\n" << buf << "\n\n";
    }
    
    // 3) Pairing testi
    element_t pairingTest;
    element_init_GT(pairingTest, params.pairing);
    auto startPairing = Clock::now();
    pairing_apply(pairingTest, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairing_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", pairingTest);
        std::cout << "[ZAMAN] e(g1, g2) hesabi: " << pairing_us << " microseconds\n";
        std::cout << "e(g1, g2) =\n" << buf << "\n\n";
    }
    element_clear(pairingTest);
    
    // 4) KeyGen (Alg.2)
    std::cout << "=== TTP ile Anahtar Uretimi (KeyGen) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    
    std::cout << "Key generation time: " << keygen_us << " microseconds\n\n";
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", keyOut.mvk.alpha2);
        std::cout << "mvk.alpha2 = g2^x =\n" << buf << "\n\n";
    }
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", keyOut.mvk.beta2);
        std::cout << "mvk.beta2 = g2^y =\n" << buf << "\n\n";
    }
    {
        char buf[1024];
        element_snprintf(buf, sizeof(buf), "%B", keyOut.mvk.beta1);
        std::cout << "mvk.beta1 = g1^y =\n" << buf << "\n\n";
    }
    
    // EA Authority'lerin detaylı yazdırılması
    for (int i = 0; i < ne; i++) {
        std::cout << "=== EA Authority " << (i + 1) << " ===\n";
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].sgk1);
            std::cout << "sgk1 (x_m degeri) = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].sgk2);
            std::cout << "sgk2 (y_m degeri) = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm1);
            std::cout << "vkm1 = g2^(x_m) = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm2);
            std::cout << "vkm2 = g2^(y_m) = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm3);
            std::cout << "vkm3 = g1^(y_m) = " << buf << "\n";
        }
        std::cout << "\n";
    }
    
    // 5) ID Generation
    auto startIDGen = Clock::now();
    std::vector<std::string> voterIDs(voterCount);
    {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<unsigned long long> dist(10000000000ULL, 99999999999ULL);
        for (int i = 0; i < voterCount; i++) {
            unsigned long long id = dist(gen);
            voterIDs[i] = std::to_string(id);
        }
    }
    auto endIDGen = Clock::now();
    auto idGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endIDGen - startIDGen).count();
    std::cout << "=== ID Generation ===\n";
    for (int i = 0; i < voterCount; i++) {
        std::cout << "Secmen " << (i+1) << " ID = " << voterIDs[i] << "\n";
    }
    std::cout << "\n";
    
    // 6) DID Generation
    auto startDIDGen = Clock::now();
    std::vector<DID> dids(voterCount);
    for (int i = 0; i < voterCount; i++) {
        dids[i] = createDID(params, voterIDs[i]);
    }
    auto endDIDGen = Clock::now();
    auto didGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endDIDGen - startDIDGen).count();
    std::cout << "=== DID Generation ===\n";
    for (int i = 0; i < voterCount; i++) {
        char* x_str = mpz_get_str(nullptr, 10, dids[i].x);
        std::cout << "Secmen " << (i+1) << " icin x = " << x_str << "\n"
                  << "Secmen " << (i+1) << " icin DID = " << dids[i].did << "\n\n";
        free(x_str);
    }
    
    // 7) Prepare Blind Sign (Alg.4)
    // PrepareBlindSign sunucusu: sabit 6 thread kullanılarak istekler paralel işleniyor.
    auto startBS = Clock::now();
    std::vector<PrepareBlindSignOutput> bsOutputs(voterCount);
    {
        // TBB global kontrolü ile 6 thread kullanılıyor.
        tbb::global_control gcPrep(tbb::global_control::max_allowed_parallelism, 6);
        tbb::parallel_for(tbb::blocked_range<int>(0, voterCount),
            [&](const tbb::blocked_range<int>& range) {
                for (int i = range.begin(); i < range.end(); i++) {
                    logThreadUsage("PrepareBlindSign", "Task for voter " + std::to_string(i+1) +
                                     " started on thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id())));
                    bsOutputs[i] = prepareBlindSign(params, dids[i].did);
                    logThreadUsage("PrepareBlindSign", "Task for voter " + std::to_string(i+1) +
                                     " finished on thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id())));
                }
            }
        );
    }
    auto endBS = Clock::now();
    auto bs_us = std::chrono::duration_cast<std::chrono::microseconds>(endBS - startBS).count();
    std::cout << "=== Prepare Blind Sign ===\n";
    for (int i = 0; i < voterCount; i++) {
        char bufComi[2048], bufH[1024], bufCom[2048];
        element_snprintf(bufComi, sizeof(bufComi), "%B", bsOutputs[i].comi);
        element_snprintf(bufH, sizeof(bufH), "%B", bsOutputs[i].h);
        element_snprintf(bufCom, sizeof(bufCom), "%B", bsOutputs[i].com);
        std::cout << "Secmen " << (i+1) << " Prepare Blind Sign:\n"
                  << "  comi = " << bufComi << "\n"
                  << "  h    = " << bufH    << "\n"
                  << "  com  = " << bufCom  << "\n";
        char* o_str = mpz_get_str(nullptr, 10, bsOutputs[i].o);
        std::cout << "  o    = " << o_str << "\n\n";
        free(o_str);
    }
    
    // 8) BlindSign (Alg.12): Admin imzalama işlemi
    // Her seçmen için, tüm 3 admin görevi eşzamanlı başlatılır.
    // Final sonuç, ilk 2 tamamlanan (threshold=2) admin imza sonucu ile elde edilir.
    std::cout << "=== BlindSign (Admin Imzalama) (Algoritma 12) ===\n";
    auto startFinalSign = Clock::now();
    std::vector< std::vector<BlindSignature> > finalSigs(voterCount);
    const int adminCount = 3; // Tüm admin görevleri başlatılıyor.
    for (int i = 0; i < voterCount; i++) {
        std::cout << "Secmen " << (i+1) << " icin admin imzalama islemi basladi.\n";
        std::vector<std::future<BlindSignature>> adminFutures;
        // Tüm admin görevleri başlatılıyor
        for (int admin = 0; admin < adminCount; admin++) {
            adminFutures.push_back(std::async(std::launch::async, [&, i, admin]() -> BlindSignature {
                logThreadUsage("BlindSign", "Voter " + std::to_string(i+1) + " - Admin " + std::to_string(admin+1) +
                                 " sign task started on thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id())));
                mpz_t xm, ym;
                mpz_init(xm);
                mpz_init(ym);
                element_to_mpz(xm, keyOut.eaKeys[admin].sgk1);
                element_to_mpz(ym, keyOut.eaKeys[admin].sgk2);
                BlindSignature sig = blindSign(params, bsOutputs[i], xm, ym);
                mpz_clear(xm);
                mpz_clear(ym);
                logThreadUsage("BlindSign", "Voter " + std::to_string(i+1) + " - Admin " + std::to_string(admin+1) +
                                 " sign task finished on thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id())));
                return sig;
            }));
        }
        // Bekleme: Threshold onayı (t=2) elde edilene kadar döngü.
        std::vector<BlindSignature> collected;
        while (collected.size() < static_cast<size_t>(t)) {
            for (int admin = 0; admin < adminCount; admin++) {
                // Eğer bu admin görevi henüz toplanmadıysa kontrol et
                if (adminFutures[admin].valid()) {
                    if (adminFutures[admin].wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                        try {
                            BlindSignature sig = adminFutures[admin].get();
                            collected.push_back(sig);
                        } catch (const std::exception &ex) {
                            std::cerr << "Secmen " << (i+1) << ", Admin " << (admin+1)
                                      << " sign error: " << ex.what() << "\n";
                        }
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        finalSigs[i] = collected;
        std::cout << "Secmen " << (i+1) << " icin " << collected.size() << " admin onayi alindi.\n\n";
        // Geri kalan admin görevleri bitmişse, sonuçları almak (temizlik) için çağırılır.
        for (int admin = 0; admin < adminCount; admin++) {
            if (adminFutures[admin].valid()) {
                try {
                    // Sonuçlar zaten alındıysa get çağrısı hata vermez, ama değeri kullanılmayacak.
                    adminFutures[admin].get();
                } catch (...) {}
            }
        }
    }
    auto endFinalSign = Clock::now();
    auto finalSign_us = std::chrono::duration_cast<std::chrono::microseconds>(endFinalSign - startFinalSign).count();
    
    // 9) Bellek temizliği
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
    for (int i = 0; i < voterCount; i++) {
        mpz_clear(dids[i].x);
    }
    for (int i = 0; i < voterCount; i++) {
        element_clear(bsOutputs[i].comi);
        element_clear(bsOutputs[i].h);
        element_clear(bsOutputs[i].com);
        element_clear(bsOutputs[i].pi_s.c);
        element_clear(bsOutputs[i].pi_s.s1);
        element_clear(bsOutputs[i].pi_s.s2);
        element_clear(bsOutputs[i].pi_s.s3);
        mpz_clear(bsOutputs[i].o);
    }
    clearParams(params);
    
    // 10) Zaman ölçümleri (ms)
    double setup_ms     = setup_us     / 1000.0;
    double pairing_ms   = pairing_us   / 1000.0;
    double keygen_ms    = keygen_us    / 1000.0;
    double idGen_ms     = idGen_us     / 1000.0;
    double didGen_ms    = didGen_us    / 1000.0;
    double bs_ms        = bs_us        / 1000.0;
    double finalSign_ms = finalSign_us / 1000.0;
    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi       : " << setup_ms     << " ms\n";
    std::cout << "Pairing suresi     : " << pairing_ms   << " ms\n";
    std::cout << "KeyGen suresi      : " << keygen_ms    << " ms\n";
    std::cout << "ID Generation      : " << idGen_ms     << " ms\n";
    std::cout << "DID Generation     : " << didGen_ms    << " ms\n";
    std::cout << "Prepare Blind Sign : " << bs_ms        << " ms\n";
    std::cout << "Blind Sign         : " << finalSign_ms << " ms\n";
    
    threadLog.close();
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
