#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>    // std::shuffle
#include "setup.h"
#include "keygen.h"
#include "didgen.h"
#include "prepareblindsign.h"
#include "blindsign.h"   // Alg.50
#include "unblindsign.h" // Alg.13
#include <thread>
#include <future>
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <mutex>
#include <limits>
#include <semaphore>    // C++20 semaphores
#include <memory>       // std::unique_ptr

using Clock = std::chrono::steady_clock;

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
    auto now = Clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    threadLog << "[" << ms << " ms] " << phase << ": " << msg << "\n";
}

// Pipeline zaman ölçümü için yapı
struct PipelineTiming {
    Clock::time_point prep_start;
    Clock::time_point prep_end;
    Clock::time_point blind_start;
    Clock::time_point blind_end;
};

// Pipeline sonucu: BlindSign imzaları ve zaman ölçümleri
struct PipelineResult {
    std::vector<BlindSignature> signatures;
    PipelineTiming timing;
};

int main() {
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
        std::cout << "[ZAMAN] e(g1, g2) hesabi: " << pairing_us << " µs\n";
        std::cout << "e(g1, g2) =\n" << buf << "\n\n";
    }
    element_clear(pairingTest);

    // 4) KeyGen (Alg.2)
    std::cout << "=== TTP ile Anahtar Uretimi (KeyGen) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();

    std::cout << "Key generation time: " << keygen_us/1000.0 << " ms\n\n";
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

    // 7) Pipeline: PrepareBlindSign ve BlindSign (Admin Imzalama)
    // PrepareBlindSign aşaması TBB ile aynı anda maksimum 6 thread çalışacak şekilde paralel yürütülecek.
    // BlindSign aşamasında ise her admin için 2 paralel görev çalışabilsin diye std::counting_semaphore kullanıyoruz.

    // Her admin için 2 izne (token) sahip semaphor oluşturuluyor.
    const int adminCount = ne;
    std::vector<std::unique_ptr<std::counting_semaphore<>>> adminSemaphores;
    for (int i = 0; i < adminCount; i++) {
        // Her admin aynı anda 2 imzaya kadar çalışabiliyor (50 diyorsan çok daha fazla da olabilir)
        adminSemaphores.push_back(std::make_unique<std::counting_semaphore<>>(50));
    }

    // Pipeline sonuçlarını tutacak vector
    std::vector<PipelineResult> pipelineResults(voterCount);

    // TBB global kontrolü ile prepare aşamasında maksimum 6 thread kullanımı sağlanıyor.
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

    // Rastgele admin seçimi için her thread kendi local RNG'sini kullanacak
    tbb::parallel_for(0, voterCount, [&](int i) {
        // Hazırlık (Prepare)
        PipelineResult result;
        result.timing.prep_start = Clock::now();
        PrepareBlindSignOutput bsOut = prepareBlindSign(params, dids[i].did);
        result.timing.prep_end = Clock::now();

        logThreadUsage("Pipeline", "Voter " + std::to_string(i+1) + " prepareBlindSign finished.");

        // Şimdi BlindSign
        result.timing.blind_start = Clock::now();

        std::vector<BlindSignature> collected;
        collected.reserve(t);  // threshold kadar imza toplanacak

        // Eşik sayıda (t) imza toplanana kadar rastgele admin dene
        int scheduled = 0;

        // Her voter için ayrı RNG
        std::random_device rd;
        std::mt19937 rng(rd());

        // 0..(adminCount-1) aralığını tutan bir vector
        std::vector<int> adminIndices(adminCount);
        for (int k = 0; k < adminCount; k++) {
            adminIndices[k] = k;
        }

        while (scheduled < t) {
            // 1) adminIndices'i karıştır
            std::shuffle(adminIndices.begin(), adminIndices.end(), rng);

            bool usedAny = false;
            // 2) Karıştırılmış sırada admin'leri dene
            for (int admin : adminIndices) {
                // threshold dolduysa çık
                if (scheduled >= t) break;

                // Müsaitse imzala
                if (adminSemaphores[admin]->try_acquire()) {
                    usedAny = true;

                    logThreadUsage("BlindSign",
                        "Voter " + std::to_string(i+1) + 
                        " - Admin " + std::to_string(admin+1) +
                        " sign task started on thread " +
                        std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
                    );

                    mpz_t xm, ym;
                    mpz_init(xm);
                    mpz_init(ym);
                    element_to_mpz(xm, keyOut.eaKeys[admin].sgk1);
                    element_to_mpz(ym, keyOut.eaKeys[admin].sgk2);

                    // Kör imza fonksiyonu
                    BlindSignature sig = blindSign(params, bsOut, xm, ym);

                    mpz_clear(xm);
                    mpz_clear(ym);

                    logThreadUsage("BlindSign",
                        "Voter " + std::to_string(i+1) + 
                        " - Admin " + std::to_string(admin+1) +
                        " sign task finished on thread " +
                        std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
                    );

                    // Semaforu sal
                    adminSemaphores[admin]->release();

                    collected.push_back(sig);
                    scheduled++;
                }
            }
            // Bu turda hiç admin bulunamadıysa 1 ms bekle
            if (!usedAny && scheduled < t) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        result.timing.blind_end = Clock::now();
        result.signatures = collected;
        pipelineResults[i] = result;
    });

    // Pipeline sonuçlarının yazdırılması
    long long cumulativePrep_us = 0;
    long long cumulativeBlind_us = 0;
    for (int i = 0; i < voterCount; i++) {
        std::cout << "Secmen " << (i+1) << " icin "
                  << pipelineResults[i].signatures.size()
                  << " admin onayi alindi.\n";

        auto prep_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.prep_end - pipelineResults[i].timing.prep_start).count();
        auto blind_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.blind_end - pipelineResults[i].timing.blind_start).count();

        cumulativePrep_us += prep_time;
        cumulativeBlind_us += blind_time;

        std::cout << "Voter " << (i+1)
                  << ": Prepare time = " << prep_time/1000.0
                  << " ms, BlindSign time = " << blind_time/1000.0 << " ms\n";
    }

    // Toplam pipeline süresi
    auto endPipeline = Clock::now();
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(
        endPipeline - pipelineResults[0].timing.prep_start
    ).count();

    std::cout << "=== Pipeline (Prep+Blind) Toplam Süresi = "
              << pipeline_us/1000.0 << " ms ===\n";
    std::cout << "Cumulative Prepare time (sum of all tasks): "
              << cumulativePrep_us/1000.0 << " ms\n";
    std::cout << "Cumulative BlindSign time (sum of all tasks): "
              << cumulativeBlind_us/1000.0 << " ms\n";

    // 8) Bellek temizliği
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
    clearParams(params);

    // 9) Zaman ölçümleri (ms)
    double setup_ms    = setup_us    / 1000.0;
    double pairing_ms  = pairing_us  / 1000.0;
    double keygen_ms   = keygen_us   / 1000.0;
    double idGen_ms    = idGen_us    / 1000.0;
    double didGen_ms   = didGen_us   / 1000.0;
    double pipeline_ms = pipeline_us / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi       : " << setup_ms     << " ms\n";
    std::cout << "Pairing suresi     : " << pairing_ms   << " ms\n";
    std::cout << "KeyGen suresi      : " << keygen_ms    << " ms\n";
    std::cout << "ID Generation      : " << idGen_ms     << " ms\n";
    std::cout << "DID Generation     : " << didGen_ms    << " ms\n";
    std::cout << "Pipeline (Prep+Blind): " << pipeline_ms  << " ms\n";

    threadLog.close();
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
