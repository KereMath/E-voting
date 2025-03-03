#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>    // std::shuffle
#include <thread>
#include <future>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <semaphore>    // C++20 semaphores
#include <memory>       // std::unique_ptr>

#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#include <tbb/global_control.h>

#include "setup.h"
#include "keygen.h"
#include "didgen.h"
#include "prepareblindsign.h"
#include "blindsign.h"   // Alg.50
#include "unblindsign.h" // Alg.13

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

// --- SignRequest: Her bir imza talebi için kuyruk nesnesi ---
struct SignRequest {
    int voterId;                      // Hangi seçmenin isteği
    PrepareBlindSignOutput bsOut;     // Kör imza ön verisi
};

// Global paylaşılacak: pipelineResults
std::vector<PipelineResult> pipelineResults;

// Kuyruk ve senkronizasyon yapıları
std::queue<SignRequest> requestQueue;
std::mutex queueMutex;
std::condition_variable queueCV;
std::atomic<int> remainingJobs;  // Kaç tane imza işi kaldı (voterCount * t)

// keyOut, params gibi yapıları admin thread'lerde de kullanacağız
// Global olarak saklayalım (örnek basitlik için)
KeyGenOutput keyOut;
TIACParams params;

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
    params = setupParams();
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
    keyOut = keygen(params, t, ne);
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

    // 7) Pipeline hazırlığı
    pipelineResults.resize(voterCount);

    // 7a) PREPARE aşaması: TBB ile paralel
    {
        // TBB global kontrolü: maksimum 6 thread
        tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

        // Her seçmenin prepare zamanını ölçelim
        tbb::parallel_for(0, voterCount, [&](int i) {
            pipelineResults[i].timing.prep_start = Clock::now();
            // Her seçmen .did'i verip prepare'lesin
            PrepareBlindSignOutput bsOut = prepareBlindSign(params, dids[i].did);
            pipelineResults[i].timing.prep_end = Clock::now();

            // Bu bsOut'u saklayacağız, çünkü BlindSign'da lazım
            // Şimdilik vektörde DID saklamıyoruz ama pipeline'a koymamız gerekebilir
            // Onun yerine DID struct'ına ekleyebilirdik. Fakat basit olsun diye
            // pipelineResults[i] bu veriyi saklamıyor; alt aşamada queue'ye atacağız.

            // Log
            logThreadUsage("Pipeline", "Voter " + std::to_string(i+1) + " prepareBlindSign finished.");

            // Hazırlık biterken DID struct'ına (veya ayrık bir vektöre) bsOut kaydedebilirsiniz
            // Örneğin DID'e ek alan açabilirsiniz.
            // Burada basitçe DID'e ekliyoruz:
            dids[i].bsOut = bsOut;
        });
    }

    // 7b) BLIND SIGN: Producer–Consumer (En iyi dağılım)
    //    - Producer: Her seçmen için t adet SignRequest oluşturur, queue'ya atar
    //    - Consumer: ne adet admin thread, queue'dan alıp blindSign yapar

    auto blindStart = Clock::now(); // pipeline global start
    // 7b-i) Producer
    remainingJobs = voterCount * t; // Toplam istek adedi
    {
        // Kuyruk doldurma
        std::lock_guard<std::mutex> lk(queueMutex);
        for (int i = 0; i < voterCount; i++) {
            pipelineResults[i].timing.blind_start = blindStart; // her seçmen için start
            // t adet SignRequest üret
            for (int j = 0; j < t; j++) {
                SignRequest req;
                req.voterId = i;
                req.bsOut   = dids[i].bsOut; // prepare'de sakladığımız bsOut
                requestQueue.push(req);
            }
        }
    }
    // notify_all: Kuyruk doldu, admin'ler başlayabilir
    queueCV.notify_all();

    // 7b-ii) Consumer fonksiyonu (Admin Thread)
    auto adminWorker = [&](int adminIndex) {
        for (;;) {
            SignRequest job;
            {
                std::unique_lock<std::mutex> ul(queueMutex);

                // Kuyruk boş ve hala iş varsa bekle
                queueCV.wait(ul, [&]{
                    return (!requestQueue.empty() || remainingJobs <= 0);
                });
                if (remainingJobs <= 0) {
                    // Tüm işler bitti
                    return;
                }
                // Aksi halde kuyruğun boş olmadığını garanti ediyoruz
                job = requestQueue.front();
                requestQueue.pop();
            }
            // Şimdi queueMutex'i bıraktık, imzalama yapabiliriz
            // Log: started
            logThreadUsage("BlindSign",
               "Voter " + std::to_string(job.voterId+1) +
               " - Admin " + std::to_string(adminIndex+1) +
               " sign task started on thread " +
               std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
            );

            // İmzalama:
            mpz_t xm, ym;
            mpz_init(xm);
            mpz_init(ym);
            element_to_mpz(xm, keyOut.eaKeys[adminIndex].sgk1);
            element_to_mpz(ym, keyOut.eaKeys[adminIndex].sgk2);

            BlindSignature sig = blindSign(params, job.bsOut, xm, ym);

            mpz_clear(xm);
            mpz_clear(ym);

            // Log: finished
            logThreadUsage("BlindSign",
               "Voter " + std::to_string(job.voterId+1) +
               " - Admin " + std::to_string(adminIndex+1) +
               " sign task finished on thread " +
               std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
            );

            // Sonucu pipelineResults'e kaydet
            {
                // Tek seçmene yazdığımız için normalde race riskini threshold>1'de dahi minimal
                // ama yine de emniyet için bir lock kullanabiliriz
                static std::mutex resultMutex;
                std::lock_guard<std::mutex> lk(resultMutex);
                pipelineResults[job.voterId].signatures.push_back(sig);
            }

            // Bir iş bitti
            int r = --remainingJobs;
            if (r <= 0) {
                // Tüm işler bitti => diğer thread'leri uyandır ki çıkabilsinler
                queueCV.notify_all();
                return;
            }
        }
    };

    // 7b-iii) Admin thread'lerini başlat
    std::vector<std::thread> adminThreads;
    adminThreads.reserve(ne);
    for (int a = 0; a < ne; a++) {
        adminThreads.emplace_back(adminWorker, a);
    }

    // 7b-iv) Admin thread'lerini join (hepsini bekle)
    for (auto &th : adminThreads) {
        th.join();
    }

    auto blindEnd = Clock::now(); // pipeline global end
    // Her voter için blind_end'i kaydedelim
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].timing.blind_end = blindEnd;
    }

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
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(
        blindEnd - pipelineResults[0].timing.prep_start
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
