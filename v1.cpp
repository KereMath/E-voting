#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <memory>
#include <mutex>
#include <thread>

#include <tbb/parallel_for.h>
#include <tbb/global_control.h>

#include "setup.h"
#include "keygen.h"
#include "didgen.h"
#include "prepareblindsign.h"
#include "blindsign.h"   // Alg.50
#include "unblindsign.h" // Alg.13

using Clock = std::chrono::steady_clock;

// -----------------------------------------------------------------------------
// Global logger: thread kullanımını kaydetmek için (threads.txt)
// -----------------------------------------------------------------------------
std::mutex logMutex;
std::ofstream threadLog("threads.txt");

void logThreadUsage(const std::string &phase, const std::string &msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    auto now = Clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    threadLog << "[" << ms << " ms] " << phase << ": " << msg << "\n";
}

// -----------------------------------------------------------------------------
struct PipelineTiming {
    Clock::time_point prep_start;
    Clock::time_point prep_end;
    Clock::time_point blind_start;
    Clock::time_point blind_end;
};

struct PipelineResult {
    std::vector<BlindSignature> signatures;
    PipelineTiming timing;
};

// Yardımcı fonksiyon: element kopyalamak için (const kullanılmıyor)
void my_element_dup(element_t dest, element_t src) {
    element_init_same_as(dest, src);
    element_set(dest, src);
}

// -----------------------------------------------------------------------------
int main() {
    // 1) params.txt'den EA sayısı, threshold (t) ve seçmen sayısı (voterCount) okunuyor
    int ne = 0;         // admin (EA) sayısı
    int t  = 0;         // threshold
    int voterCount = 0; // seçmen sayısı
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
            std::cout << "sgk1 (x_m) = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].sgk2);
            std::cout << "sgk2 (y_m) = " << buf << "\n";
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
        std::cout << "Secmen " << (i+1) << " icin x   = " << x_str << "\n"
                  << "Secmen " << (i+1) << " icin DID = " << dids[i].did << "\n\n";
        free(x_str);
    }

    // PipelineResult: her seçmen için
    std::vector<PipelineResult> pipelineResults(voterCount);

    // Pipeline başlangıcı
    auto pipelineStart = Clock::now();

    // TBB thread sayısını 50 ile sınırlayalım (opsiyonel)
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

    // 7) Tüm seçmenler için prepareBlindSign (paralelde)
    std::vector<PrepareBlindSignOutput> preparedOutputs(voterCount);

    tbb::parallel_for(0, voterCount, [&](int i){
        // Prepare start
        pipelineResults[i].timing.prep_start = Clock::now();
        PrepareBlindSignOutput bsOut = prepareBlindSign(params, dids[i].did);
        pipelineResults[i].timing.prep_end = Clock::now();

        // Debug log: bu seçmen prepare işi bitti
        logThreadUsage("Pipeline",
            "Voter " + std::to_string(i+1) +
            " prepareBlindSign finished on thread " +
            std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
        );

        preparedOutputs[i] = bsOut;
    });

    // 8) Kör imza görevleri için tek bir "SignTask" havuzu
    struct SignTask {
        int voterId;
        int indexInVoter;
        int adminId;
    };
    std::vector<SignTask> tasks;
    tasks.reserve(voterCount * t);

    // Rastgele admin subset'i seçimi için
    std::random_device rd;
    std::mt19937 rng(rd());

    // Admin indekslerinin [0..ne-1] aralığını tutan dizi
    std::vector<int> adminIndices(ne);
    std::iota(adminIndices.begin(), adminIndices.end(), 0);

    // Her seçmen için T adet FARKLI admin seçip tasks’e ekleyelim
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].signatures.resize(t);
        pipelineResults[i].timing.blind_start = pipelineResults[i].timing.prep_end;

        // Admin dizisini her seçmen için karıştıralım (shuffle)
        std::shuffle(adminIndices.begin(), adminIndices.end(), rng);
        // Böylece adminIndices[0..t-1] => o seçmen için T farklı admin

        for (int j = 0; j < t; j++) {
            SignTask st;
            st.voterId      = i;
            st.indexInVoter = j;
            st.adminId      = adminIndices[j]; // T farklı admin
            tasks.push_back(st);
        }
    }

    // 9) Şimdi bu tasks havuzunu paralelde koşturuyoruz
    tbb::parallel_for(
        0, (int)tasks.size(),
        [&](int idx) {
            const SignTask &st = tasks[idx];
            int vId = st.voterId;
            int j   = st.indexInVoter;
            int aId = st.adminId;

            // Log: started
            logThreadUsage("BlindSign",
                "Voter " + std::to_string(vId+1) +
                " - Admin " + std::to_string(aId+1) +
                " sign task started on thread " +
                std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
            );

            mpz_t xm, ym;
            mpz_init(xm);
            mpz_init(ym);

            element_to_mpz(xm, keyOut.eaKeys[aId].sgk1);
            element_to_mpz(ym, keyOut.eaKeys[aId].sgk2);

            BlindSignature sig = blindSign(params, preparedOutputs[vId], xm, ym);

            mpz_clear(xm);
            mpz_clear(ym);

            // Log: finished
            logThreadUsage("BlindSign",
                "Voter " + std::to_string(vId+1) +
                " - Admin " + std::to_string(aId+1) +
                " sign task finished on thread " +
                std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
            );

            // Sonucu ilgili seçmenin j. imzası olarak saklayalım
            pipelineResults[vId].signatures[j] = sig;
        }
    );

    // 10) Kör imzalar bittiğinde pipelineEnd
    auto pipelineEnd = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].timing.blind_end = pipelineEnd;
    }

    // 11) Pipeline süresi
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();

    // Sonuçları ekrana basalım
    long long cumulativePrep_us  = 0;
    long long cumulativeBlind_us = 0;

    for (int i = 0; i < voterCount; i++) {
        int gotCount = (int)pipelineResults[i].signatures.size();
        std::cout << "Secmen " << (i+1) << " icin " << gotCount
                  << " adet imza alindi.\n";

        auto prep_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.prep_end - pipelineResults[i].timing.prep_start
        ).count();

        auto blind_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.blind_end - pipelineResults[i].timing.blind_start
        ).count();

        cumulativePrep_us  += prep_time;
        cumulativeBlind_us += blind_time;

        std::cout << "Voter " << (i+1)
                  << ": Prepare time = " << (prep_time / 1000.0)
                  << " ms, BlindSign time = " << (blind_time / 1000.0) << " ms\n\n";
    }

    // 12) Bellek temizliği
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

    // 13) Zaman ölçümlerini ekrana yazalım
    double setup_ms    = setup_us    / 1000.0;
    double pairing_ms  = pairing_us  / 1000.0;
    double keygen_ms   = keygen_us   / 1000.0;
    double idGen_ms    = idGen_us    / 1000.0;
    double didGen_ms   = didGen_us   / 1000.0;
    double pipeline_ms = pipeline_us / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi       : " << setup_ms    << " ms\n";
    std::cout << "Pairing suresi     : " << pairing_ms  << " ms\n";
    std::cout << "KeyGen suresi      : " << keygen_ms   << " ms\n";
    std::cout << "ID Generation      : " << idGen_ms    << " ms\n";
    std::cout << "DID Generation     : " << didGen_ms   << " ms\n";
    std::cout << "Pipeline (Prep+Blind): " << pipeline_ms << " ms\n";

    std::cout << "\nToplam hazirlama (sum) = "
              << (cumulativePrep_us / 1000.0) << " ms\n";
    std::cout << "Toplam kör imza (sum)  = "
              << (cumulativeBlind_us / 1000.0) << " ms\n";

    // threads.txt dosyasını kapat
    threadLog.close();
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
