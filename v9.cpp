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
#include <atomic>

#include <tbb/flow_graph.h>       // TBB Flow Graph
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
static std::mutex logMutex;
static std::ofstream threadLog("threads.txt");

void logThreadUsage(const std::string &phase, const std::string &msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    auto now = Clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    threadLog << "[" << ms << " ms] " << phase << ": " << msg << "\n";
}

// -----------------------------------------------------------------------------
// Pipeline zaman bilgisi
struct PipelineTiming {
    Clock::time_point prep_start;
    Clock::time_point prep_end;
    Clock::time_point blind_start;
    Clock::time_point blind_end;
};

// Her seçmen için sonuçları tutan yapı
struct PipelineResult {
    std::vector<BlindSignature> signatures;
    PipelineTiming timing;
};

// -----------------------------------------------------------------------------
// Global: admin anahtarları, parametreler, vb.
// -----------------------------------------------------------------------------
int ne = 0;         // admin (EA) sayısı
int t  = 0;         // threshold
int voterCount = 0; // seçmen sayısı

TIACParams params;
KeyGenOutput keyOut;

// Her seçmen için DID
std::vector<DID> dids;
// Her seçmen için pipelineResult
std::vector<PipelineResult> pipelineResults;

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
int main() {
    // 1) params.txt'den EA sayısı (ne), threshold (t) ve seçmen sayısı (voterCount) okunuyor
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
    dids.resize(voterCount);
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
    pipelineResults.resize(voterCount);

    // Pipeline başlangıcı
    auto pipelineStart = Clock::now();

    // TBB concurrency (opsiyonel): max 50 thread
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

    // -------------------------------------------------------------------------
    // TBB Flow Graph
    // Burada 2 ana stage oluşturuyoruz:
    //  1) prepareNode: giren int => Voter ID, çıkan (voterId, bsOut)
    //  2) signNode   : giren (voterId, bsOut), imzaları yapar, en sonda voterId döndürür
    //
    // Son olarak graph.wait_for_all() ile pipeline bitişini bekleriz.
    // -------------------------------------------------------------------------
    tbb::flow::graph g;

    // (A) Hazırlama aşaması (prepareNode)
    // Burada concurrency = tbb::flow::unlimited diyerek,
    //   "hazırlamalar" parallel şekilde koşsun diyoruz.
    // input: int (voterId)
    // output: std::pair<int, PrepareBlindSignOutput>
    tbb::flow::function_node<int, std::pair<int, PrepareBlindSignOutput>> prepareNode(
        g,
        tbb::flow::unlimited,
        [&](int vId) -> std::pair<int, PrepareBlindSignOutput> {
            // vId seçmenin prepare’i
            pipelineResults[vId].timing.prep_start = Clock::now();
            PrepareBlindSignOutput bsOut = prepareBlindSign(params, dids[vId].did);
            pipelineResults[vId].timing.prep_end   = Clock::now();

            // Debug log
            {
                logThreadUsage("Pipeline",
                    "Voter " + std::to_string(vId+1) +
                    " prepareBlindSign finished on thread " +
                    std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
                );
            }

            // prepareNode çıktısı => (vId, bsOut)
            return {vId, bsOut};
        }
    );

    // (B) İmza aşaması (signNode)
    // input : (vId, bsOut)
    // output: int (vId) -> final stage
    // concurrency = tbb::flow::unlimited yine
    tbb::flow::function_node<std::pair<int, PrepareBlindSignOutput>, int> signNode(
        g,
        tbb::flow::unlimited,
        [&](std::pair<int, PrepareBlindSignOutput> inPair) -> int {
            int vId = inPair.first;
            PrepareBlindSignOutput &bsOut = inPair.second;

            // BlindSign başlangıcı
            pipelineResults[vId].timing.blind_start = Clock::now();

            // T adet imza alalım
            std::vector<BlindSignature> sigs(t);
            // Rastgele admin subset seçelim (yoksa j % ne de olabilir)
            std::vector<int> allAdmins(ne);
            std::iota(allAdmins.begin(), allAdmins.end(), 0);
            static thread_local std::mt19937 rng(std::random_device{}());
            std::shuffle(allAdmins.begin(), allAdmins.end(), rng);

            for (int j = 0; j < t; j++) {
                int aId = allAdmins[j % ne]; // T <= ne ise => aId = allAdmins[j]

                // Log: started
                {
                    logThreadUsage("BlindSign",
                        "Voter " + std::to_string(vId+1) +
                        " - Admin " + std::to_string(aId+1) +
                        " sign task started on thread " +
                        std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
                    );
                }

                mpz_t xm, ym;
                mpz_init(xm);
                mpz_init(ym);
                element_to_mpz(xm, keyOut.eaKeys[aId].sgk1);
                element_to_mpz(ym, keyOut.eaKeys[aId].sgk2);

                BlindSignature sig = blindSign(params, bsOut, xm, ym);

                mpz_clear(xm);
                mpz_clear(ym);

                // Log: finished
                {
                    logThreadUsage("BlindSign",
                        "Voter " + std::to_string(vId+1) +
                        " - Admin " + std::to_string(aId+1) +
                        " sign task finished on thread " +
                        std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
                    );
                }

                sigs[j] = sig;
            }

            pipelineResults[vId].timing.blind_end = Clock::now();

            // İmzaları pipelineResults[vId].signatures’e kaydedelim
            pipelineResults[vId].signatures = std::move(sigs);

            // Bu node'un çıktısı => vId
            return vId;
        }
    );

    // (C) "signNode"dan çıkan vId'yi sadece alıp "tamam" diyebileceğimiz,
    //     son bir function_node ya da empty_node oluşturabiliriz.
    //     Aslında output'a ihtiyacınız yoksa connect etmeye de gerek yok.
    //     Yine de tam pipeline hissi için ekleyelim:
    tbb::flow::function_node<int> finalNode(
        g,
        tbb::flow::serial,  // tek concurrency ile
        [&](int vId){
            // "vId" pipeline'ın sonuna geldi (hazırlama+imza bitti).
            // Burada ek bir log vs. isterseniz yapabilirsiniz.
            // Şimdilik boş bırakalım.
        }
    );

    // Bağlantılar: prepareNode -> signNode -> finalNode
    make_edge(prepareNode, signNode);
    make_edge(signNode, finalNode);

    // (D) Şimdi, tüm seçmenler için "prepareNode" girişi verelim
    for (int vId = 0; vId < voterCount; vId++) {
        prepareNode.try_put(vId);
    }

    // (E) Graph bitişini bekle
    g.wait_for_all();

    // Pipeline bitiş
    auto pipelineEnd = Clock::now();
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();

    // 8) Sonuçların ve zamanların raporlanması
    long long cumulativePrep_us  = 0;
    long long cumulativeBlind_us = 0;

    for (int i = 0; i < voterCount; i++) {
        int gotCount = (int)pipelineResults[i].signatures.size();
        std::cout << "Secmen " << (i+1)
                  << " icin " << gotCount << " adet imza alindi.\n";

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

    // 9) KeyOut ve params bellek temizliği
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

    // 10) Zaman ölçümleri (ms)
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
    std::cout << "Pipeline (Flow Graph)  : " << pipeline_ms << " ms\n";
    std::cout << "\nToplam hazirlama (sum) = "
              << (cumulativePrep_us / 1000.0) << " ms\n";
    std::cout << "Toplam kör imza (sum)  = "
              << (cumulativeBlind_us / 1000.0) << " ms\n";

    // threads.txt dosyasını kapat
    threadLog.close();
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
