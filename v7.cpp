#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <memory>
#include <mutex>

#include <tbb/parallel_for.h>
#include <tbb/global_control.h>

#include "setup.h"
#include "keygen.h"
#include "didgen.h"
#include "prepareblindsign.h"
#include "blindsign.h"   // Alg.50
#include "unblindsign.h" // Alg.13

using Clock = std::chrono::steady_clock;

struct PipelineTiming {
    // İsteğe göre her seçmen için sakladığımız süreler:
    Clock::time_point prep_start;  // prepareBlindSign başlangıcı
    Clock::time_point prep_end;    // prepareBlindSign bitişi
    // blindSign için toplu ölçüm
    Clock::time_point blind_start; // ilk kör imza görevi başlangıcı (basitçe prep_end sonrası)
    Clock::time_point blind_end;   // son kör imza görevi bitişi
};

struct PipelineResult {
    std::vector<BlindSignature> signatures;  
    PipelineTiming timing;
};

// Ana fonksiyon
int main() {
    // 1) params.txt’den EA sayısı (ne), threshold (t) ve seçmen sayısı (voterCount) okunuyor
    int ne = 0;         // admin (EA) sayısı
    int t  = 0;         // eşik
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

    std::cout << "EA (admin) sayisi       = " << ne << "\n"
              << "Esik degeri (threshold) = " << t << "\n"
              << "Secmen sayisi           = " << voterCount << "\n\n";

    // 2) Setup (Alg.1)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // 3) Pairing testi
    element_t pairingTest;
    element_init_GT(pairingTest, params.pairing);
    auto startPairing = Clock::now();
    pairing_apply(pairingTest, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairing_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();
    element_clear(pairingTest);

    // 4) KeyGen (Alg.2)
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();

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

    // 6) DID Generation
    auto startDIDGen = Clock::now();
    std::vector<DID> dids(voterCount);
    for (int i = 0; i < voterCount; i++) {
        dids[i] = createDID(params, voterIDs[i]);
    }
    auto endDIDGen = Clock::now();
    auto didGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endDIDGen - startDIDGen).count();

    // PipelineResult: her seçmen için imza sonuçlarını ve zaman ölçümlerini saklıyoruz
    std::vector<PipelineResult> pipelineResults(voterCount);

    // 7) Pipeline başlangıcı: Prepare aşamasına giriyoruz
    auto pipelineStart = Clock::now();

    // TBB thread sayısını örneğin 50 ile sınırlayalım (opsiyonel):
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

    // 7A) Bütün seçmenler için prepareBlindSign paralelde
    std::vector<PrepareBlindSignOutput> preparedOutputs(voterCount);

    tbb::parallel_for(0, voterCount, [&](int i){
        // Prepare start
        pipelineResults[i].timing.prep_start = Clock::now();
        preparedOutputs[i] = prepareBlindSign(params, dids[i].did);
        pipelineResults[i].timing.prep_end   = Clock::now();
    });

    // 8) Kör imza görevlerinin tamamını tek bir "task listesi"ne yerleştiriyoruz
    struct SignTask {
        int voterId;
        int indexInVoter; // Aynı seçmen için kaçıncı imza
        int adminId;
    };
    std::vector<SignTask> tasks;
    tasks.reserve(voterCount * t);

    // Her seçmen için t adet imza işi ekleyelim
    // Hangi admin imzalayacak? Burada basitçe "j % ne" veya rastgele admin seçebilirsiniz.
    for (int i = 0; i < voterCount; i++) {
        // signatures vector'ünü baştan boyutlandıralım:
        pipelineResults[i].signatures.resize(t);

        // "blind_start" için kabaca "prepare bitti" anını kullanabiliriz.
        // ya da pipelineStart ile de sabitlenebilir. Tamamen tercih meselesi.
        pipelineResults[i].timing.blind_start = pipelineResults[i].timing.prep_end;

        for (int j = 0; j < t; j++) {
            SignTask st;
            st.voterId      = i;
            st.indexInVoter = j;
            // Örnek: sabit bir dağıtım
            st.adminId      = (j % ne);
            // İsterseniz rastgele admin atayabilirsiniz:
            // st.adminId = rand() % ne;
            tasks.push_back(st);
        }
    }

    // 9) Bütün kör imza (blindSign) görevlerini paralelde çalıştırıyoruz
    tbb::parallel_for(
        0, static_cast<int>(tasks.size()),
        [&](int idx) {
            const SignTask &st = tasks[idx];
            int vId = st.voterId;
            int j   = st.indexInVoter;
            int aId = st.adminId;

            // Admin aId'nin anahtarlarını mpz_t olarak alalım:
            mpz_t xm, ym;
            mpz_init(xm);
            mpz_init(ym);

            element_to_mpz(xm, keyOut.eaKeys[aId].sgk1);
            element_to_mpz(ym, keyOut.eaKeys[aId].sgk2);

            // Kör imza
            BlindSignature sig = blindSign(params, preparedOutputs[vId], xm, ym);

            // Signeyi ilgili seçmenin j. imzası olarak saklayalım
            pipelineResults[vId].signatures[j] = sig;

            mpz_clear(xm);
            mpz_clear(ym);
        }
    );

    // 10) Her seçmen için "blind_end" zamanını güncelleyelim
    //    (Bütün işler bittikten sonra, tam "pipelineEnd" öncesi)
    auto pipelineEnd = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].timing.blind_end = pipelineEnd;
    }

    // 11) Toplam pipeline süresi (hazırla + kör imza)
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();

    // Sonuçları yazdırma + zaman ölçümleri
    long long cumulativePrep_us = 0;
    long long cumulativeBlind_us = 0;

    for (int i = 0; i < voterCount; i++) {
        int gotCount = static_cast<int>(pipelineResults[i].signatures.size());

        auto prep_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.prep_end - pipelineResults[i].timing.prep_start
        ).count();

        auto blind_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.blind_end - pipelineResults[i].timing.blind_start
        ).count();

        cumulativePrep_us  += prep_time;
        cumulativeBlind_us += blind_time;

        std::cout << "Secmen " << (i+1)
                  << " icin " << gotCount << " adet imza alindi.\n"
                  << " - Prepare suresi   = " << prep_time/1000.0  << " ms\n"
                  << " - BlindSign suresi = " << blind_time/1000.0 << " ms\n\n";
    }

    // 12) KeyOut ve params bellek temizliği
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

    // 13) Zaman ölçümlerini (ms olarak) gösterelim
    double setup_ms    = setup_us    / 1000.0;
    double pairing_ms  = pairing_us  / 1000.0;
    double keygen_ms   = keygen_us   / 1000.0;
    double idGen_ms    = idGen_us    / 1000.0;
    double didGen_ms   = didGen_us   / 1000.0;
    double pipeline_ms = pipeline_us / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi             : " << setup_ms     << " ms\n";
    std::cout << "Pairing suresi           : " << pairing_ms   << " ms\n";
    std::cout << "KeyGen suresi            : " << keygen_ms    << " ms\n";
    std::cout << "ID Generation            : " << idGen_ms     << " ms\n";
    std::cout << "DID Generation           : " << didGen_ms    << " ms\n";
    std::cout << "Pipeline (Prep+Blind)    : " << pipeline_ms  << " ms\n";

    std::cout << "\nToplam hazirlama (sum) = " << cumulativePrep_us/1000.0 << " ms\n";
    std::cout << "Toplam kör imza (sum)  = " << cumulativeBlind_us/1000.0 << " ms\n";

    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
