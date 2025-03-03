#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>    // std::shuffle
#include <memory>       // std::unique_ptr
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

// Yardımcı fonksiyon: element kopyalamak için (const kullanılmıyor)
void my_element_dup(element_t dest, element_t src) {
    element_init_same_as(dest, src);
    element_set(dest, src);
}

// Bu örnekte, pipeline aşamalarının zaman ölçümlerini tutmak için kullandığımız yapı.
struct PipelineTiming {
    Clock::time_point prep_start;   // prepareBlindSign başlangıcı
    Clock::time_point prep_end;     // prepareBlindSign bitişi
    Clock::time_point blind_start;  // blindSign görevlerinin başlangıcı
    Clock::time_point blind_end;    // blindSign görevlerinin tamamlandığı son an
};

// Her seçmenin kör imza sonuçlarını ve timing bilgisini tutmak için.
struct PipelineResult {
    std::vector<BlindSignature> signatures;
    PipelineTiming timing;
};

int main() {
    // 1) params.txt'den EA sayısı, eşik ve seçmen sayısı okunuyor.
    int ne = 0;         // admin (EA sayısı)
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

    std::cout << "EA (admin) sayisi         = " << ne << "\n";
    std::cout << "Esik degeri (threshold)   = " << t << "\n";
    std::cout << "Secmen sayisi (voterCount) = " << voterCount << "\n\n";

    // 2) Setup (Alg.1)
    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();

    // Örnek olarak ekrana bazı parametreleri basalım
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
            std::cout << "vkm1 = g2^(x_m)   = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm2);
            std::cout << "vkm2 = g2^(y_m)   = " << buf << "\n";
        }
        {
            char buf[1024];
            element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm3);
            std::cout << "vkm3 = g1^(y_m)   = " << buf << "\n";
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

    // Her seçmen için sonuçların ve zamanlama ölçümlerinin saklanacağı yapı.
    std::vector<PipelineResult> pipelineResults(voterCount);

    // Pipeline başlangıç zamanını kaydet
    auto pipelineStart = Clock::now();

    // TBB paralellik ayarı: max 50 thread (örn. isteğe göre değiştirilebilir).
    // Bu, TBB'nin oluşturabileceği en fazla worker thread sayısını sınırlamak içindir.
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

    // 7) Asıl paralel iş: Her seçmen (i) için:
    //    - prepareBlindSign
    //    - T kez blindSign (farklı admin’lerce imzalanacağı varsayımıyla)
    tbb::parallel_for(0, voterCount, [&](int i) {
        // A) Prepare
        pipelineResults[i].timing.prep_start = Clock::now();
        PrepareBlindSignOutput bsOut = prepareBlindSign(params, dids[i].did);
        pipelineResults[i].timing.prep_end   = Clock::now();

        // B) T kez kör imza
        pipelineResults[i].timing.blind_start = Clock::now();

        // Her seçmenin t tane imzaya ihtiyacı var.
        // Bu kısımda nested (iç içe) bir paralel_for çalıştırarak T adet imzayı aynı anda dağıtabilirsiniz.
        // Veya tek for ile de yazılabilir. Burada paralel_for yazalım:
        std::vector<BlindSignature> localSignatures(t);

        tbb::parallel_for(0, t, [&](int j) {
            // Bu örnekte, imzayı hangi admin atıyor, j'yi admin sayısına modlayarak basitçe seçiyoruz.
            // (Gerçek senaryoda her j'nin farklı admin'e gittiğini düşünebilirsiniz.)
            int adminIndex = j % ne;

            mpz_t xm, ym;
            mpz_init(xm);
            mpz_init(ym);

            element_to_mpz(xm, keyOut.eaKeys[adminIndex].sgk1);
            element_to_mpz(ym, keyOut.eaKeys[adminIndex].sgk2);

            BlindSignature sig = blindSign(params, bsOut, xm, ym);

            mpz_clear(xm);
            mpz_clear(ym);

            localSignatures[j] = sig;
        });

        // Elde edilen T adet imzayı pipelineResults’e ekle
        pipelineResults[i].signatures.insert(pipelineResults[i].signatures.end(),
                                             localSignatures.begin(),
                                             localSignatures.end());

        // Son kör imzanın da bittiği zaman
        pipelineResults[i].timing.blind_end = Clock::now();
    });

    // Tüm seçmenlerin işleri bittikten sonra pipeline bitiş
    auto pipelineEnd = Clock::now();
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();

    // 8) Sonuçların yazdırılması
    long long cumulativePrep_us = 0;
    long long cumulativeBlind_us = 0;

    for (int i = 0; i < voterCount; i++) {
        // Kaç admin onayı alındı?
        int gotCount = (int) pipelineResults[i].signatures.size();

        std::cout << "Secmen " << (i+1) << " icin " << gotCount
                  << " adet (kör) imza alindi.\n";

        auto prep_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.prep_end - pipelineResults[i].timing.prep_start
        ).count();

        auto blind_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.blind_end - pipelineResults[i].timing.blind_start
        ).count();

        cumulativePrep_us  += prep_time;
        cumulativeBlind_us += blind_time;

        std::cout << "Voter " << (i+1)
                  << ": Prepare time  = " << prep_time/1000.0  << " ms, "
                  << "BlindSign time = " << blind_time/1000.0 << " ms\n\n";
    }

    // 9) Bellek temizliği (keyOut, params, vs.)
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

    // 10) Zaman ölçümlerini ekrana dökelim.
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

    // Toplam pipeline (kümülatif) zamanlar (hazırlama + kör imzalama):
    std::cout << "\nToplam hazırlama islerinin (sum) süresi   = "
              << cumulativePrep_us/1000.0 << " ms\n";
    std::cout << "Toplam kör imza islerinin (sum) süresi    = "
              << cumulativeBlind_us/1000.0 << " ms\n";

    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
