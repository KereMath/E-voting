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
#include "aggregate.h" // aggregateSign fonksiyonunu kullanmak için
#include "provecredential.h"  // proveCredential fonksiyonunu içerir
#include "verifycredential.h"  // verifyCredential tanımı

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
    auto programStart = Clock::now();

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

    // {
    //     char* p_str = mpz_get_str(nullptr, 10, params.prime_order);
    //     std::cout << "p (Grup mertebesi) =\n" << p_str << "\n\n";
    //     free(p_str);
    // }
    // {
    //     char buf[1024];
    //     element_snprintf(buf, sizeof(buf), "%B", params.g1);
    //     std::cout << "g1 =\n" << buf << "\n\n";
    // }
    // {
    //     char buf[1024];
    //     element_snprintf(buf, sizeof(buf), "%B", params.h1);
    //     std::cout << "h1 =\n" << buf << "\n\n";
    // }
    // {
    //     char buf[1024];
    //     element_snprintf(buf, sizeof(buf), "%B", params.g2);
    //     std::cout << "g2 =\n" << buf << "\n\n";
    // }

    // 3) Pairing testi
    element_t pairingTest;
    element_init_GT(pairingTest, params.pairing);
    auto startPairing = Clock::now();
    pairing_apply(pairingTest, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairing_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();
    // {
    //     char buf[1024];
    //     element_snprintf(buf, sizeof(buf), "%B", pairingTest);
    //     std::cout << "[ZAMAN] e(g1, g2) hesabi: " << pairing_us << " µs\n";
    //     std::cout << "e(g1, g2) =\n" << buf << "\n\n";
    // }
    element_clear(pairingTest);

    // 4) KeyGen (Alg.2)
    // std::cout << "=== TTP ile Anahtar Uretimi (KeyGen) ===\n";
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
    // for (int i = 0; i < ne; i++) {
    //     std::cout << "=== EA Authority " << (i + 1) << " ===\n";
    //     {
    //         char buf[1024];
    //         element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].sgk1);
    //         std::cout << "sgk1 (x_m) = " << buf << "\n";
    //     }
    //     {
    //         char buf[1024];
    //         element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].sgk2);
    //         std::cout << "sgk2 (y_m) = " << buf << "\n";
    //     }
    //     {
    //         char buf[1024];
    //         element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm1);
    //         std::cout << "vkm1 = g2^(x_m) = " << buf << "\n";
    //     }
    //     {
    //         char buf[1024];
    //         element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm2);
    //         std::cout << "vkm2 = g2^(y_m) = " << buf << "\n";
    //     }
    //     {
    //         char buf[1024];
    //         element_snprintf(buf, sizeof(buf), "%B", keyOut.eaKeys[i].vkm3);
    //         std::cout << "vkm3 = g1^(y_m) = " << buf << "\n";
    //     }
    //     std::cout << "\n";
    // }

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
    // std::cout << "=== ID Generation ===\n";
    // for (int i = 0; i < voterCount; i++) {
    //     std::cout << "Secmen " << (i+1) << " ID = " << voterIDs[i] << "\n";
    // }
    // std::cout << "\n";

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
// prepareBlindSign çağrılarından sonra:
    // for (size_t i = 0; i < preparedOutputs.size(); i++) {
    //     std::cout << "=== Voter " << i+1 << " Debug Bilgileri ===\n";
    //     std::cout << "oi         : " << preparedOutputs[i].debug.oi << "\n";
    //     std::cout << "didInt     : " << preparedOutputs[i].debug.didInt << "\n";
    //     std::cout << "comi       : " << preparedOutputs[i].debug.comi << "\n";
    //     std::cout << "h          : " << preparedOutputs[i].debug.h << "\n";
    //     std::cout << "com        : " << preparedOutputs[i].debug.com << "\n";
    //     std::cout << "--- KoR Debug ---\n";
    //     std::cout << "r1         : " << preparedOutputs[i].debug.kor_r1 << "\n";
    //     std::cout << "r2         : " << preparedOutputs[i].debug.kor_r2 << "\n";
    //     std::cout << "r3         : " << preparedOutputs[i].debug.kor_r3 << "\n";
    //     std::cout << "comi_prime : " << preparedOutputs[i].debug.kor_comi_prime << "\n";
    //     std::cout << "com_prime  : " << preparedOutputs[i].debug.kor_com_prime << "\n";
    //     std::cout << "c          : " << preparedOutputs[i].debug.kor_c << "\n";
    //     std::cout << "s1         : " << preparedOutputs[i].debug.kor_s1 << "\n";
    //     std::cout << "s2         : " << preparedOutputs[i].debug.kor_s2 << "\n";
    //     std::cout << "s3         : " << preparedOutputs[i].debug.kor_s3 << "\n";
    //     std::cout << "============================\n\n";
    // }

    // 8) Kör imza görevleri için tek bir "SignTask" havuzu
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

// 9) Tasks havuzunu paralel çalıştırıyoruz
// 9) Kör imza görevlerini paralel çalıştırıyoruz
tbb::parallel_for(
    0, (int)tasks.size(),
    [&](int idx) {
        const SignTask &st = tasks[idx];
        int vId = st.voterId;
        int j   = st.indexInVoter;
        int aId = st.adminId;

        // logThreadUsage("BlindSign",
        //     "Voter " + std::to_string(vId+1) +
        //     " - Admin " + std::to_string(aId+1) +
        //     " sign task started on thread " +
        //     std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
        // );

        mpz_t xm, ym;
        mpz_init(xm);
        mpz_init(ym);

        element_to_mpz(xm, keyOut.eaKeys[aId].sgk1);
        element_to_mpz(ym, keyOut.eaKeys[aId].sgk2);

        BlindSignature sig = blindSign(params, preparedOutputs[vId], xm, ym, aId, vId);

        mpz_clear(xm);
        mpz_clear(ym);

        // logThreadUsage("BlindSign",
        //     "Voter " + std::to_string(vId+1) +
        //     " - Admin " + std::to_string(aId+1) +
        //     " sign task finished on thread " +
        //     std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
        // );

        pipelineResults[vId].signatures[j] = sig;
    }
);

    // 10) Kör imzalar tamamlandığında, pipeline bitiş zamanı ayarlanır
    auto pipelineEnd = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].timing.blind_end = pipelineEnd;
    }

    // std::cout << "\n=== İmzalama Sonuçları ===\n";
    for (int i = 0; i < voterCount; i++) {
        // std::cout << "Voter " << (i+1) << " için:\n";
        // Her seçmenin imzaları, hangi admin tarafından üretilmişse admin sırası ile yazdırılıyor.
        for (int j = 0; j < (int)pipelineResults[i].signatures.size(); j++) {
            BlindSignature &sig = pipelineResults[i].signatures[j];
            // std::cout << "  Admin " << (sig.debug.adminId + 1)
            //         << " tarafından imzalandı. \n";
            // std::cout << "     h  = " << elemToStrG1(sig.h) << "\n";
            // std::cout << "     cm = " << elemToStrG1(sig.cm) << "\n";
        }
        // std::cout << "-------------------------\n";
    }


    // 11) Pipeline süresi
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();

    // Sonuçları ekrana basalım
    long long cumulativePrep_us  = 0;
    long long cumulativeBlind_us = 0;

    for (int i = 0; i < voterCount; i++) {
        int gotCount = (int)pipelineResults[i].signatures.size();
        // std::cout << "Secmen " << (i+1) << " icin " << gotCount
        //           << " adet imza alindi.\n";

        auto prep_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.prep_end - pipelineResults[i].timing.prep_start
        ).count();

        auto blind_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.blind_end - pipelineResults[i].timing.blind_start
        ).count();

        cumulativePrep_us  += prep_time;
        cumulativeBlind_us += blind_time;

        // std::cout << "Voter " << (i+1)
        //           << ": Prepare time = " << (prep_time / 1000.0)
        //           << " ms, BlindSign time = " << (blind_time / 1000.0) << " ms\n\n";
    }

    //Unblindsign
// 14) Unblind Phase: Her seçmen için threshold (örneğin t adet) imza unblind edilecek.
auto unblindStart = Clock::now();

std::vector< std::vector<UnblindSignature> > unblindResults(voterCount);
tbb::parallel_for(0, voterCount, [&](int i) {
    int numSigs = (int)pipelineResults[i].signatures.size();
    unblindResults[i].resize(numSigs);
    // İç döngüde de paralelleştirme (küçük eşik değerler için fazladan overhead yaratabilir)
    tbb::parallel_for(0, numSigs, [&](int j) {
        int adminId = pipelineResults[i].signatures[j].debug.adminId;
        UnblindSignature usig = unblindSign(params, preparedOutputs[i], pipelineResults[i].signatures[j], keyOut.eaKeys[adminId], dids[i].did);
        unblindResults[i][j] = usig;
    });
});


auto unblindEnd = Clock::now();
auto unblind_us = std::chrono::duration_cast<std::chrono::microseconds>(unblindEnd - unblindStart).count();

// Unblind sonuçlarını raporlama:
// std::cout << "\n=== Unblind Signature Results ===\n";
for (int i = 0; i < voterCount; i++) {
    // std::cout << "Voter " << (i+1) << " unblind signatures:\n";
    for (int j = 0; j < (int)unblindResults[i].size(); j++) {
        UnblindSignature &usig = unblindResults[i][j];
        // std::cout << "  Signature " << (j+1) << ":\n";
        std::cout << "     h   = " << elementToStringG1(usig.h) << "\n";
        std::cout << "     s_m = " << elementToStringG1(usig.s_m) << "\n";
        // std::cout << "     Debug - Hash(comi): " << usig.debug.hash_comi << "\n";
        std::cout << "     Debug - computed s_m: " << usig.debug.computed_s_m << "\n";
        // std::cout << "     Debug - pairing LHS: " << usig.debug.pairing_lhs << "\n";
        // std::cout << "     Debug - pairing RHS: " << usig.debug.pairing_rhs << "\n";
    }
    // std::cout << "-------------------------\n";
}


    //Aggregate
    std::vector<AggregateSignature> aggregateResults(voterCount);
    auto aggregateStart = Clock::now();
    
    tbb::parallel_for(0, voterCount, [&](int i) {
        // Her seçmenin aggregate imzası, unblindResults[i] (vector<UnblindSignature>) içindeki partial imza parçalarının çarpımıyla elde edilir.
        AggregateSignature aggSig = aggregateSign(params, unblindResults[i], keyOut.mvk, dids[i].did);
        aggregateResults[i] = aggSig;
    });
    
    auto aggregateEnd = Clock::now();
    auto aggregate_us = std::chrono::duration_cast<std::chrono::microseconds>(aggregateEnd - aggregateStart).count();
    
    // Aggregate sonuçlarını raporlama:
    std::cout << "\n=== Aggregate Signature Results ===\n";
    for (int i = 0; i < voterCount; i++) {
        std::cout << "Voter " << (i+1) << " aggregate signature:\n";
        std::cout << "    h = " << elementToStringG1(aggregateResults[i].h) << "\n";
        std::cout << "    s = " << elementToStringG1(aggregateResults[i].s) << "\n";
        std::cout << "    Debug Info:\n" << aggregateResults[i].debug_info << "\n";
        std::cout << "-------------------------\n";
    }



//Provecredential


// 16) ProveCredential Phase: Her seçmenin aggregate imzası üzerinde imza kanıtı oluşturulacak.
// ProveCredential Phase: Her seçmenin aggregate imzası üzerinde imza kanıtı oluşturulacak.


// VerifyCredential Phase: ProveCredential çıktısını doğrulayalım.



// 16) ProveCredential Phase: Her seçmenin aggregate imzası üzerinde imza kanıtı oluşturulacak.
std::vector<ProveCredentialOutput> proveResults(voterCount);
auto proveStart = Clock::now();
tbb::parallel_for(0, voterCount, [&](int i) {
    ProveCredentialOutput pOut = proveCredential(params, aggregateResults[i], keyOut.mvk, dids[i].did);
    proveResults[i] = pOut;
});
auto proveEnd = Clock::now();
auto prove_us = std::chrono::duration_cast<std::chrono::microseconds>(proveEnd - proveStart).count();

// ProveCredential sonuçlarını raporlama:
std::cout << "\n=== ProveCredential Results ===\n";
for (int i = 0; i < voterCount; i++) {
    std::cout << "Voter " << (i+1) << " prove credential output:\n";
    std::cout << "    h'' = " << elementToStringG1(proveResults[i].sigmaRnd.h) << "\n";
    std::cout << "    s'' = " << elementToStringG1(proveResults[i].sigmaRnd.s) << "\n";
    std::cout << "    k   = " << elementToStringG1(proveResults[i].k) << "\n";
    std::cout << "    π_v = " << proveResults[i].proof_v << "\n";
    std::cout << "    Debug Info:\n" << proveResults[i].sigmaRnd.debug_info << "\n";
    std::cout << "-------------------------\n";
}
std::cout << "\n[PROVE] Total ProveCredential Phase Time = " << (prove_us / 1000.0) << " ms\n";

// 17) VerifyCredential Phase: ProveCredential çıktısını doğrulayalım.
std::vector<bool> verifyResults(voterCount);
auto verifyStart = Clock::now();
tbb::parallel_for(0, voterCount, [&](int i) {
    bool res = verifyCredential(params, proveResults[i]);
    verifyResults[i] = res;
});
auto verifyEnd = Clock::now();
auto verify_us = std::chrono::duration_cast<std::chrono::microseconds>(verifyEnd - verifyStart).count();

// VerifyCredential sonuçlarını raporlama:
std::cout << "\n=== VerifyCredential Results ===\n";
for (int i = 0; i < voterCount; i++) {
    std::cout << "Voter " << (i+1) << " credential verification: " 
              << (verifyResults[i] ? "PASSED" : "FAILED") << "\n";
}
std::cout << "\n[VERIFY] Total VerifyCredential Phase Time = " << (verify_us / 1000.0) << " ms\n";









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
    auto programEnd = Clock::now();

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
    std::cout << "\n[UNBLIND] Total Unblind Phase Time = " << (unblind_us / 1000.0) << " ms\n";
    std::cout << "\n[AGGREGATE] Total Aggregate Phase Time = " << (aggregate_us / 1000.0) << " ms\n";
    std::cout << "\n[PROVE] Total ProveCredential Phase Time = " << (prove_us / 1000.0) << " ms\n";

    // threads.txt dosyasını kapat
    threadLog.close();
    auto totalDuration = std::chrono::duration_cast<std::chrono::microseconds>(programEnd - programStart).count();
    std::cout << "Total execution time: " << (totalDuration / 1000.0) << " ms\n";
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
