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
#include "aggregate.h"   // for aggregateSignatures

using Clock = std::chrono::steady_clock;

// -----------------------------------------------------------------------------
// Global logger
// -----------------------------------------------------------------------------
std::mutex logMutex;
std::ofstream threadLog("threads.txt");

void logThreadUsage(const std::string &phase, const std::string &msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    auto now = Clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch())
                  .count();
    threadLog << "[" << ms << " ms] " << phase << ": " << msg << "\n";
}

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

// copy helper
void my_element_dup(element_t dest, element_t src) {
    element_init_same_as(dest, src);
    element_set(dest, src);
}

int main() {
    // 1) read from params.txt
    int ne = 0; 
    int t  = 0; 
    int voterCount = 0;
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

    // 2) setup
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

    // 3) Pairing test
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

    // 4) KeyGen
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

    // Print EAs
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

    // PipelineResult: for each voter
    std::vector<PipelineResult> pipelineResults(voterCount);

    // pipeline start
    auto pipelineStart = Clock::now();

    // limit TBB to 50 threads
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);

    // 7) prepareBlindSign in parallel
    std::vector<PrepareBlindSignOutput> preparedOutputs(voterCount);

    tbb::parallel_for(0, voterCount, [&](int i){
        pipelineResults[i].timing.prep_start = Clock::now();
        PrepareBlindSignOutput bsOut = prepareBlindSign(params, dids[i].did);
        pipelineResults[i].timing.prep_end = Clock::now();

        logThreadUsage("Pipeline",
            "Voter " + std::to_string(i+1) +
            " prepareBlindSign finished on thread " +
            std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
        );
        preparedOutputs[i] = bsOut;
    });

    // 8) "SignTask" struct
    struct SignTask {
        int voterId;
        int indexInVoter;
        int adminId;
    };
    std::vector<SignTask> tasks;
    tasks.reserve(voterCount * t);

    // random device for admin subset
    std::random_device rd2;
    std::mt19937 rng(rd2());

    // adminIndices => [0..ne-1]
    std::vector<int> adminIndices(ne);
    std::iota(adminIndices.begin(), adminIndices.end(), 0);

    // for each voter => T distinct admin
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].signatures.resize(t);
        pipelineResults[i].timing.blind_start = pipelineResults[i].timing.prep_end;

        // shuffle adminIndices
        std::shuffle(adminIndices.begin(), adminIndices.end(), rng);

        for (int j = 0; j < t; j++) {
            SignTask st;
            st.voterId = i;
            st.indexInVoter = j;
            st.adminId = adminIndices[j];
            tasks.push_back(st);
        }
    }

    // 9) parallel blindSign
    tbb::parallel_for(0, (int)tasks.size(), [&](int idx){
        const SignTask &st = tasks[idx];
        int vId = st.voterId;
        int j   = st.indexInVoter;
        int aId = st.adminId;

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

        logThreadUsage("BlindSign",
            "Voter " + std::to_string(vId+1) +
            " - Admin " + std::to_string(aId+1) +
            " sign task finished on thread " +
            std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()))
        );

        pipelineResults[vId].signatures[j] = sig;
    });

    // 10) done
    auto pipelineEnd = Clock::now();
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].timing.blind_end = pipelineEnd;
    }

    // 11) measure pipeline time
    auto pipeline_us = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();

    // show results
    long long cumulativePrep_us  = 0;
    long long cumulativeBlind_us = 0;
    for (int i = 0; i < voterCount; i++) {
        int gotCount = (int)pipelineResults[i].signatures.size();
        std::cout << "Secmen " << (i+1) << " icin " << gotCount << " adet imza alindi.\n";

        auto prep_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.prep_end -
            pipelineResults[i].timing.prep_start).count();

        auto blind_time = std::chrono::duration_cast<std::chrono::microseconds>(
            pipelineResults[i].timing.blind_end -
            pipelineResults[i].timing.blind_start).count();

        cumulativePrep_us  += prep_time;
        cumulativeBlind_us += blind_time;

        std::cout << "Voter " << (i+1)
                  << ": Prepare time = " << (prep_time / 1000.0)
                  << " ms, BlindSign time = " << (blind_time / 1000.0)
                  << " ms\n\n";
    }

    //
    // ********** UNBLIND PHASE (Alg.13) **********
    //
    auto unblindStart = std::chrono::steady_clock::now();

    std::vector<std::vector<UnblindSignature>> unblindResults(voterCount);
    tbb::parallel_for(0, voterCount, [&](int i) {
        unblindResults[i].resize(t);

        for (int j = 0; j < t; j++) {
            UnblindSignInput in;
            element_init_G1(in.comi, params.pairing);
            element_set(in.comi, preparedOutputs[i].comi);

            mpz_init(in.o);
            mpz_set(in.o, preparedOutputs[i].o);

            element_init_G1(in.h, params.pairing);
            element_set(in.h, pipelineResults[i].signatures[j].h);

            element_init_G1(in.cm, params.pairing);
            element_set(in.cm, pipelineResults[i].signatures[j].cm);

            // partial version => alpha2,beta2,beta1 from eaKeys[j]
            element_init_G2(in.alpha2, params.pairing);
            element_set(in.alpha2, keyOut.eaKeys[j].vkm1);

            element_init_G2(in.beta2, params.pairing);
            element_set(in.beta2, keyOut.eaKeys[j].vkm2);

            element_init_G1(in.beta1, params.pairing);
            element_set(in.beta1, keyOut.eaKeys[j].vkm3);

            mpz_init(in.DIDi);
            mpz_set(in.DIDi, dids[i].x);

            try {
                UnblindSignature usig = unblindSignature(params, in);
                unblindResults[i][j] = usig;
            } catch (const std::exception &ex) {
                std::cerr << "[ERROR] UnblindSignature failed for voter " << i
                          << " partialSig " << j << ": " << ex.what() << std::endl;
            }

            // cleanup
            element_clear(in.comi);
            mpz_clear(in.o);
            element_clear(in.h);
            element_clear(in.cm);
            element_clear(in.alpha2);
            element_clear(in.beta2);
            element_clear(in.beta1);
            mpz_clear(in.DIDi);
        }
    });

    auto unblindEnd = std::chrono::steady_clock::now();
    long long unblind_us = std::chrono::duration_cast<std::chrono::microseconds>(
        unblindEnd - unblindStart).count();

    //
    // ********** AGGREGATION PHASE (Alg.14) **********
    //
    // auto aggStart = std::chrono::steady_clock::now();

    // std::vector<AggregateOutput> finalSignatures(voterCount);

    // for (int i = 0; i < voterCount; i++) {
    //     // gather partial unblinded sigs => unblindResults[i][0..t-1]
    //     AggregateInput aggIn;
    //     for (int j = 0; j < t; j++) {
    //         aggIn.partials.push_back(unblindResults[i][j]);
    //     }

    //     // the MASTER public key
    //     element_init_G2(aggIn.alpha2, params.pairing);
    //     element_set(aggIn.alpha2, keyOut.mvk.alpha2);

    //     element_init_G2(aggIn.beta2, params.pairing);
    //     element_set(aggIn.beta2, keyOut.mvk.beta2);

    //     element_init_G1(aggIn.beta1, params.pairing);
    //     element_set(aggIn.beta1, keyOut.mvk.beta1);

    //     mpz_init(aggIn.DIDi);
    //     mpz_set(aggIn.DIDi, dids[i].x);

    //     AggregateOutput aggOut = aggregateSignatures(params, aggIn);
    //     finalSignatures[i] = aggOut;

    //     // cleanup
    //     element_clear(aggIn.alpha2);
    //     element_clear(aggIn.beta2);
    //     element_clear(aggIn.beta1);
    //     mpz_clear(aggIn.DIDi);
    // }

    // auto aggEnd = std::chrono::steady_clock::now();
    // long long agg_us = std::chrono::duration_cast<std::chrono::microseconds>(
    //     aggEnd - aggStart).count();

    // 12) cleanup
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

    // 13) print times
    double setup_ms    = setup_us / 1000.0;
    double pairing_ms  = pairing_us / 1000.0;
    double keygen_ms   = keygen_us / 1000.0;
    double idGen_ms    = idGen_us / 1000.0;
    double didGen_ms   = didGen_us / 1000.0;
    double pipeline_ms = pipeline_us / 1000.0;

    std::cout << "=== Zaman Olcumleri (ms) ===\n";
    std::cout << "Setup suresi       : " << setup_ms   << " ms\n";
    std::cout << "Pairing suresi     : " << pairing_ms << " ms\n";
    std::cout << "KeyGen suresi      : " << keygen_ms  << " ms\n";
    std::cout << "ID Generation      : " << idGen_ms   << " ms\n";
    std::cout << "DID Generation     : " << didGen_ms  << " ms\n";
    std::cout << "Pipeline (Prep+Blind): " << pipeline_ms << " ms\n";

    std::cout << "\nToplam hazirlama (sum) = "
              << (cumulativePrep_us / 1000.0) << " ms\n";
    std::cout << "Toplam kör imza (sum)  = "
              << (cumulativeBlind_us / 1000.0) << " ms\n";

    std::cout << "UnblindSignature total time: "
              << (unblind_us / 1000.0) << " ms\n";
    std::cout << "AggregateSignatures total time: "
              << (agg_us / 1000.0) << " ms\n";

    threadLog.close();
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
