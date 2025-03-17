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
#include "blindsign.h"  
#include "unblindsign.h"
#include "aggregate.h" 
#include "provecredential.h" 
#include "pairinginverify.h"
#include "checkkorverify.h"
#include "kor.h"
using Clock = std::chrono::steady_clock;

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

void my_element_dup(element_t dest, element_t src) {
    element_init_same_as(dest, src);
    element_set(dest, src);
}

int main() {
    auto programStart = Clock::now();
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

    auto startSetup = Clock::now();
    TIACParams params = setupParams();
    auto endSetup = Clock::now();
    auto setup_us = std::chrono::duration_cast<std::chrono::microseconds>(endSetup - startSetup).count();
    element_t pairingTest;
    element_init_GT(pairingTest, params.pairing);
    auto startPairing = Clock::now();
    pairing_apply(pairingTest, params.g1, params.g2, params.pairing);
    auto endPairing = Clock::now();
    auto pairing_us = std::chrono::duration_cast<std::chrono::microseconds>(endPairing - startPairing).count();
    element_clear(pairingTest);
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygen_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
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
    auto startDIDGen = Clock::now();
    std::vector<DID> dids(voterCount);
    for (int i = 0; i < voterCount; i++) {
        dids[i] = createDID(params, voterIDs[i]);
    }
    auto endDIDGen = Clock::now();
    auto didGen_us = std::chrono::duration_cast<std::chrono::microseconds>(endDIDGen - startDIDGen).count();
    std::vector<PipelineResult> pipelineResults(voterCount);
    auto pipelineStart = Clock::now();
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, 50);
    
    // 1. Prepare işlemleri için toplam süre ölçümü - başlangıç
    auto prepStart = Clock::now();
    
    // Tüm prepare işlemlerini paralel olarak yap
    std::vector<PrepareBlindSignOutput> preparedOutputs(voterCount);
    tbb::parallel_for(0, voterCount, [&](int i){
        preparedOutputs[i] = prepareBlindSign(params, dids[i].did);
    });
    
    // Prepare işlemi bitti - süre ölçümü
    auto prepEnd = Clock::now();
    auto prepTime = std::chrono::duration_cast<std::chrono::microseconds>(prepEnd - prepStart).count();
    
    // 2. Blind signing için hazırlık
    struct SignTask {
        int voterId;
        int indexInVoter;
        int adminId;
    };
    
    std::vector<SignTask> tasks;
    tasks.reserve(voterCount * t);
    std::random_device rd;
    std::mt19937 rng(rd());
    
    for (int i = 0; i < voterCount; i++) {
        pipelineResults[i].signatures.resize(t);
        
        std::vector<int> adminIndices(ne);
        std::iota(adminIndices.begin(), adminIndices.end(), 0);
        std::shuffle(adminIndices.begin(), adminIndices.end(), rng);
        
        for (int j = 0; j < t; j++) {
            SignTask st;
            st.voterId = i;
            st.indexInVoter = j;
            st.adminId = adminIndices[j]; // T farklı admin
            tasks.push_back(st);
        }
    }
    
    // BlindSign işlemleri için toplam süre ölçümü - başlangıç
    auto blindStart = Clock::now();
    
    // Tüm blind sign işlemlerini paralel olarak yap
    tbb::parallel_for(0, (int)tasks.size(), [&](int idx) {
        const SignTask &st = tasks[idx];
        int vId = st.voterId;
        int j = st.indexInVoter;
        int aId = st.adminId;
        
        mpz_t xm, ym;
        mpz_init(xm);
        mpz_init(ym);
        element_to_mpz(xm, keyOut.eaKeys[aId].sgk1);
        element_to_mpz(ym, keyOut.eaKeys[aId].sgk2);
        BlindSignature sig = blindSign(params, preparedOutputs[vId], xm, ym, aId, vId);
        mpz_clear(xm);
        mpz_clear(ym);
        pipelineResults[vId].signatures[j] = sig;
    });
    
    // BlindSign işlemi bitti - süre ölçümü
    auto blindEnd = Clock::now();
    auto blindTime = std::chrono::duration_cast<std::chrono::microseconds>(blindEnd - blindStart).count();
    
    // Toplam süre
    auto pipelineEnd = Clock::now();
    auto totalTime = std::chrono::duration_cast<std::chrono::microseconds>(pipelineEnd - pipelineStart).count();
    for (int i = 0; i < voterCount; i++) {
        for (int j = 0; j < (int)pipelineResults[i].signatures.size(); j++) {
            BlindSignature &sig = pipelineResults[i].signatures[j];
            // Original code doesn't do anything with sig here
        }
    }    

auto unblindStart = Clock::now();
std::vector<std::vector<std::pair<int, UnblindSignature>>> unblindResultsWithAdmin(voterCount);
std::vector<std::vector<UnblindSignature>> unblindResults(voterCount);
tbb::parallel_for(0, voterCount, [&](int i) {
    int numSigs = (int) pipelineResults[i].signatures.size();
    unblindResults[i].resize(numSigs);
    unblindResultsWithAdmin[i].resize(numSigs); // Alt vektörün boyutunu ayarla
    tbb::parallel_for(0, numSigs, [&](int j) {
        int adminId = pipelineResults[i].signatures[j].debug.adminId;
        UnblindSignature usig = unblindSign(params, preparedOutputs[i], pipelineResults[i].signatures[j], keyOut.eaKeys[adminId], dids[i].did);
        unblindResults[i][j] = usig;
        unblindResultsWithAdmin[i][j] = {adminId, usig}; // Admin ID'si ile birlikte sakla
    });
});

auto unblindEnd = Clock::now();
auto unblind_us = std::chrono::duration_cast<std::chrono::microseconds>(unblindEnd - unblindStart).count();

for (int i = 0; i < voterCount; i++) {
    for (int j = 0; j < (int)unblindResultsWithAdmin[i].size(); j++) {
        int adminId = unblindResultsWithAdmin[i][j].first; // Admin ID'sini al
        UnblindSignature &usig = unblindResultsWithAdmin[i][j].second; // İlgili imzayı al
    }
}

std::vector<AggregateSignature> aggregateResults(voterCount);
auto aggregateStart = Clock::now();
tbb::parallel_for(0, voterCount, [&](int i) {
    AggregateSignature aggSig = aggregateSign(params, unblindResultsWithAdmin[i], keyOut.mvk, dids[i].did, params.prime_order);
    aggregateResults[i] = aggSig;
});
auto aggregateEnd = Clock::now();
auto aggregate_us = std::chrono::duration_cast<std::chrono::microseconds>(aggregateEnd - aggregateStart).count();

std::vector<ProveCredentialOutput> proveResults(voterCount);
auto proveStart = Clock::now();
tbb::parallel_for(0, voterCount, [&](int i) {
    ProveCredentialOutput pOut = proveCredential(params, aggregateResults[i], keyOut.mvk, dids[i].did, preparedOutputs[i].o);
    proveResults[i] = pOut;
});
auto proveEnd = Clock::now();
auto prove_us = std::chrono::duration_cast<std::chrono::microseconds>(proveEnd - proveStart).count();
auto korStart = Clock::now();
tbb::parallel_for(tbb::blocked_range<int>(0, voterCount),
    [&](const tbb::blocked_range<int>& r) {
        for (int i = r.begin(); i != r.end(); ++i) {
            mpz_t did_int;
            mpz_init(did_int);
            mpz_set_str(did_int, dids[i].did.c_str(), 16);
            mpz_mod(did_int, did_int, params.prime_order);
            element_t com_elem;
            element_init_G1(com_elem, params.pairing);
            try {
                stringToElement(com_elem, preparedOutputs[i].debug.com, params.pairing, 1); // 1 for G1
            } catch (const std::exception& e) {
                std::cerr << "Error converting com string to element: " << e.what() << std::endl;
                element_random(com_elem);
            }
            KnowledgeOfRepProof korProof = generateKoRProof(
                params,
                aggregateResults[i].h,
                proveResults[i].k,
                proveResults[i].r,
                com_elem,
                keyOut.mvk.alpha2,
                keyOut.mvk.beta2,
                did_int,
                preparedOutputs[i].o
            );
            element_set(proveResults[i].c, korProof.c);
            element_set(proveResults[i].s1, korProof.s1);
            element_set(proveResults[i].s2, korProof.s2);
            element_set(proveResults[i].s3, korProof.s3);
            proveResults[i].proof_v = korProof.proof_string;
            element_clear(com_elem);
            element_clear(korProof.c);
            element_clear(korProof.s1);
            element_clear(korProof.s2);
            element_clear(korProof.s3);
            mpz_clear(did_int);
        }
    }
);
auto korEnd = Clock::now();
auto kor_us = std::chrono::duration_cast<std::chrono::microseconds>(korEnd - korStart).count();
auto totalVerStart = Clock::now();
std::atomic<bool> allVerified(true);
std::atomic<uint64_t> totalPairing_us(0);
std::atomic<uint64_t> totalKorVer_us(0);
tbb::parallel_for(tbb::blocked_range<int>(0, voterCount),
    [&](const tbb::blocked_range<int>& r) {
        for (int i = r.begin(); i != r.end(); ++i) {
            auto pairingStart = Clock::now();
            bool pairing_ok = pairingCheck(params, proveResults[i]);
            auto pairingEnd = Clock::now();
            auto pairing_us = std::chrono::duration_cast<std::chrono::microseconds>(pairingEnd - pairingStart).count();
            totalPairing_us += pairing_us;
            auto korVerStart = Clock::now();
            bool kor_ok = checkKoRVerify(
                params,
                proveResults[i],
                keyOut.mvk,
                preparedOutputs[i].debug.com,
                aggregateResults[i].h
            );
            auto korVerEnd = Clock::now();
            auto korVer_us = std::chrono::duration_cast<std::chrono::microseconds>(korVerEnd - korVerStart).count();
            totalKorVer_us += korVer_us;
            bool verified = pairing_ok && kor_ok;
            if (!verified) {
                allVerified.store(false);
            }
        }
    }
);
auto totalVerEnd = Clock::now();
auto totalVer_us = std::chrono::duration_cast<std::chrono::microseconds>(totalVerEnd - totalVerStart).count();
if (!allVerified.load()) {
    throw std::runtime_error("Verification failed: pairing check or KoR verification returned false");
}
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
    auto totalDuration = std::chrono::duration_cast<std::chrono::microseconds>(programEnd - programStart).count();
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
    std::cout << "Total prepare time: " << prepTime << " microseconds" << std::endl;
    std::cout << "Total blind sign time: " << blindTime << " microseconds" << std::endl;
    std::cout << "\n[UNBLIND] Total Unblind Phase Time = " << (unblind_us / 1000.0) << " ms\n";
    std::cout << "\n[AGGREGATE] Total Aggregate Phase Time = " << (aggregate_us / 1000.0) << " ms\n";
    std::cout << "\n[PROVE] Total ProveCredential (without KOR) Phase Time = " << (prove_us / 1000.0) << " ms\n";
    std::cout << "\n[KOR] Total Knowledge of Representation Phase Time = " << (kor_us / 1000.0) << " ms\n";
    std::cout << "\n[PAIRING] Total Pairing Check Time = " << (totalPairing_us / 1000.0) << " ms\n";
    std::cout << "\n[KOR VERIFY] Total Knowledge of Representation Verification Time = " << (totalKorVer_us / 1000.0) << " ms\n";
    std::cout << "\n[VERIFICATION] Total Verification (Pairing + KoR) Time = " << (totalVer_us / 1000.0) << " ms\n";
    std::cout << "Total execution time: " << (totalDuration / 1000.0) << " ms\n";
    std::cout << "\n=== Program Sonu ===\n";
    return 0;
}
