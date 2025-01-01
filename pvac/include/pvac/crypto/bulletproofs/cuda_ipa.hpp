#pragma once
/**
 * GPU Inner Product Argument (IPA) — uses blitzar's dual-generator
 * GPU driver for on-device MSMs and generator folding.
 *
 * Round-by-round API: blitzar computes L/R and folds on GPU,
 * we handle transcript interaction on CPU.
 *
 * Optimization: base generators G and H are decoded once and cached as
 * ExtPoints. H_prime = H[i] * y_inv[i] is computed from the cached
 * ExtPoints via ext_scalarmul (no rist_decode on the hot path).
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <cstdio>
#include <chrono>
#include <mutex>
#include <atomic>
#include "cuda_msm.hpp"  // GpuExtPoint, to_gpu_point, from_gpu_point
#include "../ristretto255.hpp"
#include "generators.hpp"
#include "transcript.hpp"
#include "inner_product.hpp"  // InnerProductProof

namespace pvac {
namespace bp {

// ─────────────────────────────────────────────────────────────────────
// Blitzar dual-gen IPA C API (from libblitzar.so)
// ─────────────────────────────────────────────────────────────────────

// Must match blitzar's cbindings types (binary-compatible)
struct sxt_ristretto255_t { uint64_t X[5], Y[5], Z[5], T[5]; };
struct sxt_ristretto255_compressed_t { uint8_t ristretto_bytes[32]; };
struct sxt_curve25519_scalar_t { uint8_t bytes[32]; };
struct sxt_ipa_dual_workspace_t;

#ifdef PVAC_USE_BLITZAR_IPA

extern "C" {
sxt_ipa_dual_workspace_t* sxt_ipa_dual_new(
    uint64_t n,
    const sxt_ristretto255_t* g_vector,
    const sxt_ristretto255_t* h_vector,
    const sxt_ristretto255_t* q_value,
    const sxt_curve25519_scalar_t* a_vector,
    const sxt_curve25519_scalar_t* b_vector);

void sxt_ipa_dual_commit(
    sxt_ristretto255_compressed_t* l_out,
    sxt_ristretto255_compressed_t* r_out,
    sxt_ipa_dual_workspace_t* workspace);

void sxt_ipa_dual_fold(
    sxt_ipa_dual_workspace_t* workspace,
    const sxt_curve25519_scalar_t* x);

void sxt_ipa_dual_final(
    sxt_curve25519_scalar_t* a_out,
    sxt_curve25519_scalar_t* b_out,
    const sxt_ipa_dual_workspace_t* workspace);

void sxt_ipa_dual_free(sxt_ipa_dual_workspace_t* workspace);

// Single-shot prove with raw 64-byte transcript state (no round-trip sync)
void sxt_ipa_dual_prove_state(
    sxt_ristretto255_compressed_t* l_vector,
    sxt_ristretto255_compressed_t* r_vector,
    sxt_curve25519_scalar_t* ap_value,
    sxt_curve25519_scalar_t* bp_value,
    const uint8_t* transcript_state,
    uint64_t n,
    const sxt_ristretto255_t* g_vector,
    const sxt_ristretto255_t* h_vector,
    const sxt_ristretto255_t* q_value,
    const sxt_curve25519_scalar_t* a_vector,
    const sxt_curve25519_scalar_t* b_vector);
}

#endif // PVAC_USE_BLITZAR_IPA

// ─────────────────────────────────────────────────────────────────────
// Single-GPU scheduling: blocking lock so final IPAs queue for GPU,
// freeing CPU cores for concurrent bit-proofs from other range proofs.
// ─────────────────────────────────────────────────────────────────────

#ifdef PVAC_USE_BLITZAR_IPA
inline std::mutex& gpu_mutex() {
    static std::mutex mtx;
    return mtx;
}
#endif

// ─────────────────────────────────────────────────────────────────────
// Generator cache: decode base G and H once, reuse across all IPA calls.
// Keyed by size (generators are deterministic from hash, so same size =
// same generators). Grows monotonically — never shrinks.
// ─────────────────────────────────────────────────────────────────────

struct GpuGenCache {
    // Pre-decoded base generators as ExtPoints (for computing H_prime)
    std::vector<ExtPoint> G_ext;
    std::vector<ExtPoint> H_ext;
    // Pre-converted G in GPU format (G never changes, so store final form)
    std::vector<sxt_ristretto255_t> G_sxt;
    std::mutex cache_mtx;

    void ensure_size(size_t n) {
        if (G_ext.size() >= n) {
            return;  // Fast path: already big enough
        }
        std::lock_guard<std::mutex> lock(cache_mtx);
        if (G_ext.size() >= n) return;  // Double-check after acquiring lock
        size_t old = G_ext.size();
        G_ext.resize(n);
        H_ext.resize(n);
        G_sxt.resize(n);
        const auto& gt = generators();
        for (size_t i = old; i < n; i++) {
            rist_decode(G_ext[i], gt.G(i));
            rist_decode(H_ext[i], gt.H(i));
            GpuExtPoint gp = to_gpu_point(G_ext[i]);
            std::memcpy(&G_sxt[i], &gp, sizeof(sxt_ristretto255_t));
        }
    }
};

inline GpuGenCache& gpu_gen_cache() {
    static GpuGenCache cache;
    return cache;
}

// ─────────────────────────────────────────────────────────────────────
// High-level wrapper: accepts base H + y_inv scalars to avoid decode
// Uses try_lock to avoid GPU contention — if all GPUs busy, returns
// false so caller uses CPU fallback.
// ─────────────────────────────────────────────────────────────────────

inline bool try_gpu_ipp_prove(
    Transcript& transcript,
    const RistrettoPoint& Q,
    const std::vector<Scalar>& a,
    const std::vector<Scalar>& b,
    const std::vector<Scalar>& y_inv_n,  // y_inv powers: H_prime[i] = H[i]*y_inv_n[i]
    size_t N,
    InnerProductProof& proof_out
) {
#ifndef PVAC_USE_BLITZAR_IPA
    return false;
#else
    if (N == 0 || (N & (N - 1)) != 0) return false;
    if (N < 16384) return false;  // GPU only wins for large N (launch overhead dominates below this)

    // Block until GPU is available — keeps CPU cores free for other proofs' bit-proofs
    std::unique_lock<std::mutex> gpu_lock(gpu_mutex());

    static std::atomic<int> ipa_call_count{0};
    static auto first_call_time = std::chrono::steady_clock::now();
    auto call_start = std::chrono::steady_clock::now();

    size_t lg = 0;
    { size_t tmp = N; while (tmp >>= 1) lg++; }

    // Ensure base generators are decoded and cached (thread-safe: grow-only)
    auto& cache = gpu_gen_cache();
    cache.ensure_size(N);

    auto t_hprime_start = std::chrono::steady_clock::now();

    // Compute H_prime in GPU format from cached ExtPoints (NO rist_decode)
    // OpenMP parallelized — this is the CPU-side bottleneck
    std::vector<sxt_ristretto255_t> H_prime_sxt(N);
    #pragma omp parallel for schedule(static)
    for (size_t i = 0; i < N; i++) {
        ExtPoint hp = ext_scalarmul(cache.H_ext[i], y_inv_n[i]);
        GpuExtPoint gp = to_gpu_point(hp);
        std::memcpy(&H_prime_sxt[i], &gp, sizeof(sxt_ristretto255_t));
    }

    auto t_hprime_end = std::chrono::steady_clock::now();

    // Decode Q (just 1 point, negligible)
    sxt_ristretto255_t Q_sxt;
    {
        ExtPoint ep; rist_decode(ep, Q);
        GpuExtPoint gp = to_gpu_point(ep);
        std::memcpy(&Q_sxt, &gp, sizeof(sxt_ristretto255_t));
    }

    // Serialize scalars
    std::vector<sxt_curve25519_scalar_t> a_bytes(N), b_bytes(N);
    for (size_t i = 0; i < N; i++) {
        sc_tobytes(a_bytes[i].bytes, a[i]);
        sc_tobytes(b_bytes[i].bytes, b[i]);
    }

    auto t_gpu_start = std::chrono::steady_clock::now();

    // Create GPU workspace with cached G and freshly-computed H_prime
    auto* ws = sxt_ipa_dual_new(N, cache.G_sxt.data(), H_prime_sxt.data(), &Q_sxt,
                                a_bytes.data(), b_bytes.data());
    if (!ws) { return false; }

    // Round-by-round proving with our transcript
    proof_out.L.resize(lg);
    proof_out.R.resize(lg);

    for (size_t k = 0; k < lg; k++) {
        sxt_ristretto255_compressed_t l_c, r_c;
        sxt_ipa_dual_commit(&l_c, &r_c, ws);

        std::memcpy(proof_out.L[k].data(), l_c.ristretto_bytes, 32);
        std::memcpy(proof_out.R[k].data(), r_c.ristretto_bytes, 32);

        transcript.append_point("L", proof_out.L[k]);
        transcript.append_point("R", proof_out.R[k]);
        Scalar u_k = transcript.challenge_scalar("u");

        sxt_curve25519_scalar_t x_bytes;
        sc_tobytes(x_bytes.bytes, u_k);
        sxt_ipa_dual_fold(ws, &x_bytes);
    }

    // Extract final scalars
    sxt_curve25519_scalar_t a_final, b_final;
    sxt_ipa_dual_final(&a_final, &b_final, ws);
    proof_out.a = sc_from_bytes(a_final.bytes);
    proof_out.b = sc_from_bytes(b_final.bytes);

    sxt_ipa_dual_free(ws);

    int count = ++ipa_call_count;
    auto call_end = std::chrono::steady_clock::now();
    double hprime_ms = std::chrono::duration<double, std::milli>(t_hprime_end - t_hprime_start).count();
    double gpu_ms = std::chrono::duration<double, std::milli>(call_end - t_gpu_start).count();
    double call_ms = std::chrono::duration<double, std::milli>(call_end - call_start).count();
    double total_ms = std::chrono::duration<double, std::milli>(call_end - first_call_time).count();
    printf("  [GPU IPA #%d] n=%zu, %.0fms (H_prime=%.0fms, GPU=%.0fms) total %.1fs\n",
           count, N, call_ms, hprime_ms, gpu_ms, total_ms / 1000.0);
    fflush(stdout);

    return true;
#endif
}

// Legacy interface (decodes all points — slow, for compatibility)
inline bool try_gpu_ipp_prove(
    Transcript& transcript,
    const RistrettoPoint& Q,
    const std::vector<Scalar>& a,
    const std::vector<Scalar>& b,
    const std::vector<RistrettoPoint>& G_vec,
    const std::vector<RistrettoPoint>& H_vec,
    InnerProductProof& proof_out
) {
#ifndef PVAC_USE_BLITZAR_IPA
    return false;
#else
    size_t n = a.size();
    if (n == 0 || (n & (n - 1)) != 0) return false;
    if (n < 4) return false;

    size_t lg = 0;
    { size_t tmp = n; while (tmp >>= 1) lg++; }

    // Decode all points (expensive — use the y_inv overload when possible)
    std::vector<sxt_ristretto255_t> G_sxt(n), H_sxt(n);
    sxt_ristretto255_t Q_sxt;
    for (size_t i = 0; i < n; i++) {
        ExtPoint ep; rist_decode(ep, G_vec[i]);
        GpuExtPoint gp = to_gpu_point(ep);
        std::memcpy(&G_sxt[i], &gp, sizeof(sxt_ristretto255_t));
    }
    for (size_t i = 0; i < n; i++) {
        ExtPoint ep; rist_decode(ep, H_vec[i]);
        GpuExtPoint gp = to_gpu_point(ep);
        std::memcpy(&H_sxt[i], &gp, sizeof(sxt_ristretto255_t));
    }
    {
        ExtPoint ep; rist_decode(ep, Q);
        GpuExtPoint gp = to_gpu_point(ep);
        std::memcpy(&Q_sxt, &gp, sizeof(sxt_ristretto255_t));
    }

    std::vector<sxt_curve25519_scalar_t> a_bytes(n), b_bytes(n);
    for (size_t i = 0; i < n; i++) {
        sc_tobytes(a_bytes[i].bytes, a[i]);
        sc_tobytes(b_bytes[i].bytes, b[i]);
    }

    auto* ws = sxt_ipa_dual_new(n, G_sxt.data(), H_sxt.data(), &Q_sxt,
                                a_bytes.data(), b_bytes.data());
    if (!ws) return false;

    proof_out.L.resize(lg);
    proof_out.R.resize(lg);

    for (size_t k = 0; k < lg; k++) {
        sxt_ristretto255_compressed_t l_c, r_c;
        sxt_ipa_dual_commit(&l_c, &r_c, ws);

        std::memcpy(proof_out.L[k].data(), l_c.ristretto_bytes, 32);
        std::memcpy(proof_out.R[k].data(), r_c.ristretto_bytes, 32);

        transcript.append_point("L", proof_out.L[k]);
        transcript.append_point("R", proof_out.R[k]);
        Scalar u_k = transcript.challenge_scalar("u");

        sxt_curve25519_scalar_t x_bytes;
        sc_tobytes(x_bytes.bytes, u_k);
        sxt_ipa_dual_fold(ws, &x_bytes);
    }

    sxt_curve25519_scalar_t a_final, b_final;
    sxt_ipa_dual_final(&a_final, &b_final, ws);
    proof_out.a = sc_from_bytes(a_final.bytes);
    proof_out.b = sc_from_bytes(b_final.bytes);

    sxt_ipa_dual_free(ws);
    return true;
#endif
}

}  // namespace bp
}  // namespace pvac
