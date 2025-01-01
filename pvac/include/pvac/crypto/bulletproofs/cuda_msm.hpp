#pragma once
/**
 * CUDA MSM (Multi-Scalar Multiplication) dispatch layer.
 *
 * When PVAC_USE_CUDA_MSM is defined at compile time, multi_scalar_mul
 * calls are forwarded to a GPU implementation based on a cuZK-style
 * Pippenger algorithm.
 *
 * Runtime control:
 *   pvac::bp::cuda_msm_set_enabled(true/false)  — toggle at runtime
 *   pvac::bp::cuda_msm_is_enabled()             — query current state
 *
 * The CUDA implementation must be linked separately (cuda_msm.cu compiled
 * with nvcc). When PVAC_USE_CUDA_MSM is not defined, the functions are
 * stubs that always fall back to the CPU path.
 *
 * Type bridge:
 *   Our Scalar (4×u64, 256-bit mod L) maps to cuZK's FieldT via
 *   raw byte serialization (sc_tobytes → 32 bytes little-endian).
 *
 *   Our RistrettoPoint (32 bytes compressed) is decoded to ExtPoint
 *   (extended twisted Edwards: X,Y,Z,T as Fe25519) for arithmetic.
 *   The GPU kernels operate on an equivalent extended-coordinate
 *   representation. Points are transferred as decoded coordinates
 *   (4×5×u64 = 160 bytes per point) to avoid decode overhead on GPU.
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>

#include "../ristretto255.hpp"

namespace pvac {
namespace bp {

// ─────────────────────────────────────────────────────────────────────
// Runtime enable/disable
// ─────────────────────────────────────────────────────────────────────

namespace detail {
    inline std::atomic<bool>& cuda_msm_flag() {
        static std::atomic<bool> flag{false};
        return flag;
    }
    inline size_t& cuda_msm_total_calls()  { static size_t v=0; return v; }
    inline size_t& cuda_msm_total_points() { static size_t v=0; return v; }
    inline double& cuda_msm_total_prep()   { static double v=0; return v; }
    inline double& cuda_msm_total_gpu()    { static double v=0; return v; }
}

inline void cuda_msm_set_enabled(bool enabled) {
    detail::cuda_msm_flag().store(enabled, std::memory_order_relaxed);
}

inline bool cuda_msm_is_enabled() {
    return detail::cuda_msm_flag().load(std::memory_order_relaxed);
}

// ─────────────────────────────────────────────────────────────────────
// GPU point representation (extended twisted Edwards, unpacked)
// Laid out for coalesced GPU memory access.
// ─────────────────────────────────────────────────────────────────────

struct alignas(8) GpuExtPoint {
    uint64_t X[5];  // Fe25519 limbs
    uint64_t Y[5];
    uint64_t Z[5];
    uint64_t T[5];
};

static_assert(sizeof(GpuExtPoint) == 160, "GpuExtPoint must be 160 bytes");

// ─────────────────────────────────────────────────────────────────────
// Conversion helpers (host side)
// ─────────────────────────────────────────────────────────────────────

inline GpuExtPoint to_gpu_point(const ExtPoint& p) {
    GpuExtPoint g;
    for (int i = 0; i < 5; i++) {
        g.X[i] = p.X.v[i];
        g.Y[i] = p.Y.v[i];
        g.Z[i] = p.Z.v[i];
        g.T[i] = p.T.v[i];
    }
    return g;
}

inline ExtPoint from_gpu_point(const GpuExtPoint& g) {
    ExtPoint p;
    for (int i = 0; i < 5; i++) {
        p.X.v[i] = g.X[i];
        p.Y.v[i] = g.Y[i];
        p.Z.v[i] = g.Z[i];
        p.T.v[i] = g.T[i];
    }
    return p;
}

// ─────────────────────────────────────────────────────────────────────
// CUDA kernel interface (implemented in cuda_msm.cu)
// ─────────────────────────────────────────────────────────────────────

#ifdef PVAC_USE_CUDA_MSM

/**
 * Perform MSM on GPU using cuZK-style Pippenger.
 *
 * @param points   Array of decoded extended-coordinate points (host memory)
 * @param scalars  Array of 32-byte little-endian scalars (host memory)
 * @param n        Number of (point, scalar) pairs
 * @param result   Output: single accumulated point
 * @return true on success, false on GPU error (caller falls back to CPU)
 *
 * Implemented in cuda_msm.cu — link with nvcc.
 */
extern bool cuda_msm_compute(
    const GpuExtPoint* points,
    const uint8_t (*scalars)[32],
    size_t n,
    GpuExtPoint* result
);

#else

// Stub: always returns false → caller uses CPU Pippenger
inline bool cuda_msm_compute(
    const GpuExtPoint* /*points*/,
    const uint8_t (*/*scalars*/)[32],
    size_t /*n*/,
    GpuExtPoint* /*result*/
) {
    return false;
}

#endif // PVAC_USE_CUDA_MSM

// ─────────────────────────────────────────────────────────────────────
// High-level dispatch: try GPU, fall back to CPU
// Called from multi_scalar_mul when cuda_msm_is_enabled() == true.
// ─────────────────────────────────────────────────────────────────────

inline bool try_cuda_msm(
    const std::vector<Scalar>& scalars,
    const std::vector<RistrettoPoint>& points,
    RistrettoPoint& result_out
) {
    using clock = std::chrono::high_resolution_clock;
    size_t n = scalars.size();
    if (n == 0) return false;

    // Minimum batch size to justify GPU transfer overhead
    if (n < 64) return false;

    auto t0 = clock::now();

    // Decode points to extended coordinates for GPU
    std::vector<GpuExtPoint> gpu_pts(n);
    for (size_t i = 0; i < n; i++) {
        ExtPoint ep;
        rist_decode(ep, points[i]);
        gpu_pts[i] = to_gpu_point(ep);
    }

    // Serialize scalars to 32-byte arrays
    std::vector<std::array<uint8_t, 32>> scalar_bytes(n);
    for (size_t i = 0; i < n; i++)
        sc_tobytes(scalar_bytes[i].data(), scalars[i]);

    auto t1 = clock::now();

    GpuExtPoint gpu_result;
    bool ok = cuda_msm_compute(
        gpu_pts.data(),
        reinterpret_cast<const uint8_t(*)[32]>(scalar_bytes.data()),
        n,
        &gpu_result
    );

    auto t2 = clock::now();

    if (!ok) return false;

    ExtPoint ep = from_gpu_point(gpu_result);
    result_out = rist_encode(ep);

    auto t3 = clock::now();

    double prep_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double gpu_ms  = std::chrono::duration<double, std::milli>(t2 - t1).count();
    double post_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    detail::cuda_msm_total_calls()++;
    detail::cuda_msm_total_points() += n;
    detail::cuda_msm_total_prep() += prep_ms;
    detail::cuda_msm_total_gpu() += gpu_ms;

    return true;
}

inline void cuda_msm_print_stats() {
    fprintf(stderr, "[cuda_msm] SUMMARY: %zu calls, %zu total points, "
            "prep=%.1fms, gpu=%.1fms, combined=%.1fms\n",
            detail::cuda_msm_total_calls(), detail::cuda_msm_total_points(),
            detail::cuda_msm_total_prep(), detail::cuda_msm_total_gpu(),
            detail::cuda_msm_total_prep() + detail::cuda_msm_total_gpu());
}

}  // namespace bp
}  // namespace pvac
