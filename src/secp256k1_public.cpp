#include "hta/secp256k1_public.hpp"
#include "hta/operation_counters.hpp"

#include "hta/framing.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <stdexcept>

#include <mcl/g1_def.hpp>
#ifdef HTA_PUBLIC_FIXED_BASE
#include <mcl/window_method.hpp>
#endif

namespace hta {
namespace {
#ifdef HTA_OPCOUNTERS
struct AtomicCounters {
    std::atomic<std::uint64_t> scalar_add{0}, scalar_multiply{0}, point_add{0};
    std::atomic<std::uint64_t> variable_multiply{0}, generator_multiply{0}, msm{0}, msm_bases{0};
};
AtomicCounters counters;
#define HTA_INCREMENT(name, amount) counters.name.fetch_add((amount), std::memory_order_relaxed)
#else
#define HTA_INCREMENT(name, amount) ((void)0)
#endif

void initialize() {
    static std::once_flag once;
    std::call_once(once, [] { mcl::initCurve<mcl::G1>(MCL_SECP256K1); });
}

bool decode_scalar(const PublicBytes &bytes, mcl::Fr &out) {
    if (!is_canonical_scalar(bytes))
        return false;
    PublicBytes little(bytes.rbegin(), bytes.rend());
    return out.deserialize(little.data(), little.size()) == little.size();
}

PublicBytes encode_scalar(const mcl::Fr &value) {
    PublicBytes little(32);
    if (value.serialize(little.data(), little.size()) != little.size())
        throw std::runtime_error("mcl scalar serialization failed");
    return PublicBytes(little.rbegin(), little.rend());
}

PublicBytes encode_point(const mcl::G1 &point) {
    if (point.isZero())
        return {0};
    std::array<std::uint8_t, 33> little{};
    if (point.serialize(little.data(), little.size()) != little.size())
        throw std::runtime_error("mcl point serialization failed");
    PublicBytes result{little[0]};
    result.insert(result.end(), little.rbegin(), little.rend() - 1);
    return result;
}

bool decode_point(const PublicBytes &bytes, bool allow_identity, mcl::G1 &out) {
    if (bytes == PublicBytes{0}) {
        if (!allow_identity)
            return false;
        out.clear();
        return true;
    }
    if (bytes.size() != 33 || (bytes[0] != 2 && bytes[0] != 3))
        return false;
    std::array<std::uint8_t, 33> little{};
    little[0] = bytes[0];
    std::reverse_copy(bytes.begin() + 1, bytes.end(), little.begin() + 1);
    return out.deserialize(little.data(), little.size()) == little.size() && !out.isZero() &&
           out.isValid() && encode_point(out) == bytes;
}

std::optional<PublicBytes> multiply_encoded_point(const PublicBytes &point,
                                                  const PublicBytes &scalar, bool generator) {
    initialize();
    mcl::G1 p, result;
    mcl::Fr s;
    if (!decode_point(point, true, p) || !decode_scalar(scalar, s))
        return std::nullopt;
    if (generator)
        HTA_INCREMENT(generator_multiply, 1);
    else
        HTA_INCREMENT(variable_multiply, 1);
    mcl::G1::mul(result, p, s);
    return encode_point(result);
}
} // namespace

void reset_operation_counters() noexcept {
#ifdef HTA_OPCOUNTERS
    counters.scalar_add.store(0, std::memory_order_relaxed);
    counters.scalar_multiply.store(0, std::memory_order_relaxed);
    counters.point_add.store(0, std::memory_order_relaxed);
    counters.variable_multiply.store(0, std::memory_order_relaxed);
    counters.generator_multiply.store(0, std::memory_order_relaxed);
    counters.msm.store(0, std::memory_order_relaxed);
    counters.msm_bases.store(0, std::memory_order_relaxed);
#endif
}

OperationCounters operation_counters_snapshot() noexcept {
    OperationCounters result;
#ifdef HTA_OPCOUNTERS
    result.scalar_add_calls = counters.scalar_add.load(std::memory_order_relaxed);
    result.scalar_multiply_calls = counters.scalar_multiply.load(std::memory_order_relaxed);
    result.point_add_calls = counters.point_add.load(std::memory_order_relaxed);
    result.variable_point_multiply_calls =
        counters.variable_multiply.load(std::memory_order_relaxed);
    result.generator_multiply_calls = counters.generator_multiply.load(std::memory_order_relaxed);
    result.msm_calls = counters.msm.load(std::memory_order_relaxed);
    result.msm_bases = counters.msm_bases.load(std::memory_order_relaxed);
#endif
    return result;
}

bool valid_public_scalar(const PublicBytes &encoded) noexcept {
    return is_canonical_scalar(encoded);
}

bool valid_public_point(const PublicBytes &encoded, bool allow_identity) {
    initialize();
    mcl::G1 point;
    return decode_point(encoded, allow_identity, point);
}

std::optional<PublicBytes> public_scalar_add(const PublicBytes &left, const PublicBytes &right) {
    initialize();
    mcl::Fr a, b, result;
    if (!decode_scalar(left, a) || !decode_scalar(right, b))
        return std::nullopt;
    HTA_INCREMENT(scalar_add, 1);
    mcl::Fr::add(result, a, b);
    return encode_scalar(result);
}

std::optional<PublicBytes> public_scalar_subtract(const PublicBytes &left,
                                                  const PublicBytes &right) {
    initialize();
    mcl::Fr a, b, result;
    if (!decode_scalar(left, a) || !decode_scalar(right, b))
        return std::nullopt;
    HTA_INCREMENT(scalar_add, 1);
    mcl::Fr::sub(result, a, b);
    return encode_scalar(result);
}

std::optional<PublicBytes> public_scalar_multiply(const PublicBytes &left,
                                                  const PublicBytes &right) {
    initialize();
    mcl::Fr a, b, result;
    if (!decode_scalar(left, a) || !decode_scalar(right, b))
        return std::nullopt;
    HTA_INCREMENT(scalar_multiply, 1);
    mcl::Fr::mul(result, a, b);
    return encode_scalar(result);
}

std::optional<PublicBytes> public_point_add(const PublicBytes &left, const PublicBytes &right) {
    initialize();
    mcl::G1 a, b, result;
    if (!decode_point(left, true, a) || !decode_point(right, true, b))
        return std::nullopt;
    HTA_INCREMENT(point_add, 1);
    mcl::G1::add(result, a, b);
    return encode_point(result);
}

std::optional<PublicBytes> public_point_multiply(const PublicBytes &point,
                                                 const PublicBytes &scalar) {
    return multiply_encoded_point(point, scalar, false);
}

std::optional<PublicBytes> public_generator_multiply(const PublicBytes &scalar) {
    static const PublicBytes generator{2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                                       0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
                                       0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
                                       0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
#ifdef HTA_PUBLIC_FIXED_BASE
    initialize();
    mcl::Fr s;
    if (!decode_scalar(scalar, s))
        return std::nullopt;
    struct GeneratorTable {
        mcl::fp::WindowMethod<mcl::G1> table;
        explicit GeneratorTable(const PublicBytes &encoded) {
            mcl::G1 point;
            if (!decode_point(encoded, false, point))
                throw std::runtime_error("invalid generator");
            table.init(point, 256, 4);
        }
    };
    static const GeneratorTable fixed(generator);
    mcl::G1 result;
    HTA_INCREMENT(generator_multiply, 1);
    fixed.table.mul(result, s);
    return encode_point(result);
#else
    return multiply_encoded_point(generator, scalar, true);
#endif
}

std::optional<PublicBytes> public_msm(const std::vector<PublicBytes> &points,
                                      const std::vector<PublicBytes> &scalars) {
    return public_msm_with_bucket(points, scalars, 0);
}

std::optional<PublicBytes> public_msm_with_bucket(const std::vector<PublicBytes> &points,
                                                  const std::vector<PublicBytes> &scalars,
                                                  std::size_t bucket) {
    if (points.size() != scalars.size())
        return std::nullopt;
    if (bucket != 0 && (bucket < 2 || bucket > 12))
        return std::nullopt;
    initialize();
    if (points.empty())
        return PublicBytes{0};
    std::vector<mcl::G1> decoded_points(points.size());
    std::vector<mcl::Fr> decoded_scalars(scalars.size());
    for (std::size_t i = 0; i < points.size(); ++i) {
        if (!decode_point(points[i], true, decoded_points[i]) ||
            !decode_scalar(scalars[i], decoded_scalars[i]))
            return std::nullopt;
    }
    HTA_INCREMENT(msm, 1);
    HTA_INCREMENT(msm_bases, points.size());
    mcl::G1 result;
    mcl::G1::mulVec(result, decoded_points.data(), decoded_scalars.data(), points.size(), bucket);
    return encode_point(result);
}
} // namespace hta
