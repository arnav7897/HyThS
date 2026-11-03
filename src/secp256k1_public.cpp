#include "hta/secp256k1_public.hpp"

#include "hta/framing.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>

#include <mcl/g1_def.hpp>

namespace hta {
namespace {
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
} // namespace

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
    mcl::Fr::add(result, a, b);
    return encode_scalar(result);
}

std::optional<PublicBytes> public_scalar_multiply(const PublicBytes &left,
                                                  const PublicBytes &right) {
    initialize();
    mcl::Fr a, b, result;
    if (!decode_scalar(left, a) || !decode_scalar(right, b))
        return std::nullopt;
    mcl::Fr::mul(result, a, b);
    return encode_scalar(result);
}

std::optional<PublicBytes> public_point_add(const PublicBytes &left, const PublicBytes &right) {
    initialize();
    mcl::G1 a, b, result;
    if (!decode_point(left, true, a) || !decode_point(right, true, b))
        return std::nullopt;
    mcl::G1::add(result, a, b);
    return encode_point(result);
}

std::optional<PublicBytes> public_point_multiply(const PublicBytes &point,
                                                 const PublicBytes &scalar) {
    initialize();
    mcl::G1 p, result;
    mcl::Fr s;
    if (!decode_point(point, true, p) || !decode_scalar(scalar, s))
        return std::nullopt;
    mcl::G1::mul(result, p, s);
    return encode_point(result);
}

std::optional<PublicBytes> public_generator_multiply(const PublicBytes &scalar) {
    static const PublicBytes generator{2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                                       0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
                                       0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
                                       0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    return public_point_multiply(generator, scalar);
}

std::optional<PublicBytes> public_msm(const std::vector<PublicBytes> &points,
                                      const std::vector<PublicBytes> &scalars) {
    if (points.size() != scalars.size())
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
    mcl::G1 result;
    mcl::G1::mulVec(result, decoded_points.data(), decoded_scalars.data(), points.size());
    return encode_point(result);
}
} // namespace hta
