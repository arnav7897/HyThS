#include "hta/secret_group.hpp"

#include "hta/framing.hpp"
#include "hta/secp256k1_public.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>

#include <openssl/crypto.h>

#include <mcl/g1_def.hpp>

namespace hta {
namespace {
void initialize() {
    static std::once_flag once;
    std::call_once(once, [] { mcl::initCurve<mcl::G1>(MCL_SECP256K1); });
}

bool decode_secret(const SecretScalar &encoded, mcl::Fr &result) {
    if (!encoded.valid(false))
        return false;
    std::array<std::uint8_t, 32> little{};
    std::reverse_copy(encoded.bytes().begin(), encoded.bytes().end(), little.begin());
    const bool valid = result.deserialize(little.data(), little.size()) == little.size();
    OPENSSL_cleanse(little.data(), little.size());
    return valid;
}

std::array<std::uint8_t, 32> encode_secret(const mcl::Fr &value) {
    std::array<std::uint8_t, 32> little{};
    std::array<std::uint8_t, 32> big{};
    if (value.serialize(little.data(), little.size()) != little.size())
        throw std::runtime_error("mcl secret scalar serialization failed");
    std::reverse_copy(little.begin(), little.end(), big.begin());
    OPENSSL_cleanse(little.data(), little.size());
    return big;
}

bool decode_public_point(const std::vector<std::uint8_t> &encoded, mcl::G1 &point) {
    if (!valid_public_point(encoded, true))
        return false;
    if (encoded == std::vector<std::uint8_t>{0}) {
        point.clear();
        return true;
    }
    if (encoded.size() != 33 || (encoded[0] != 2 && encoded[0] != 3))
        return false;
    std::array<std::uint8_t, 33> little{};
    little[0] = encoded[0];
    std::reverse_copy(encoded.begin() + 1, encoded.end(), little.begin() + 1);
    return point.deserialize(little.data(), little.size()) == little.size() && !point.isZero() &&
           point.isValid();
}

std::vector<std::uint8_t> encode_public_point(const mcl::G1 &point) {
    if (point.isZero())
        return {0};
    std::array<std::uint8_t, 33> little{};
    if (point.serialize(little.data(), little.size()) != little.size())
        throw std::runtime_error("mcl point serialization failed");
    std::vector<std::uint8_t> result{little[0]};
    result.insert(result.end(), little.rbegin(), little.rend() - 1);
    return result;
}

std::vector<std::uint8_t> multiply(const std::vector<std::uint8_t> &point,
                                   const SecretScalar &scalar) {
    initialize();
    mcl::G1 decoded, result;
    mcl::Fr secret;
    if (!decode_public_point(point, decoded) || !decode_secret(scalar, secret))
        throw std::invalid_argument("invalid secret multiplication input");
    mcl::G1::mul(result, decoded, secret);
    return encode_public_point(result);
}
} // namespace

SecretScalar secret_scalar_add(const SecretScalar &left, const SecretScalar &right) {
    initialize();
    mcl::Fr a, b, result;
    if (!decode_secret(left, a) || !decode_secret(right, b))
        throw std::invalid_argument("invalid secret scalar");
    mcl::Fr::add(result, a, b);
    auto encoded = encode_secret(result);
    SecretScalar output(encoded);
    OPENSSL_cleanse(encoded.data(), encoded.size());
    return output;
}

SecretScalar secret_scalar_multiply(const SecretScalar &left, const SecretScalar &right) {
    initialize();
    mcl::Fr a, b, result;
    if (!decode_secret(left, a) || !decode_secret(right, b))
        throw std::invalid_argument("invalid secret scalar");
    mcl::Fr::mul(result, a, b);
    auto encoded = encode_secret(result);
    SecretScalar output(encoded);
    OPENSSL_cleanse(encoded.data(), encoded.size());
    return output;
}

std::vector<std::uint8_t> secret_generator_multiply(const SecretScalar &scalar) {
    static const std::vector<std::uint8_t> generator{
        2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    return multiply(generator, scalar);
}

std::vector<std::uint8_t> secret_point_multiply(const std::vector<std::uint8_t> &point,
                                                const SecretScalar &scalar) {
    return multiply(point, scalar);
}

std::vector<std::uint8_t> secret_msm(const std::vector<std::vector<std::uint8_t>> &points,
                                     const std::vector<SecretScalar> &scalars) {
    if (points.size() != scalars.size())
        throw std::invalid_argument("secret MSM input lengths differ");
    initialize();
    if (points.empty())
        return {0};
    std::vector<mcl::G1> decoded_points(points.size());
    std::vector<mcl::Fr> decoded_scalars(scalars.size());
    for (std::size_t i = 0; i < points.size(); ++i) {
        if (!decode_public_point(points[i], decoded_points[i]) ||
            !decode_secret(scalars[i], decoded_scalars[i]))
            throw std::invalid_argument("invalid secret MSM input");
    }
    mcl::G1 result;
    mcl::G1::mulVec(result, decoded_points.data(), decoded_scalars.data(), points.size());
    return encode_public_point(result);
}
} // namespace hta
