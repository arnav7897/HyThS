#include "hta/hash_to_field.hpp"

#include "hta/expand_message.hpp"

#include <memory>
#include <stdexcept>

#include <openssl/bn.h>

namespace hta {
std::vector<std::array<std::uint8_t, 32>>
hash_to_field_secp256k1(const std::vector<std::uint8_t> &message,
                        const std::vector<std::uint8_t> &dst, std::size_t count) {
    constexpr std::size_t element_length = 48;
    if (count == 0 || count > 170)
        throw std::invalid_argument("hash-to-field count must be between 1 and 170");
    const auto uniform = expand_message_xmd_sha256(message, dst, count * element_length);

    using Number = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using Context = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
    BIGNUM *prime_raw = nullptr;
    if (!BN_hex2bn(&prime_raw,
                   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")) {
        BN_free(prime_raw);
        throw std::runtime_error("secp256k1 field initialization failed");
    }
    Number prime(prime_raw, BN_free);
    Number wide(BN_new(), BN_free);
    Number reduced(BN_new(), BN_free);
    Context context(BN_CTX_new(), BN_CTX_free);
    if (!wide || !reduced || !context)
        throw std::runtime_error("hash-to-field allocation failed");
    std::vector<std::array<std::uint8_t, 32>> output(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (!BN_bin2bn(uniform.data() + i * element_length, static_cast<int>(element_length),
                       wide.get()) ||
            !BN_nnmod(reduced.get(), wide.get(), prime.get(), context.get()) ||
            BN_bn2binpad(reduced.get(), output[i].data(), 32) != 32)
            throw std::runtime_error("hash-to-field reduction failed");
    }
    return output;
}
} // namespace hta
