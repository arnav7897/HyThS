#include "hta/registration.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstdint>

static hta::SecretScalar scalar(std::uint8_t value) {
    return hta::SecretScalar::from_canonical([&] {
        std::array<std::uint8_t, 32> encoded{};
        encoded.back() = value;
        return encoded;
    }());
}

int main() {
    const hta::PublicBytes registry_id{'r', 'e', 'g', 'i', 's', 't', 'r', 'y', '-', '1'};
    const auto first = hta::create_registration(scalar(7), 1, registry_id);
    const auto second = hta::create_registration(scalar(11), 2, registry_id);
    if (!hta::verify_registration(first, registry_id) ||
        hta::verify_registration(first, {'o', 't', 'h', 'e', 'r'}))
        return EXIT_FAILURE;

    const auto roster = hta::build_roster({first, second}, registry_id);
    const auto repeated = hta::build_roster({first, second}, registry_id);
    if (!roster || !repeated || roster->public_keys.size() != 2 ||
        repeated->digest != roster->digest)
        return EXIT_FAILURE;
    const auto duplicate_key = hta::create_registration(scalar(7), 2, registry_id);
    if (hta::build_roster({first, duplicate_key}, registry_id) ||
        hta::build_roster({second, first}, registry_id) || hta::build_roster({}, registry_id) ||
        hta::build_roster({first}, {}))
        return EXIT_FAILURE;

    auto changed = first;
    changed.proof.response.back() ^= 1;
    if (hta::verify_registration(changed, registry_id))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
