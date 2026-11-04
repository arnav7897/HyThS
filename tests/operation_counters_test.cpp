#include "hta/operation_counters.hpp"
#include "hta/secp256k1_public.hpp"

#include <cstdlib>
#include <cstdint>

int main() {
    const hta::PublicBytes one(31, 0);
    auto scalar_one = one;
    scalar_one.push_back(1);
    auto scalar_two = one;
    scalar_two.push_back(2);
    const auto generator = hta::public_generator_multiply(scalar_one);
    if (!generator)
        return EXIT_FAILURE;

    hta::reset_operation_counters();
    if (!hta::public_scalar_add(scalar_one, scalar_two) ||
        !hta::public_scalar_multiply(scalar_one, scalar_two) ||
        !hta::public_point_add(*generator, *generator) ||
        !hta::public_point_multiply(*generator, scalar_two) ||
        !hta::public_generator_multiply(scalar_two) ||
        !hta::public_msm({*generator, *generator}, {scalar_one, scalar_two}) ||
        hta::public_point_multiply({4}, scalar_one))
        return EXIT_FAILURE;

    const auto counts = hta::operation_counters_snapshot();
#ifdef HTA_OPCOUNTERS
    if (counts.scalar_add_calls != 1 || counts.scalar_multiply_calls != 1 ||
        counts.point_add_calls != 1 || counts.variable_point_multiply_calls != 1 ||
        counts.generator_multiply_calls != 1 || counts.msm_calls != 1 || counts.msm_bases != 2)
        return EXIT_FAILURE;
#else
    if (counts.scalar_add_calls || counts.scalar_multiply_calls || counts.point_add_calls ||
        counts.variable_point_multiply_calls || counts.generator_multiply_calls ||
        counts.msm_calls || counts.msm_bases)
        return EXIT_FAILURE;
#endif
    hta::reset_operation_counters();
    const auto reset = hta::operation_counters_snapshot();
    if (reset.scalar_add_calls || reset.scalar_multiply_calls || reset.point_add_calls ||
        reset.variable_point_multiply_calls || reset.generator_multiply_calls || reset.msm_calls ||
        reset.msm_bases)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
