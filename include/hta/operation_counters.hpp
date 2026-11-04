#pragma once

#include <cstdint>

namespace hta {
// Counts successful high-level adapter calls, not internal curve/field operations.
struct OperationCounters {
    std::uint64_t scalar_add_calls = 0;
    std::uint64_t scalar_multiply_calls = 0;
    std::uint64_t point_add_calls = 0;
    std::uint64_t variable_point_multiply_calls = 0;
    std::uint64_t generator_multiply_calls = 0;
    std::uint64_t msm_calls = 0;
    std::uint64_t msm_bases = 0;
};

void reset_operation_counters() noexcept;
OperationCounters operation_counters_snapshot() noexcept;
} // namespace hta
