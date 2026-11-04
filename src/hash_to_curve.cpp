#include "hta/hash_to_curve.hpp"

#include "hta/hash_to_field.hpp"

#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <openssl/bn.h>
#include <openssl/err.h>

namespace hta {
namespace {
using Number = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using Context = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

Number number() {
    Number value(BN_new(), BN_free);
    if (!value)
        throw std::runtime_error("hash-to-curve allocation failed");
    return value;
}
Number constant(const char *hex) {
    BIGNUM *raw = nullptr;
    if (!BN_hex2bn(&raw, hex)) {
        BN_free(raw);
        throw std::runtime_error("hash-to-curve constant initialization failed");
    }
    return Number(raw, BN_free);
}
void ok(int result) {
    if (result != 1)
        throw std::runtime_error("hash-to-curve field operation failed");
}
void add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *c) {
    ok(BN_mod_add(r, a, b, p, c));
}
void sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *c) {
    ok(BN_mod_sub(r, a, b, p, c));
}
void mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *c) {
    ok(BN_mod_mul(r, a, b, p, c));
}
void inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *c) {
    if (!BN_mod_inverse(r, a, p, c))
        throw std::runtime_error("hash-to-curve inverse failed");
}

void polynomial(BIGNUM *out, const BIGNUM *x, const char *const *coefficients, std::size_t count,
                const BIGNUM *p, BN_CTX *ctx) {
    auto coefficient = constant(coefficients[count - 1]);
    ok(BN_copy(out, coefficient.get()) ? 1 : 0);
    for (std::size_t i = count - 1; i > 0; --i) {
        mul(out, out, x, p, ctx);
        coefficient = constant(coefficients[i - 1]);
        add(out, out, coefficient.get(), p, ctx);
    }
}

struct Point {
    Number x{nullptr, BN_free};
    Number y{nullptr, BN_free};
    bool infinity{true};
};

Point copy_point(const Point &point) {
    if (point.infinity)
        return {};
    Number x(BN_dup(point.x.get()), BN_free), y(BN_dup(point.y.get()), BN_free);
    if (!x || !y)
        throw std::runtime_error("hash-to-curve allocation failed");
    return {std::move(x), std::move(y), false};
}

Point add_points(const Point &left, const Point &right, const BIGNUM *curve_a, const BIGNUM *p,
                 BN_CTX *ctx) {
    if (left.infinity)
        return copy_point(right);
    if (right.infinity)
        return copy_point(left);
    auto slope = number(), numerator = number(), denominator = number();
    if (BN_cmp(left.x.get(), right.x.get()) == 0) {
        auto sum_y = number();
        add(sum_y.get(), left.y.get(), right.y.get(), p, ctx);
        if (BN_is_zero(sum_y.get()) || BN_is_zero(left.y.get()))
            return {};
        auto three = constant("3"), two = constant("2");
        mul(numerator.get(), left.x.get(), left.x.get(), p, ctx);
        mul(numerator.get(), numerator.get(), three.get(), p, ctx);
        add(numerator.get(), numerator.get(), curve_a, p, ctx);
        mul(denominator.get(), left.y.get(), two.get(), p, ctx);
    } else {
        sub(numerator.get(), right.y.get(), left.y.get(), p, ctx);
        sub(denominator.get(), right.x.get(), left.x.get(), p, ctx);
    }
    auto denominator_inverse = number();
    inv(denominator_inverse.get(), denominator.get(), p, ctx);
    mul(slope.get(), numerator.get(), denominator_inverse.get(), p, ctx);
    auto x = number(), y = number();
    mul(x.get(), slope.get(), slope.get(), p, ctx);
    sub(x.get(), x.get(), left.x.get(), p, ctx);
    sub(x.get(), x.get(), right.x.get(), p, ctx);
    sub(y.get(), left.x.get(), x.get(), p, ctx);
    mul(y.get(), slope.get(), y.get(), p, ctx);
    sub(y.get(), y.get(), left.y.get(), p, ctx);
    return {std::move(x), std::move(y), false};
}

Point map_swu(const BIGNUM *u, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    // RFC 9380 Sections 6.6.2 and 8.7; Z = -11.
    auto z = constant("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC24");
    auto u2 = number(), u4 = number(), denominator = number(), temporary = number();
    auto x1 = number(), x2 = number(), gx = number(), y = number();
    mul(u2.get(), u, u, p, ctx);
    mul(u4.get(), u2.get(), u2.get(), p, ctx);
    mul(denominator.get(), z.get(), u2.get(), p, ctx);
    mul(temporary.get(), z.get(), z.get(), p, ctx);
    mul(temporary.get(), temporary.get(), u4.get(), p, ctx);
    add(denominator.get(), denominator.get(), temporary.get(), p, ctx);

    if (BN_is_zero(denominator.get())) {
        auto za = number();
        mul(za.get(), z.get(), a, p, ctx);
        inv(za.get(), za.get(), p, ctx);
        mul(x1.get(), b, za.get(), p, ctx);
    } else {
        inv(temporary.get(), denominator.get(), p, ctx);
        add(temporary.get(), temporary.get(), BN_value_one(), p, ctx);
        auto b_over_a = number(), minus_b_over_a = number();
        inv(b_over_a.get(), a, p, ctx);
        mul(b_over_a.get(), b_over_a.get(), b, p, ctx);
        sub(minus_b_over_a.get(), p, b_over_a.get(), p, ctx);
        mul(x1.get(), minus_b_over_a.get(), temporary.get(), p, ctx);
    }

    auto a_x = number(), x_sq = number(), x_cube = number();
    mul(x_sq.get(), x1.get(), x1.get(), p, ctx);
    mul(x_cube.get(), x_sq.get(), x1.get(), p, ctx);
    mul(a_x.get(), a, x1.get(), p, ctx);
    add(gx.get(), x_cube.get(), a_x.get(), p, ctx);
    add(gx.get(), gx.get(), b, p, ctx);
    BIGNUM *root = BN_mod_sqrt(nullptr, gx.get(), p, ctx);
    const bool first_square = root != nullptr;
    if (first_square)
        y.reset(root);
    else
        ERR_clear_error();

    mul(x2.get(), z.get(), u2.get(), p, ctx);
    mul(x2.get(), x2.get(), x1.get(), p, ctx);
    if (!first_square) {
        mul(x_sq.get(), x2.get(), x2.get(), p, ctx);
        mul(x_cube.get(), x_sq.get(), x2.get(), p, ctx);
        mul(a_x.get(), a, x2.get(), p, ctx);
        add(gx.get(), x_cube.get(), a_x.get(), p, ctx);
        add(gx.get(), gx.get(), b, p, ctx);
        root = BN_mod_sqrt(nullptr, gx.get(), p, ctx);
        if (!root) {
            ERR_clear_error();
            throw std::runtime_error("SWU square root failed");
        }
        y.reset(root);
        x1.swap(x2);
    }
    if (BN_is_odd(u) != BN_is_odd(y.get()))
        sub(y.get(), p, y.get(), p, ctx);
    return {std::move(x1), std::move(y), false};
}

Point isogeny(const Point &point, const BIGNUM *p, BN_CTX *ctx) {
    static const char *const x_num[] = {
        "8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7",
        "7D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581",
        "534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262",
        "8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C"};
    static const char *const x_den[] = {
        "D35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B",
        "EDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14", "1"};
    static const char *const y_num[] = {
        "4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C",
        "C75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3",
        "29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931",
        "2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84"};
    static const char *const y_den[] = {
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B",
        "7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573",
        "6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F", "1"};
    auto xn = number(), xd = number(), yn = number(), yd = number();
    polynomial(xn.get(), point.x.get(), x_num, 4, p, ctx);
    polynomial(xd.get(), point.x.get(), x_den, 3, p, ctx);
    polynomial(yn.get(), point.x.get(), y_num, 4, p, ctx);
    polynomial(yd.get(), point.x.get(), y_den, 4, p, ctx);
    if (BN_is_zero(xd.get()) || BN_is_zero(yd.get()))
        return {};
    auto reciprocal = number(), x = number(), y = number();
    inv(reciprocal.get(), xd.get(), p, ctx);
    mul(x.get(), xn.get(), reciprocal.get(), p, ctx);
    inv(reciprocal.get(), yd.get(), p, ctx);
    mul(y.get(), point.y.get(), yn.get(), p, ctx);
    mul(y.get(), y.get(), reciprocal.get(), p, ctx);
    return {std::move(x), std::move(y), false};
}
} // namespace

std::vector<std::uint8_t> hash_to_curve_secp256k1(const std::vector<std::uint8_t> &message) {
    const std::string dst = "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";
    constexpr const char *prime_hex =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    auto p = constant(prime_hex);
    auto a = constant("3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533");
    auto b = constant("6EB"), target_a = constant("0");
    Context ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx)
        throw std::runtime_error("hash-to-curve context allocation failed");
    const std::vector<std::uint8_t> domain(dst.begin(), dst.end());
    const auto fields = hash_to_field_secp256k1(message, domain, 2);
    std::array<Point, 2> points;
    for (std::size_t i = 0; i < points.size(); ++i) {
        auto u = number();
        ok(BN_bin2bn(fields[i].data(), static_cast<int>(fields[i].size()), u.get()) ? 1 : 0);
        points[i] =
            isogeny(map_swu(u.get(), p.get(), a.get(), b.get(), ctx.get()), p.get(), ctx.get());
    }
    const auto point = add_points(points[0], points[1], target_a.get(), p.get(), ctx.get());
    if (point.infinity)
        return {0};
    std::vector<std::uint8_t> encoded(33);
    encoded[0] = BN_is_odd(point.y.get()) ? 3 : 2;
    if (BN_bn2binpad(point.x.get(), encoded.data() + 1, 32) != 32)
        throw std::runtime_error("hash-to-curve serialization failed");
    return encoded;
}
} // namespace hta
