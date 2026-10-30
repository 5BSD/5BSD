/* SPDX-License-Identifier: BSD-2-Clause */
/* Bounded link/runtime checks; the maintained msun accuracy suite is separate. */
#include <complex.h>
#include <fenv.h>
#include <math.h>
#include <stdio.h>

#pragma STDC FENV_ACCESS ON

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #expr); return 1; \
} } while (0)

int
main(void)
{
    volatile double half = 0.5, two = 2.0, minus = -1.0;
    double s, c;
    double complex z;
    int original = fegetround();

    CHECK(fabs(sin(half) - 0.479425538604203) < 1e-15);
    CHECK(fabs(cos(half) - 0.877582561890373) < 1e-15);
    sincos(half, &s, &c);
    CHECK(fabs(s * s + c * c - 1.0) < 1e-15);
    CHECK(fabs(log(exp(half)) - half) < 1e-15);
    CHECK(sqrt(two * two) == two);
    CHECK(fabs(tgamma(5.0) - 24.0) < 1e-12);
    CHECK(fabsf(sinf((float)half) - 0.47942554f) < 1e-7f);
    CHECK(fabsl(tgammal(5.0L) - 24.0L) < 1e-15L);
    CHECK(fabsl(sinl((long double)half) - 0.47942553860420300027L) < 1e-18L);
    z = csqrt(-4.0 + 0.0 * I);
    CHECK(creal(z) == 0.0 && cimag(z) == 2.0);
    CHECK(fesetround(FE_DOWNWARD) == 0);
    CHECK(nearbyint(half) == 0.0);
    CHECK(fesetround(FE_UPWARD) == 0);
    CHECK(nearbyint(half) == 1.0);
    CHECK(fesetround(original) == 0);
    CHECK(feclearexcept(FE_ALL_EXCEPT) == 0);
    CHECK(isnan(sqrt(minus)));
    CHECK(fetestexcept(FE_INVALID));
    CHECK(signbit(sin(-0.0)));
    return 0;
}
