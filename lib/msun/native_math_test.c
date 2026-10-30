/* SPDX-License-Identifier: BSD-2-Clause */
#include <math.h>
#include <fenv.h>
#include <complex.h>
#include <err.h>
#pragma STDC FENV_ACCESS ON
int main(void) {
    volatile double x = 1.25, negative = -1.0;
    volatile float xf = 1.25f;
    volatile long double xl = 1.25L;
    if (floor(x) != 1 || ceil(x) != 2 || floorf(xf) != 1 || floorl(xl) != 1)
        errx(1, "floor/ceil precision variants");
    if (fabs(sin(x)*sin(x)+cos(x)*cos(x)-1.0) > 1e-14 ||
        fabs(log(exp(x))-x) > 1e-14 || fabsl(sqrtl(xl*xl)-xl) > 1e-18L)
        errx(1, "transcendental identities");
    if (fma(x, 4.0, -5.0) != 0.0 || fmaf(xf, 4.0f, -5.0f) != 0.0f)
        errx(1, "fma dispatch");
    double complex z = csqrt(-4.0 + 0.0*I);
    if (creal(z) != 0 || cimag(z) != 2) errx(1, "complex square root");
    if (fesetround(FE_DOWNWARD) || rint(x) != 1.0) errx(1, "round down");
    if (fesetround(FE_UPWARD) || rint(x) != 2.0) errx(1, "round up");
    if (fesetround(FE_TONEAREST)) errx(1, "restore rounding");
    feclearexcept(FE_ALL_EXCEPT);
    if (!isnan(sqrt(negative)) || !(fetestexcept(FE_INVALID))) errx(1, "invalid exception");
    feclearexcept(FE_ALL_EXCEPT);
    return 0;
}
