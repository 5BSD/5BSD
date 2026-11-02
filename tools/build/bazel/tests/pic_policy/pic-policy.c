/* SPDX-License-Identifier: BSD-2-Clause */
#if defined(__PIC__) != defined(PIC)
#error compiler PIC mode and explicit PIC define disagree
#endif
#ifdef __PIC__
#if __PIC__ != EXPECTED_PIC_LEVEL
#error compiler PIC level disagrees with the declared contract
#endif
const unsigned policy_pic_level = __PIC__;
#else
const unsigned policy_pic_level = 0;
#endif
_Static_assert(sizeof(unsigned) == 4, "fixture expects the native unsigned ABI");
