#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Check packet queue helpers used by SDIO aggregation against real bodies."""
import sys
sys.dont_write_bytecode = True
from power_test import run_test

if __name__ == '__main__':
    run_test('skbuff_queue_test.c', [
        ('sys/compat/linuxkpi/common/include/linux/skbuff.h', result, name)
        for result, name in [
            ('static inline void', '__skb_queue_head_init'),
            ('static inline void', '__skb_insert'),
            ('static inline void', '__skb_queue_before'),
            ('static inline void', '__skb_queue_tail'),
            ('static inline struct sk_buff *', 'skb_peek'),
            ('static inline struct sk_buff *', '__skb_peek'),
            ('static inline bool', 'skb_queue_is_last'),
            ('static inline struct sk_buff *', 'skb_peek_next'),
            ('static inline bool', 'skb_cloned'),
            ('static inline void', '__skb_unlink'),
            ('static inline struct sk_buff *', '__skb_dequeue'),
        ]
    ], flags=['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])
