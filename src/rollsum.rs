/*
 * Copyright 2011 Avery Pennarun. All rights reserved.
 * Copyright (c) 2015, Aidan Hobson Sayers
 *
 * (This license applies to bupsplit.c and bupsplit.h only.)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AVERY PENNARUN AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

const WINDOW_BITS: usize = 6;
pub const WINDOW_SIZE: usize = 1 << WINDOW_BITS;
pub const CHUNK_MASK: u32 = 0x1fff;
const CHAR_OFFSET: usize = 31;

/// Rolling checksum method used by `bup`
/// based on: https://github.com/bup/bup/lib/bup/bupsplit.c
pub struct Rollsum {
    s1: usize,
    s2: usize,
    window: [u8; WINDOW_SIZE],
    wofs: usize,
    chunk_mask: u32,
}

impl Default for Rollsum {
    fn default() -> Self {
        Rollsum {
            s1: WINDOW_SIZE * CHAR_OFFSET,
            s2: WINDOW_SIZE * (WINDOW_SIZE - 1) * CHAR_OFFSET,
            window: [0; WINDOW_SIZE],
            wofs: 0,
            chunk_mask: CHUNK_MASK,
        }
    }
}

impl Rollsum {
    /// Create new Rollsum engine with default chunking settings
    pub fn new() -> Self {
        Default::default()
    }

    pub fn new_with_chunk_mask(chunk_mask: u32) -> Self {
        Rollsum {
            chunk_mask,
            ..Default::default()
        }
    }

    #[inline(always)]
    pub fn roll_byte(&mut self, newch: u8) -> bool {
        // Since this crate is performance critical, and
        // we're in strict control of `wofs`, it is justified
        // to skip bound checking to increase the performance
        // https://github.com/rust-lang/rfcs/issues/811
        let prevch = unsafe { *self.window.get_unchecked(self.wofs) };
        self.s1 += newch as usize;
        self.s1 -= prevch as usize;
        self.s2 += self.s1;
        self.s2 -= WINDOW_SIZE * (prevch as usize + CHAR_OFFSET);
        unsafe { *self.window.get_unchecked_mut(self.wofs) = newch };
        self.wofs = (self.wofs + 1) % WINDOW_SIZE;
        let digest = ((self.s1 as u32) << 16) | ((self.s2 as u32) & 0xffff);
        (digest & self.chunk_mask) == self.chunk_mask
    }

    #[inline]
    pub fn reset(&mut self) {
        *self = Rollsum {
            chunk_mask: self.chunk_mask,
            ..Default::default()
        }
    }
}
