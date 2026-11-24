"""AES-256 (FIPS-197) montado no mesmo motor: referência de comparação e prova de que o motor está correto."""
import numpy as np

from cifra import CifraBlocos, circulante, gf_inversos, gf_mul


def _sbox():
    inv = gf_inversos(0x11B).astype(int)
    rot = lambda v, n: (v << n | v >> (8 - n)) & 255
    return (inv ^ rot(inv, 1) ^ rot(inv, 2) ^ rot(inv, 3) ^ rot(inv, 4) ^ 0x63).astype(np.uint8)


SBOX = _sbox()


def aes256(chave):
    w = [list(chave[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = w[-1]
        if i % 8 == 0:
            t = [int(SBOX[b]) for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = gf_mul(rcon, 2, 0x11B)
        elif i % 8 == 4:
            t = [int(SBOX[b]) for b in t]
        w.append([a ^ b for a, b in zip(w[-8], t)])
    return CifraBlocos([SBOX] * 4, [(0, 1, 2, 3)] * 14, circulante((2, 3, 1, 1)), 0x11B,
                       np.array(w, np.uint8).reshape(15, 16))
