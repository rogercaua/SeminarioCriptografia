"""VITRAL-256: cifra de blocos derivada do AES-256, aplicada a qualquer dado (texto, imagem, áudio, documento...).

Mudanças em relação ao AES-256:
  1. SubBytes    -> 4 S-boxes geradas pela chave (uma por linha do estado)
  2. ShiftRows   -> deslocamentos escolhidos pela chave a cada rodada
  3. MixColumns  -> outro corpo (0x11D) e outra matriz MDS, circ(1,5,2,1)
  4. Key schedule-> SHAKE-256, sem a estrutura linear do AES
  5. 14 rodadas  -> 16 rodadas

O motor é parametrizado: com os parâmetros do AES ele reproduz a FIPS-197 (ver testes.py).
"""
import hashlib
import hmac
import os
import struct
from itertools import permutations

import numpy as np

ITERACOES = 600_000
BLOCOS_POR_LOTE = 1 << 16


class FalhaAutenticacao(ValueError):
    """Senha errada ou dado cifrado adulterado."""


# ---------- corpo GF(2^8) ----------
def gf_mul(a, b, poli):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poli
        b >>= 1
    return r


def gf_inversos(poli):
    inv = np.zeros(256, np.uint8)
    for a in range(1, 256):
        inv[a] = next(b for b in range(1, 256) if gf_mul(a, b, poli) == 1)
    return inv


def circulante(c):
    return [[c[(j - i) % 4] for j in range(4)] for i in range(4)]


def matriz_inversa(M, poli):
    """Gauss-Jordan em GF(2^8)."""
    inv = gf_inversos(poli)
    A = [list(l) + [int(i == j) for j in range(4)] for i, l in enumerate(M)]
    for c in range(4):
        p = next(i for i in range(c, 4) if A[i][c])
        A[c], A[p] = A[p], A[c]
        k = int(inv[A[c][c]])
        A[c] = [gf_mul(v, k, poli) for v in A[c]]
        for i in range(4):
            if i != c and A[i][c]:
                f = A[i][c]
                A[i] = [v ^ gf_mul(f, w, poli) for v, w in zip(A[i], A[c])]
    return [l[4:] for l in A]


# ---------- motor de blocos (128 bits) ----------
class CifraBlocos:
    """Rede de substituição-permutação; estado em colunas, como no AES."""

    def __init__(self, sboxes, deslocamentos, matriz, poli, subchaves):
        self.sboxes, self.deslocamentos = sboxes, deslocamentos
        self.matriz, self.poli, self.subchaves = matriz, poli, subchaves
        self.rodadas = len(deslocamentos)
        mult = {c: np.array([gf_mul(x, c, poli) for x in range(256)], np.uint32) for c in {v for l in matriz for v in l}}
        # tabela T[r]: S-box da linha r seguida da coluna r da matriz, em 32 bits
        self.T = [sum(mult[matriz[i][r]][sboxes[r]] << np.uint32(8 * i) for i in range(4)).astype("<u4") for r in range(4)]
        self.origem = [[[4 * ((c + d[r]) % 4) + r for c in range(4)] for r in range(4)] for d in deslocamentos]

    def cifrar(self, blocos, rodadas=None):
        """blocos: array (n,16) uint8. `rodadas` menor que o total serve à análise."""
        n = rodadas or self.rodadas
        x = blocos ^ self.subchaves[0]
        for r in range(n - 1):
            o = self.origem[r]
            w = self.T[0][x[:, o[0]]] ^ self.T[1][x[:, o[1]]] ^ self.T[2][x[:, o[2]]] ^ self.T[3][x[:, o[3]]]
            x = np.ascontiguousarray(w).view(np.uint8).reshape(-1, 16) ^ self.subchaves[r + 1]
        y = np.empty_like(x)  # última rodada sem mistura, como no AES
        for lin in range(4):
            y[:, lin::4] = self.sboxes[lin][x[:, self.origem[n - 1][lin]]]
        return y ^ self.subchaves[n]

    def decifrar(self, blocos):
        inv_s = [np.argsort(s).astype(np.uint8) for s in self.sboxes]
        inv_m = matriz_inversa(self.matriz, self.poli)
        mult = {c: np.array([gf_mul(x, c, self.poli) for x in range(256)], np.uint8) for c in {v for l in inv_m for v in l}}
        x = blocos ^ self.subchaves[self.rodadas]
        for r in reversed(range(self.rodadas)):
            if r < self.rodadas - 1:
                y = np.zeros_like(x)
                for i in range(4):
                    for j in range(4):
                        y[:, i::4] ^= mult[inv_m[i][j]][x[:, j::4]]
                x = y
            y = np.empty_like(x)
            for lin in range(4):
                y[:, self.origem[r][lin]] = inv_s[lin][x[:, lin::4]]
            x = y ^ self.subchaves[r]
        return x


# ---------- VITRAL-256 ----------
POLI = 0x11D
MATRIZ = circulante((1, 5, 2, 1))
RODADAS = 16
INVERSOS = gf_inversos(POLI)
ORDENS = list(permutations(range(4)))
_PARIDADE = np.array([bin(i).count("1") & 1 for i in range(256)], np.uint8)


def _inversivel(linhas):
    linhas = list(linhas)
    for bit in range(8):
        pivo = next((l for l in linhas if l >> bit & 1), None)
        if pivo is None:
            return False
        linhas.remove(pivo)
        linhas = [l ^ pivo if l >> bit & 1 else l for l in linhas]
    return True


def gerar_sbox(fluxo):
    """S(x) = L·x⁻¹ ⊕ c, com L sorteada pela chave; afim-equivalente à do AES (NL 112, DU 4)."""
    x = np.arange(256, dtype=np.uint8)
    while True:
        L = [next(fluxo) for _ in range(8)]
        sorteio = next(fluxo)
        if not _inversivel(L):
            continue
        t = np.zeros(256, np.uint8)
        for bit, linha in enumerate(L):
            t |= _PARIDADE[INVERSOS & linha] << bit
        proibidos = set((t ^ x).tolist()) | set((t ^ x ^ 255).tolist())  # pontos fixos e antifixos
        livres = [c for c in range(256) if c not in proibidos]
        if livres:
            return t ^ np.uint8(livres[sorteio % len(livres)])


def vitral(chave):
    if len(chave) != 32:
        raise ValueError("a chave deve ter 256 bits")
    # 9 bytes por tentativa de S-box, ~3,5 tentativas em média: 16 KiB sobram com folga
    b = hashlib.shake_256(b"VITRAL-256/v1" + chave).digest(16384)
    n = 16 * (RODADAS + 1)
    subchaves = np.frombuffer(b[:n], np.uint8).reshape(-1, 16)
    deslocamentos = [ORDENS[v % 24] for v in b[n:n + RODADAS]]
    fluxo = iter(b[n + RODADAS:])
    return CifraBlocos([gerar_sbox(fluxo) for _ in range(4)], deslocamentos, MATRIZ, POLI, subchaves)


def ctr(cifra, iv, dados):
    """Modo contador: o mesmo passo cifra e decifra."""
    saida = np.empty(len(dados), np.uint8)
    for ini in range(0, (len(dados) + 15) // 16, BLOCOS_POR_LOTE):
        m = min(BLOCOS_POR_LOTE, (len(dados) + 15) // 16 - ini)
        blocos = np.tile(np.frombuffer(iv, np.uint8), (m, 1))
        blocos[:, 8:] ^= np.arange(ini, ini + m, dtype=">u8").view(np.uint8).reshape(-1, 8)
        fatia = dados[16 * ini:16 * (ini + m)]
        saida[16 * ini:16 * ini + len(fatia)] = fatia ^ cifra.cifrar(blocos).ravel()[:len(fatia)]
    return saida


# ---------- dados <-> pacote ----------
MAGICO = b"VTR2"
CAB = struct.Struct(">4s16s16s")  # mágico, salt, IV/etiqueta; o nome do arquivo vai cifrado junto do conteúdo


def derivar(senha, salt, iteracoes=ITERACOES):
    mestre = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, iteracoes)
    return tuple(hmac.digest(mestre, rotulo, "sha256") for rotulo in (b"vitral2 cifra", b"vitral2 mac"))


def moldura(nome, dados):
    """O que é de fato cifrado: 1 byte com o tamanho do nome, o nome e o conteúdo."""
    n = nome.encode()
    if len(n) > 255:
        raise ValueError("nome de arquivo longo demais (máximo de 255 bytes)")
    return bytes([len(n)]) + n + dados


def _iv(k_mac, salt, claro):
    """IV sintético: depende de todos os bytes e também serve de etiqueta de integridade."""
    return hmac.digest(k_mac, salt + claro, "sha256")[:16]


def cifrar(dados, senha, nome="", salt=None, iteracoes=ITERACOES):
    if not senha:
        raise ValueError("informe uma senha")
    salt = salt or os.urandom(16)  # chave nova a cada cifragem
    claro = moldura(nome, dados)
    k_cifra, k_mac = derivar(senha, salt, iteracoes)
    iv = _iv(k_mac, salt, claro)
    return CAB.pack(MAGICO, salt, iv) + ctr(vitral(k_cifra), iv, np.frombuffer(claro, np.uint8)).tobytes()


def abrir_sem_conferir(pacote, senha, iteracoes=ITERACOES):
    """Decifra ignorando a etiqueta: (moldura, etiqueta no pacote, etiqueta recalculada, chave). Só para análise."""
    if len(pacote) <= CAB.size or pacote[:4] != MAGICO:
        raise ValueError("isto não foi cifrado com a VITRAL-256 Dados")
    _, salt, iv = CAB.unpack_from(pacote)
    k_cifra, k_mac = derivar(senha, salt, iteracoes)
    claro = ctr(vitral(k_cifra), iv, np.frombuffer(pacote, np.uint8, offset=CAB.size)).tobytes()
    return claro, iv, _iv(k_mac, salt, claro), k_cifra


def decifrar(pacote, senha, iteracoes=ITERACOES):
    """Devolve (nome, dados) ou recusa o pacote inteiro."""
    claro, iv, calculada, _ = abrir_sem_conferir(pacote, senha, iteracoes)
    if not hmac.compare_digest(iv, calculada):
        raise FalhaAutenticacao("senha errada ou dado adulterado")
    n = 1 + claro[0]
    return claro[1:n].decode(), claro[n:]
