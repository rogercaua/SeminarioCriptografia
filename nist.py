"""Nove testes da NIST SP 800-22 (recebem um array de bits 0/1)."""
import math

import numpy as np


def igamc(a, x):
    """Gama incompleta superior regularizada, para a múltiplo de 1/2 (recorrência em a)."""
    if x <= 0:
        return 1.0
    k, q = (0.5, math.erfc(math.sqrt(x))) if a % 1 else (1.0, math.exp(-x))
    while k < a:
        q += math.exp(k * math.log(x) - x - math.lgamma(k + 1))
        k += 1
    return min(q, 1.0)


def frequencia(b):
    return math.erfc(abs(2 * int(b.sum()) - len(b)) / math.sqrt(2 * len(b)))


def frequencia_blocos(b, M=10000):
    N = len(b) // M
    return igamc(N / 2, 2 * M * float(((b[:N * M].reshape(N, M).mean(1) - 0.5) ** 2).sum()))


def corridas(b):
    n, p = len(b), float(b.mean())
    if abs(p - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + int((b[1:] != b[:-1]).sum())
    return math.erfc(abs(v - 2 * n * p * (1 - p)) / (2 * math.sqrt(2 * n) * p * (1 - p)))


def maior_corrida(b):
    M, pi = 10000, [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
    N, v = len(b) // M, [0] * 7
    for bloco in b[:N * M].reshape(N, M):
        zeros = np.flatnonzero(np.concatenate(([0], bloco, [0])) == 0)
        v[min(max(int(np.diff(zeros).max()) - 1, 10), 16) - 10] += 1
    return igamc(3, sum((o - N * p) ** 2 / (N * p) for o, p in zip(v, pi)) / 2)


def espectral(b):
    n = len(b)
    m = np.abs(np.fft.rfft(2.0 * b - 1))[:n // 2]
    n1 = int((m < math.sqrt(n * math.log(20))).sum())
    return math.erfc(abs(n1 - 0.95 * n / 2) / math.sqrt(n * 0.95 * 0.05 / 4) / math.sqrt(2))


def somas_acumuladas(b, reverso=False):
    s = np.cumsum(2 * (b[::-1] if reverso else b).astype(np.int64) - 1)
    n, z = len(b), int(np.abs(s).max())
    F = lambda x: 0.5 * math.erfc(-x / math.sqrt(2))
    r = math.sqrt(n)
    a = sum(F((4 * k + 1) * z / r) - F((4 * k - 1) * z / r) for k in range(int((-n / z + 1) / 4), int((n / z - 1) / 4) + 1))
    c = sum(F((4 * k + 3) * z / r) - F((4 * k + 1) * z / r) for k in range(int((-n / z - 3) / 4), int((n / z - 1) / 4) + 1))
    return 1 - a + c


def _contagens(b, m):
    if m == 0:
        return np.array([len(b)])
    e = np.concatenate((b, b[:m - 1])).astype(np.int64)
    return np.bincount(sum(e[i:len(b) + i] << (m - 1 - i) for i in range(m)), minlength=1 << m)


def serial(b, m=10):
    n = len(b)
    psi = lambda k: (1 << k) / n * float((_contagens(b, k).astype(float) ** 2).sum()) - n if k > 0 else 0.0
    p0, p1, p2 = psi(m), psi(m - 1), psi(m - 2)
    return igamc(2 ** (m - 2), (p0 - p1) / 2), igamc(2 ** (m - 3), (p0 - 2 * p1 + p2) / 2)


def entropia_aproximada(b, m=9):
    def phi(k):
        c = _contagens(b, k) / len(b)
        return float((c[c > 0] * np.log(c[c > 0])).sum())
    return igamc(2 ** (m - 1), len(b) * (math.log(2) - (phi(m) - phi(m + 1))))


def posto_matriz(b):
    N, f = len(b) // 1024, [0, 0, 0]
    for q in np.packbits(b[:N * 1024]).reshape(N, 32, 4):
        linhas, posto = [int.from_bytes(l.tobytes()) for l in q], 0
        while linhas:
            p = linhas.pop()
            if p:
                posto += 1
                menor = p & -p
                linhas = [l ^ p if l & menor else l for l in linhas]
        f[min(32 - posto, 2)] += 1
    return math.exp(-sum((o - N * p) ** 2 / (N * p) for o, p in zip(f, (0.2888, 0.5776, 0.1336))) / 2)


def todos(b):
    s1, s2 = serial(b)
    return {"frequência": frequencia(b), "frequência em blocos": frequencia_blocos(b), "corridas": corridas(b),
            "maior corrida": maior_corrida(b), "espectral (FFT)": espectral(b), "somas acumuladas": somas_acumuladas(b),
            "somas acumuladas (inv.)": somas_acumuladas(b, True), "serial 1": s1, "serial 2": s2,
            "entropia aproximada": entropia_aproximada(b), "posto de matriz": posto_matriz(b)}
