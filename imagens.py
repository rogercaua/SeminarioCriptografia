"""Imagens de teste geradas por código (sem direitos de terceiros)."""
import numpy as np


def vitral_colorido(n=512, semente=3):
    """Mosaico de Voronoi: grandes áreas lisas, o pior caso para vazar padrão."""
    rng = np.random.default_rng(semente)
    pontos, cores = rng.integers(0, n, (60, 2)), rng.integers(40, 256, (60, 3), np.uint8)
    y, x = np.mgrid[:n, :n]
    d = np.sort(np.stack([(y - a) ** 2 + (x - b) ** 2 for a, b in pontos]), 0)
    dono = np.argmin(np.stack([(y - a) ** 2 + (x - b) ** 2 for a, b in pontos]), 0)
    img = cores[dono]
    img[np.sqrt(d[1]) - np.sqrt(d[0]) < 5] = 20
    return img


def paisagem(n=512, semente=5):
    """Ruído suave em várias escalas: parecido com fotografia (alta correlação entre vizinhos)."""
    rng = np.random.default_rng(semente)
    f = np.fft.fftfreq(n)
    raio = np.hypot(*np.meshgrid(f, f)) + 1 / n
    rel = np.fft.ifft2(np.fft.fft2(rng.normal(size=(n, n))) / raio ** 1.6).real
    rel = (rel - rel.min()) / np.ptp(rel)
    canais = [255 * rel ** g * k for g, k in ((1.3, 1.0), (0.9, 0.85), (0.7, 0.7))]
    return np.stack(canais, -1).astype(np.uint8)


TODAS = {"vitral": vitral_colorido, "paisagem": paisagem,
         "preta": lambda n=512: np.zeros((n, n, 3), np.uint8)}
