"""Esteganografia LSB: esconde um pacote VITRAL-256 no bit menos significativo de uma imagem de capa."""
import math
import struct

import numpy as np
from PIL import Image, ImageOps

import cifra


MAX_PIXELS = 25_000_000


def abrir_capa(origem):
    img = Image.open(origem)
    if img.width * img.height > MAX_PIXELS:
        raise ValueError("capa grande demais (máximo de 25 megapixels)")
    return np.asarray(ImageOps.exif_transpose(img).convert("RGB"))


def capacidade(capa):
    return capa.size // 8 - 4


def esconder(pacote, capa):
    if len(pacote) > capacidade(capa):
        raise ValueError(f"a capa comporta {max(0, capacidade(capa))} bytes e o dado cifrado tem {len(pacote)}; use uma capa maior")
    bits = np.unpackbits(np.frombuffer(struct.pack(">I", len(pacote)) + pacote, np.uint8))
    plano = capa.ravel().copy()
    plano[:len(bits)] = plano[:len(bits)] & 0xFE | bits
    return plano.reshape(capa.shape)


def extrair(estego):
    bits = estego.ravel() & 1
    n = struct.unpack(">I", np.packbits(bits[:32]).tobytes())[0] if bits.size >= 32 else 0
    if not cifra.CAB.size <= n <= bits.size // 8 - 4:
        raise ValueError("nenhum dado da VITRAL-256 Dados escondido aqui")
    pacote = np.packbits(bits[32:32 + 8 * n]).tobytes()
    if pacote[:4] != cifra.MAGICO:
        raise ValueError("nenhum dado da VITRAL-256 Dados escondido aqui")
    return pacote


def psnr(a, b):
    mse = np.mean((a.astype(float) - b.astype(float)) ** 2)
    return math.inf if mse == 0 else 10 * math.log10(255 ** 2 / mse)
