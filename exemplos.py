"""Um exemplo de cada tipo de dado, gerado por código (sem direitos de terceiros)."""
import io
import wave
import zipfile

import numpy as np
from PIL import Image

import imagens


def texto():
    return ("Relatório interno. Este texto repete frases para deixar padrões visíveis: ação, coração, você. " * 400).encode()


def imagem(formato="BMP"):  # BMP não comprime, então o padrão da imagem aparece nos bytes
    buf = io.BytesIO()
    Image.fromarray(imagens.vitral_colorido(256)).save(buf, formato)
    return buf.getvalue()


def audio():
    t = np.arange(3 * 8000) / 8000
    notas = np.repeat([440, 554, 659, 440, 554, 659], 4000)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setparams((1, 2, 8000, 0, "NONE", ""))
        w.writeframes((12000 * np.sin(2 * np.pi * notas * t)).astype("<i2").tobytes())
    return buf.getvalue()


def tabela():
    v = np.random.default_rng(1).integers(0, 10_000, 3000)
    return "\n".join(["id,cidade,valor", *(f"{i},Recife,{x}" for i, x in enumerate(v))]).encode()


def compactado():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for nome, f in (("mensagem.txt", texto), ("tabela.csv", tabela)):
            z.writestr(zipfile.ZipInfo(nome), f(), zipfile.ZIP_DEFLATED)  # ZipInfo fixa a data: sempre os mesmos bytes
    return buf.getvalue()


TODOS = {"mensagem.txt": texto, "imagem.bmp": imagem, "audio.wav": audio, "tabela.csv": tabela,
         "documento.pdf": lambda: imagem("PDF"), "arquivos.zip": compactado}
