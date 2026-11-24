"""Métricas do esquema VITRAL-256 e ataques, por tipo de dado. Gera resultados/metricas.json.

Uso: python metricas.py   (todas as amostras são aleatórias; os números variam um pouco a cada execução)
"""
import hashlib
import json
import math
import os
import time
from concurrent.futures import ProcessPoolExecutor
from itertools import combinations
from pathlib import Path

import numpy as np

import cifra
import estego
import eventos
import exemplos
import imagens
import nist
from aes_ref import SBOX as SBOX_AES, aes256
from cifra import vitral

PASTA = Path(__file__).with_name("resultados")
BITS = np.array([bin(i).count("1") for i in range(256)])
CIFRAS = {"VITRAL-256": vitral, "AES-256": aes256}


def aleatorio(*forma):
    return np.frombuffer(os.urandom(math.prod(forma)), np.uint8).reshape(forma).copy()


def resumo(v):
    v = np.asarray(v, float)
    return {"media": v.mean(), "desvio": v.std(), "min": v.min(), "max": v.max(), "n": v.size}


def xor_fixa(px, chave):
    return px ^ np.resize(np.frombuffer(chave, np.uint8), px.size).reshape(px.shape)


# ---------- S-box ----------
def walsh(v):
    w = v.astype(np.int64)
    h = 1
    while h < len(w):
        w = w.reshape(-1, 2 * h)
        w = np.hstack((w[:, :h] + w[:, h:], w[:, :h] - w[:, h:])).ravel()
        h *= 2
    return w


def grau_algebrico(S):
    melhor = 0
    for bit in range(8):
        f = (S >> bit & 1).astype(np.uint8)
        for k in range(8):  # transformada de Möbius
            g = f.reshape(-1, 2, 1 << k)
            g[:, 1] ^= g[:, 0]
        melhor = max(melhor, int(BITS[np.flatnonzero(f)].max(initial=0)))
    return melhor


def metricas_sbox(S):
    x = np.arange(256)
    nl = 128 - max(int(np.abs(walsh(1 - 2 * (BITS[S & m] & 1))).max()) for m in range(1, 256)) // 2
    du = max(int(np.bincount(S[x] ^ S[x ^ d], minlength=256).max()) for d in range(1, 256))
    sac = np.mean([BITS[S[x] ^ S[x ^ 1 << b]].mean() / 8 for b in range(8)])
    return {"nao_linearidade": nl, "uniformidade_diferencial": du, "sac": float(sac),
            "grau_algebrico": grau_algebrico(S.copy()), "pontos_fixos": int((S == x).sum())}


# ---------- difusão ----------
def numero_de_ramos(matriz, poli):
    """Matriz MDS (todos os menores não nulos) equivale a 5 ramos, o máximo possível."""
    def det(M):
        if len(M) == 1:
            return M[0][0]
        r = 0
        for j, v in enumerate(M[0]):
            r ^= cifra.gf_mul(v, det([l[:j] + l[j + 1:] for l in M[1:]]), poli)
        return r
    mds = all(det([[matriz[i][j] for j in c] for i in l])
              for k in range(1, 5) for l in combinations(range(4), k) for c in combinations(range(4), k))
    return 5 if mds else None


def avalanche(fabrica, rodadas=None, chaves=40, n=500):
    texto, chave = [], []
    for _ in range(chaves):
        k = os.urandom(32)
        c, p = fabrica(k), aleatorio(n, 16)
        q = p.copy()
        pos = np.random.default_rng().integers(0, 128, n)
        q[np.arange(n), pos // 8] ^= (1 << pos % 8).astype(np.uint8)
        base = c.cifrar(p, rodadas)
        texto.append(BITS[base ^ c.cifrar(q, rodadas)].sum(1) / 1.28)
        k2 = bytearray(k)
        bit = int.from_bytes(os.urandom(1))
        k2[bit // 8] ^= 1 << bit % 8
        chave.append(BITS[base ^ fabrica(bytes(k2)).cifrar(p, rodadas)].sum(1) / 1.28)
    return np.concatenate(texto), np.concatenate(chave)


def sac_bic(fabrica, N=4096):
    soma_sac, bic = [], []
    c, p = fabrica(os.urandom(32)), aleatorio(N, 16)
    base = c.cifrar(p)
    for i in range(128):
        q = p.copy()
        q[:, i // 8] ^= 128 >> i % 8
        d = np.unpackbits(base ^ c.cifrar(q), axis=1).astype(np.float32)
        soma_sac.append(d.mean(0))
        bic.append(np.abs(np.corrcoef(d.T)[np.triu_indices(128, 1)]))
    bic = np.concatenate(bic)
    return {"sac": resumo(np.concatenate(soma_sac)), "sac_desvio_ideal": 0.5 / math.sqrt(N),
            "bic_media": float(bic.mean()), "bic_media_ideal": math.sqrt(2 / math.pi / N), "bic_max": float(bic.max())}


# ---------- dados ----------
def entropia(px):
    p = np.bincount(px.ravel(), minlength=256) / px.size
    return float(-(p[p > 0] * np.log2(p[p > 0])).sum())


def qui_quadrado(px):
    h, e = np.bincount(px.ravel(), minlength=256), px.size / 256
    q = float(((h - e) ** 2 / e).sum())
    return q, nist.igamc(127.5, q / 2)


def correlacao(v):
    """Correlação entre bytes vizinhos; None quando não há variação para medir."""
    a, b = v[:-1], v[1:]
    return float(np.corrcoef(a, b)[0, 1]) if len(v) > 2 and a.std() and b.std() else None


def npcr_uaci(a, b):
    return float((a != b).mean() * 100), float(np.abs(a.astype(np.int16) - b).mean() / 255 * 100)


def criticos_npcr_uaci(n, F=255):
    """Faixas de aceitação (5%) de Wu, Noonan e Agaian (2011) para n amostras de 8 bits."""
    mu, s = F / (F + 1), math.sqrt(F / n) / (F + 1)
    mu2 = (F + 2) / (3 * F + 3)
    s2 = math.sqrt((F + 2) * (F * F + 2 * F + 3) / (18 * (F + 1) ** 2 * n * F))
    return {"npcr_min": 100 * (mu - 1.645 * s), "npcr_ideal": 100 * mu,
            "uaci_min": 100 * (mu2 - 1.96 * s2), "uaci_max": 100 * (mu2 + 1.96 * s2), "uaci_ideal": 100 * mu2}


def cifrados(v, senha="senha de teste", salt=None):
    pac = cifra.cifrar(v.tobytes(), senha, "", salt, iteracoes=1)
    return np.frombuffer(pac, np.uint8, offset=cifra.CAB.size + 1)


def blocos_repetidos(v):
    b = v[:len(v) // 16 * 16].reshape(-1, 16)
    return 100 * (1 - len(np.unique(b, axis=0)) / len(b)) if len(b) else 0.0


def analisar(v):
    """Mesma análise para qualquer tipo: o dado é só uma sequência de bytes."""
    c = cifrados(v)
    cheio = v[:len(v) // 16 * 16]  # ECB só aceita blocos completos
    versoes = {"original": v, "vitral": c, "ecb": vitral(os.urandom(32)).cifrar(cheio.reshape(-1, 16)).ravel(), "xor": xor_fixa(v, os.urandom(7))}
    r = {"bytes": len(v)}
    for k, x in versoes.items():
        q, p = qui_quadrado(x)
        r[k] = {"entropia": entropia(x), "qui2": q, "qui2_p": p, "correlacao": correlacao(x), "blocos_repetidos_pct": blocos_repetidos(x)}
    # 1 bit trocado, mesmo salt (mesma chave): é o ataque diferencial
    trocas = []
    for _ in range(30):
        salt, v2 = os.urandom(16), v.copy()
        i = int.from_bytes(os.urandom(4)) % v.size
        v2[i] ^= 1 << (i % 8)
        trocas.append(npcr_uaci(cifrados(v, salt=salt), cifrados(v2, salt=salt)))
    crit = criticos_npcr_uaci(v.size)
    npcr, uaci = np.array(trocas).T
    r["diferencial"] = {"npcr": resumo(npcr), "uaci": resumo(uaci), "criticos": crit,
                        "npcr_aprovados": int((npcr >= crit["npcr_min"]).sum()),
                        "uaci_aprovados": int(((uaci >= crit["uaci_min"]) & (uaci <= crit["uaci_max"])).sum())}
    return r


# ---------- NIST ----------
NB = 125_000  # 1 milhão de bits


def _nist(nome):
    zeros, ch = np.zeros(NB, np.uint8), os.urandom(32)
    if nome == "XOR repetida":
        d = xor_fixa(imagens.paisagem(256).ravel()[:NB], ch[:7])
    else:
        d = cifra.ctr(CIFRAS[nome](ch), os.urandom(16), zeros)
    return nist.todos(np.unpackbits(d))


def bateria_nist(pool, nome, n=100):
    v = list(pool.map(_nist, [nome] * n))
    saida = {}
    for t in v[0]:
        ps = np.array([x[t] for x in v])
        h = np.bincount(np.minimum((ps * 10).astype(int), 9), minlength=10)
        saida[t] = {"aprovadas": int((ps >= 0.01).sum()), "uniformidade_p": nist.igamc(4.5, float(((h - n / 10) ** 2 / (n / 10)).sum()) / 2)}
    return saida


# ---------- ataques ----------
def _tentar(args):
    pac, ini, fim = args
    for i in range(ini, fim):
        try:
            cifra.decifrar(pac, f"{i:03d}")
            return i
        except cifra.FalhaAutenticacao:
            pass


def forca_bruta(pool):
    r = {"espaco_chaves": 2.0 ** 256}
    n, t = 2000, time.perf_counter()
    bloco = np.zeros((1, 16), np.uint8)
    for i in range(n):
        vitral(i.to_bytes(32)).cifrar(bloco)
    r["chaves_por_s"] = n / (time.perf_counter() - t)
    t = time.perf_counter()
    for _ in range(20):
        cifra.derivar("x", bytes(16))
    r["senhas_por_s_1_nucleo"] = 20 / (time.perf_counter() - t)
    ano = 365.25 * 86400
    # atacante hipotético: 10^12 chaves/s e 10^6 senhas/s
    r["anos_chave_256_a_1e12_por_s"] = 2.0 ** 255 / 1e12 / ano
    r["senhas"] = {nome: {"espaco": a ** b, "anos_1_nucleo": a ** b / 2 / r["senhas_por_s_1_nucleo"] / ano,
                          "anos_1e6_por_s": a ** b / 2 / 1e6 / ano}
                   for nome, a, b in (("PIN 4 dígitos", 10, 4), ("6 minúsculas", 26, 6), ("8 alfanuméricos", 62, 8), ("12 de 94 símbolos", 94, 12))}
    pin = f"{int.from_bytes(os.urandom(2)) % 1000:03d}"
    pac = cifra.cifrar(b"segredo", pin, "segredo.txt")
    t = time.perf_counter()
    fut = [pool.submit(_tentar, (pac, i, min(i + 25, 1000))) for i in range(0, 1000, 25)]
    achou = [f.result() for f in fut]
    achado = next(x for x in achou if x is not None)
    r["ataque_real_pin3"] = {"quebrado": f"{achado:03d}" == pin, "segundos_espaco_todo": time.perf_counter() - t, "nucleos": os.cpu_count()}
    return r


def quebrar_xor(px):
    """Ataque estatístico contra a XOR repetida: área lisa entrega a chave direto pela moda por posição."""
    chave = os.urandom(7)
    c = xor_fixa(px, chave).ravel()
    coinc = {t: float((c[:-t] == c[t:]).mean()) for t in range(1, 25)}
    t = max(coinc, key=coinc.get)
    moda_orig = int(np.bincount(px.ravel()).argmax())  # atacante supõe a cor dominante (fundo)
    achada = bytes(int(np.bincount(c[i::t]).argmax()) ^ moda_orig for i in range(t))
    return {"tamanho_achado": t, "chave_recuperada": achada[:7] == chave and t % 7 == 0}


def integridade():
    dados = exemplos.texto()[:768]
    pac = cifra.cifrar(dados, "certa", iteracoes=1)
    rej = 0
    for i in range(8 * len(pac)):
        m = bytearray(pac)
        m[i // 8] ^= 1 << i % 8
        try:
            cifra.decifrar(bytes(m), "certa", iteracoes=1)
        except ValueError:
            rej += 1
    er = 0
    for i in range(2000):
        try:
            cifra.decifrar(pac, f"errada{i}", iteracoes=1)
        except cifra.FalhaAutenticacao:
            er += 1
    return {"bits_testados": 8 * len(pac), "bits_rejeitados": rej, "senhas_erradas": 2000, "senhas_rejeitadas": er,
            "cifragens_distintas_de_1000": len({cifra.cifrar(dados, "s", iteracoes=1) for _ in range(1000)})}


def metricas_estego():
    capa, r = imagens.paisagem(512), {}
    for nome, f in exemplos.TODOS.items():
        dados = f()
        pac = cifra.cifrar(dados, "s", nome, iteracoes=1)
        if len(pac) > estego.capacidade(capa):
            r[nome] = {"cabe": False, "usado_bytes": len(pac)}
            continue
        e = estego.esconder(pac, capa)
        r[nome] = {"cabe": True, "usado_bytes": len(pac), "psnr_db": estego.psnr(capa, e),
                   "recuperado": cifra.decifrar(estego.extrair(e), "s", iteracoes=1) == (nome, dados)}
    return {"capa": "512x512", "capacidade_bytes": estego.capacidade(capa), "tipos": r}


def _ia(semente):
    con = eventos.conectar(":memory:")
    eventos.simular(con, semente)
    r = eventos.treinar(con)[1]
    return r["ia"]["f1"], r["regra_fixa"]["f1"]


def main():
    PASTA.mkdir(exist_ok=True)
    R = {"cifra_sha256": hashlib.sha256(Path(cifra.__file__).read_bytes()).hexdigest()}
    with ProcessPoolExecutor() as pool:
        s = [m for m in pool.map(metricas_sbox, [S for _ in range(125) for S in vitral(os.urandom(32)).sboxes], chunksize=20)]
        R["sbox"] = {"vitral_500": {k: resumo([x[k] for x in s]) for k in s[0]}, "aes": metricas_sbox(SBOX_AES)}
        print("S-box ok", flush=True)
        R["difusao"] = {"ramos": numero_de_ramos(cifra.MATRIZ, cifra.POLI), "sboxes_ativas_4_rodadas": 25,
                        "peso_diferencial_4_rodadas": 25 * 6, "ordens_validas_deslocamento": len(cifra.ORDENS)}
        R["avalanche"], R["avalanche_por_rodada"], R["sac_bic"] = {}, {}, {}
        for nome, f in CIFRAS.items():
            t, k = avalanche(f)
            R["avalanche"][nome] = {"texto": resumo(t), "chave": resumo(k)}
            R["avalanche_por_rodada"][nome] = {r: float(avalanche(f, r, 10, 400)[0].mean()) for r in range(1, f(bytes(32)).rodadas + 1)}
            R["sac_bic"][nome] = sac_bic(f)
        print("difusão ok", flush=True)
        R["tipos"] = {nome: analisar(np.frombuffer(f(), np.uint8)) for nome, f in exemplos.TODOS.items()}
        print("tipos ok", flush=True)
        R["nist"] = {n: bateria_nist(pool, n) for n in (*CIFRAS, "XOR repetida")}
        print("NIST ok", flush=True)
        R["forca_bruta"] = forca_bruta(pool)
        R["ia_10_sementes"] = dict(zip(("ia", "regra_fixa"), map(resumo, zip(*pool.map(_ia, range(101, 111))))))
    R["quebra_xor"] = quebrar_xor(imagens.vitral_colorido())
    R["integridade"] = integridade()
    R["esteganografia"] = metricas_estego()
    R["vazao_MB_s"] = {}
    for nome, f in CIFRAS.items():
        d, c = np.zeros(16 << 20, np.uint8), f(bytes(32))
        t = time.perf_counter()
        cifra.ctr(c, bytes(16), d)
        R["vazao_MB_s"][nome] = d.size / 2 ** 20 / (time.perf_counter() - t)
    R["ia"] = eventos.treinar(eventos.preparar())[1]
    (PASTA / "metricas.json").write_text(json.dumps(R, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
