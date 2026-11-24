"""Segunda VITRAL-256, escrita a partir da especificação, byte a byte e sem NumPy, para conferir a primeira.

Não importa cifra.py: um erro só passa despercebido se existir igual nas duas.
Uso: python conferir.py original cifrado.vtr   (pede a senha e confere TODOS os blocos, sem o painel)
"""
import functools
import hashlib
import hmac
import itertools
import struct

CAB = struct.Struct(">4s16s16s")
ORDENS = list(itertools.permutations(range(4)))
MATRIZ = [[1, 5, 2, 1], [1, 1, 5, 2], [2, 1, 1, 5], [5, 2, 1, 1]]


@functools.cache
def mul(a, b, poli):
    """Produto de polinômios e depois o resto da divisão por poli."""
    p = 0
    for i in range(8):
        if b >> i & 1:
            p ^= a << i
    for i in range(14, 7, -1):
        if p >> i & 1:
            p ^= poli << (i - 8)
    return p


@functools.cache
def inverso(x):
    y = 1
    for _ in range(254):  # x^254 = x^-1 em GF(2^8), e 0 vai para 0
        y = mul(y, x, 0x11D)
    return y


def sbox(fluxo):
    while True:
        L, sorteio = [next(fluxo) for _ in range(8)], next(fluxo)
        t = [sum(((L[k] & inverso(x)).bit_count() & 1) << k for k in range(8)) for x in range(256)]
        livres = [c for c in range(256) if all((v ^ c) not in (x, x ^ 255) for x, v in enumerate(t))]
        if len(set(t)) == 256 and livres:  # L inversível equivale a 256 saídas distintas
            return [v ^ livres[sorteio % len(livres)] for v in t]


@functools.lru_cache(8)
def esquema(chave):
    b = hashlib.shake_256(b"VITRAL-256/v1" + chave).digest(16384)
    fluxo = iter(b[17 * 16 + 16:])
    return ([sbox(fluxo) for _ in range(4)], [ORDENS[v % 24] for v in b[17 * 16:17 * 16 + 16]],
            MATRIZ, 0x11D, [b[16 * i:16 * i + 16] for i in range(17)])


def rastro(bloco, sboxes, deslocamentos, matriz, poli, subchaves):
    """Cifra um bloco e devolve o estado (16 bytes, em colunas) depois de cada passo de cada rodada."""
    x = [int(a) ^ int(k) for a, k in zip(bloco, subchaves[0])]
    passos = [{"entrada": list(map(int, bloco)), "subchave": list(map(int, subchaves[0])), "saida": x}]
    for r, d in enumerate(deslocamentos, 1):
        s = [int(sboxes[i % 4][v]) for i, v in enumerate(x)]
        t = [s[4 * ((i // 4 + d[i % 4]) % 4) + i % 4] for i in range(16)]
        m = t
        if r < len(deslocamentos):  # a última rodada não tem mistura
            m = [functools.reduce(int.__xor__, (mul(t[i - i % 4 + j], matriz[i % 4][j], poli) for j in range(4))) for i in range(16)]
        k = list(map(int, subchaves[r]))
        x = [a ^ b for a, b in zip(m, k)]
        passos.append({"substituicao": s, "permutacao": t, "mistura": m, "subchave": k, "saida": x})
    return passos


def contador(iv, i):
    return iv[:8] + (int.from_bytes(iv[8:]) ^ i).to_bytes(8)


def chaves(senha, salt, iteracoes=600_000):
    mestre = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, iteracoes)
    return [hmac.new(mestre, r, "sha256").digest() for r in (b"vitral2 cifra", b"vitral2 mac")]


def conferir(claro, pacote, senha, indices=None, iteracoes=600_000):
    """`claro`: tamanho do nome + nome + conteúdo. Recalcula a etiqueta e recifra os blocos pedidos (todos, se None)."""
    _, salt, iv = CAB.unpack_from(pacote)
    corpo = pacote[CAB.size:]
    k_cifra, k_mac = chaves(senha, salt, iteracoes)
    etiqueta = hmac.new(k_mac, salt + claro, "sha256").digest()[:16]
    indices = range((len(claro) + 15) // 16) if indices is None else indices
    esq, certos = esquema(k_cifra), 0
    for i in indices:
        fluxo = rastro(contador(iv, i), *esq)[-1]["saida"]
        certos += corpo[16 * i:16 * i + 16] == bytes(a ^ b for a, b in zip(claro[16 * i:16 * i + 16], fluxo))
    return {"tamanho_ok": len(corpo) == len(claro), "etiqueta": etiqueta.hex(), "etiqueta_ok": etiqueta == iv,
            "blocos": len(indices), "certos": certos}


def main(original, cifrado):
    import getpass
    from pathlib import Path
    dados, pacote = Path(original).read_bytes(), Path(cifrado).read_bytes()
    n = len(pacote) - CAB.size - len(dados)  # o que sobra é o prefixo com o nome
    if pacote[:4] != b"VTR2" or not 1 <= n <= 256:
        return print("o arquivo cifrado não corresponde a este original") or 2
    senha = getpass.getpass("senha: ")
    _, salt, iv = CAB.unpack_from(pacote)
    esq = esquema(chaves(senha, salt)[0])
    fluxo = b"".join(bytes(rastro(contador(iv, i), *esq)[-1]["saida"]) for i in range(16))
    prefixo = bytes(a ^ b for a, b in zip(pacote[CAB.size:CAB.size + n], fluxo))
    r = conferir(prefixo + dados, pacote, senha)
    ok = r["tamanho_ok"] and prefixo[0] == n - 1
    print(f"tamanho    {'ok' if ok else 'FALHOU'}\netiqueta   {'ok' if r['etiqueta_ok'] else 'FALHOU'}  {r['etiqueta']}")
    print(f"blocos     {r['certos']} de {r['blocos']} iguais")
    return 0 if ok and r["etiqueta_ok"] and r["certos"] == r["blocos"] else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
