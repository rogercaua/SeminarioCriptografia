"""Painel local da VITRAL-256. Uso: python app.py  ->  http://127.0.0.1:8257"""
import base64
import hashlib
import io
import json
import mimetypes
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import numpy as np
from PIL import Image, UnidentifiedImageError

import cifra
import conferir
import estego
import eventos
import exemplos
import metricas
from aes_ref import aes256

PORTA = 8257  # a versão só de imagens usa a 8256; as duas podem rodar juntas
MAX_BYTES = 44 * 2 ** 20  # shortcut: tudo em memória e em base64, trocar por envio em partes para arquivos maiores
LIMITE = 128 * 2 ** 20  # dois arquivos no máximo, em base64
RAIZ = Path(__file__).parent

_con = eventos.preparar()
MODELO, RESUMO_IA = eventos.treinar(_con)
_con.close()
_trava = threading.Lock()  # PBKDF2 e cifra usam muita CPU/RAM: uma operação por vez


def ler(d, campo="dados"):
    texto = d.get(campo)
    if not isinstance(texto, str) or "," not in texto:
        raise ValueError("escolha um arquivo")
    try:
        bruto = base64.b64decode(texto.split(",", 1)[1], validate=True)
    except ValueError:
        raise ValueError("o texto colado não é um dado cifrado em Base64") from None
    if not bruto:
        raise ValueError("o arquivo está vazio")
    if len(bruto) > MAX_BYTES + 2 ** 16:  # folga para decifrar o que foi cifrado no limite
        raise ValueError("arquivo grande demais (máximo de 44 MiB)")
    return bruto


def ler_claro(d):
    bruto = ler(d)
    if len(bruto) > MAX_BYTES:
        raise ValueError("arquivo grande demais (máximo de 44 MiB)")
    return bruto


def senha(d):
    if not isinstance(d.get("senha"), str) or not d["senha"]:
        raise ValueError("informe a senha")
    return d["senha"]


def nome(d):
    return str(d.get("nome") or "dados.bin").replace("\\", "/").rsplit("/", 1)[-1]


def b64(b):
    return base64.b64encode(b).decode()


def png(arr):
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG")
    return "data:image/png;base64," + b64(buf.getvalue())


def mapa(b):
    """Os primeiros bytes do dado desenhados como pontos: serve para qualquer tipo."""
    v = np.frombuffer(b[:65536], np.uint8)
    lado = int(np.ceil(np.sqrt(len(v))))
    return png(np.pad(v, (0, lado * lado - len(v))).reshape(lado, lado))


def conteudo(n, dados):
    n = nome({"nome": n})
    return {"nome": n, "tipo": mimetypes.guess_type(n)[0] or "application/octet-stream", "dados": b64(dados),
            "sha": hashlib.sha256(dados).hexdigest()}


def medidas(b):
    v = np.frombuffer(b, np.uint8)
    return {"entropia": metricas.entropia(v), "histograma": np.bincount(v, minlength=256).tolist(),
            "correlacao": metricas.correlacao(v[:4 << 20]), "repetidos": metricas.blocos_repetidos(v), "mapa": mapa(b)}


def abrir_pacote(pacote, s):
    try:
        r = cifra.decifrar(pacote, s)
    except cifra.FalhaAutenticacao:
        eventos.registrar("decifrar_falha")
        raise
    eventos.registrar("decifrar_ok")
    return r


def provas(n, dados, pacote, s):
    """Reabre o pacote entregue e refaz a conta com conferir.py; nada aqui reaproveita o resultado da cifragem."""
    nome_volta, volta = cifra.decifrar(base64.b64decode(pacote), s)
    pac, claro = base64.b64decode(pacote), cifra.moldura(n, dados)
    total = (len(claro) + 15) // 16
    meio = (len(claro) // 16 - 1) // 2 if len(claro) >= 16 else 0  # bloco completo no meio do dado
    amostra = {0, meio, total - 1} | {int.from_bytes(os.urandom(6)) % total for _ in range(61)}
    _, salt, iv = cifra.CAB.unpack_from(pac)
    passos = conferir.rastro(conferir.contador(iv, meio), *conferir.esquema(conferir.chaves(s, salt)[0]))
    vetor = np.frombuffer(bytes.fromhex("00112233445566778899aabbccddeeff"), np.uint8).reshape(1, 16)
    a, b = np.frombuffer(dados, np.uint8), np.frombuffer(volta, np.uint8)
    return {"sha_original": hashlib.sha256(dados).hexdigest(), "sha_volta": hashlib.sha256(volta).hexdigest(),
            "nome_ok": n == nome_volta, "diferentes": int((a != b).sum()) if len(a) == len(b) else max(len(a), len(b)),
            "bytes": len(dados), "total_blocos": total, "conferencia": conferir.conferir(claro, pac, s, sorted(amostra)),
            "fips": aes256(bytes(range(32))).cifrar(vetor).tobytes().hex() == "8ea2b7ca516745bfeafc49904b496089",
            "bloco": {"n": meio, "passos": passos, "claro": list(claro[16 * meio:16 * meio + 16]),
                      "cifrado": list(pac[cifra.CAB.size + 16 * meio:cifra.CAB.size + 16 * meio + 16])}}


def cifrar(d):
    dados, s, n = ler_claro(d), senha(d), nome(d)
    pac = cifra.cifrar(dados, s, n)
    eventos.registrar("cifrar")
    corpo, pacote = pac[cifra.CAB.size + 1 + len(n.encode()):], b64(pac)
    mudou = metricas.npcr_uaci(np.frombuffer(dados, np.uint8), np.frombuffer(corpo, np.uint8))[0]
    return {"pacote": pacote, "nome": n + ".vtr", "antes": medidas(dados), "depois": medidas(corpo), "mudou": mudou,
            "provas": provas(n, dados, pacote, s)}


def decifrar(d):
    return conteudo(*abrir_pacote(ler(d), senha(d)))


def esconder(d):
    capa, dados = estego.abrir_capa(io.BytesIO(ler(d, "capa"))), ler_claro(d)
    pac = cifra.cifrar(dados, senha(d), nome(d))
    e = estego.esconder(pac, capa)
    eventos.registrar("cifrar")
    return {"imagem": png(e), "psnr": estego.psnr(capa, e), "uso": 100 * len(pac) / estego.capacidade(capa)}


def extrair(d):
    return conteudo(*abrir_pacote(estego.extrair(estego.abrir_capa(io.BytesIO(ler(d)))), senha(d)))


def adulterar(d):
    pac, s = ler(d), senha(d)
    n, dados = abrir_pacote(pac, s)  # a senha tem de valer antes, senão a recusa não prova nada
    i = int.from_bytes(os.urandom(6)) % len(dados) if dados else 0
    pos = 1 + len(n.encode()) + i if dados else 0
    mau = bytearray(pac)
    mau[cifra.CAB.size + pos] ^= 1
    mau = bytes(mau)
    eventos.registrar("arquivo_alterado")
    try:
        abrir_pacote(mau, s)
        recusa = None
    except cifra.FalhaAutenticacao as e:
        recusa = str(e)
    claro2, guardada, calculada, _ = cifra.abrir_sem_conferir(mau, s)
    return {"pacote": b64(mau), "nome": "adulterado.vtr", "onde": f"byte {i}", "recusa": recusa,
            "byte": [pac[cifra.CAB.size + pos], mau[cifra.CAB.size + pos]],
            "claro": [cifra.moldura(n, dados)[pos], claro2[pos]], "etiqueta": guardada.hex(), "calculada": calculada.hex()}


def diferencial(d):
    dados = ler_claro(d)
    i, salt, outro = int.from_bytes(os.urandom(6)) % len(dados), os.urandom(16), bytearray(dados)
    outro[i] ^= 1
    pacs = [cifra.cifrar(p, "senha de teste", "", salt, iteracoes=1) for p in (dados, bytes(outro))]
    a, b = (np.frombuffer(p, np.uint8, offset=cifra.CAB.size + 1) for p in pacs)
    npcr, uaci = metricas.npcr_uaci(a, b)
    fixa = os.urandom(7)
    xa, xb = (metricas.xor_fixa(np.frombuffer(bytes(p), np.uint8), fixa) for p in (dados, outro))  # controle: cifra fraca
    # dentro da cifra: dois blocos que diferem em 1 bit, comparados rodada a rodada
    esq, bloco = conferir.esquema(conferir.chaves("senha de teste", salt, 1)[0]), os.urandom(16)
    r1, r2 = (conferir.rastro(x, *esq) for x in (bloco, bytes([bloco[0] ^ 1]) + bloco[1:]))
    return {"mapa": mapa((a ^ b).tobytes()), "controle_mapa": mapa((xa ^ xb).tobytes()), "npcr": npcr, "uaci": uaci,
            **metricas.criticos_npcr_uaci(len(dados)), "onde": f"byte {i}", "byte": [dados[i], outro[i]],
            "ivs": [p[20:36].hex() for p in pacs], "saidas": [p[cifra.CAB.size:cifra.CAB.size + 16].hex() for p in pacs],
            "controle": {"npcr": metricas.npcr_uaci(xa, xb)[0], "bytes": int((xa != xb).sum())}, "bytes": int((a != b).sum()),
            "total": len(dados), "rodadas": [[u ^ v for u, v in zip(p["saida"], q["saida"])] for p, q in zip(r1, r2)]}


def tentar(d):
    """Uma tentativa de senha, com o que o atacante enxerga."""
    pac, s = ler(d), senha(d)
    t = time.perf_counter()
    claro, guardada, calculada, chave = cifra.abrir_sem_conferir(pac, s)
    ms = 1000 * (time.perf_counter() - t)
    ok = guardada == calculada
    eventos.registrar("decifrar_ok" if ok else "decifrar_falha")
    return {"ok": ok, "ms": ms, "chave": chave.hex()[:16], "etiqueta": guardada.hex(), "calculada": calculada.hex(),
            "mini": mapa(claro[:2304]), "achado": conteudo(claro[1:1 + claro[0]].decode(), claro[1 + claro[0]:]) if ok else None}


def painel():
    con = eventos.conectar()
    try:
        serie = con.execute("SELECT ts/86400*86400, COUNT(*) FROM eventos WHERE simulado=1 GROUP BY 1 ORDER BY 1").fetchall()
        reais = dict(con.execute("SELECT tipo, COUNT(*) FROM eventos WHERE simulado=0 GROUP BY 1").fetchall())
        log = con.execute("SELECT ts, tipo FROM eventos WHERE simulado=0 ORDER BY rowid DESC LIMIT 15").fetchall()
        arq = RAIZ / "resultados" / "metricas.json"
        return {"ia": RESUMO_IA, "alertas": eventos.alertas(con, MODELO), "serie": serie, "reais": reais, "log": log,
                "cifra_sha256": hashlib.sha256((RAIZ / "cifra.py").read_bytes()).hexdigest(),
                "metricas": json.loads(arq.read_text()) if arq.exists() else None}
    finally:
        con.close()


ROTAS = {f.__name__: f for f in (cifrar, decifrar, esconder, extrair, adulterar, diferencial, tentar)}


class Servidor(BaseHTTPRequestHandler):
    def responder(self, corpo, tipo="application/json; charset=utf-8", status=200):
        corpo = corpo if isinstance(corpo, bytes) else json.dumps(corpo, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(corpo)

    def local(self):
        """Barra outros sites (DNS rebinding) de usarem o painel pelo navegador da vítima."""
        if self.headers.get("Host") in (f"127.0.0.1:{PORTA}", f"localhost:{PORTA}"):
            return True
        self.responder({"erro": "host não permitido"}, status=403)

    def do_GET(self):
        if not self.local():
            return
        if self.path == "/":
            self.responder((RAIZ / "painel.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/painel":
            self.responder(painel())
        elif (ex := exemplos.TODOS.get(self.path.removeprefix("/exemplo/"))):
            self.responder(ex(), "application/octet-stream")
        else:
            self.responder({"erro": "não encontrado"}, status=404)

    def do_POST(self):
        if not self.local():
            return
        rota = ROTAS.get(self.path.removeprefix("/api/"))
        tam = self.headers.get("Content-Length", "")
        # exigir JSON força o preflight de CORS e impede envio por formulário de outro site
        if not rota or not tam.isdigit() or self.headers.get("Content-Type") != "application/json":
            return self.responder({"erro": "requisição inválida"}, status=400)
        if int(tam) > LIMITE:
            return self.responder({"erro": "arquivo grande demais"}, status=413)
        try:
            dados = json.loads(self.rfile.read(int(tam)))
            if not isinstance(dados, dict):
                raise ValueError("requisição inválida")
            with _trava:
                self.responder(rota(dados))
        except UnidentifiedImageError:
            self.responder({"erro": "a capa precisa ser uma imagem"}, status=400)
        except (ValueError, OSError, Image.DecompressionBombError) as e:
            self.responder({"erro": str(e)}, status=400)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print(f"VITRAL-256 em http://127.0.0.1:{PORTA}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORTA), Servidor).serve_forever()
