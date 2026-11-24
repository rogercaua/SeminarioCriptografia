"""Eventos (SQLite) e IA: rede neural que aprende o comportamento normal e sinaliza janelas usuário × hora anormais."""
import sqlite3
import time
from pathlib import Path

import numpy as np

DB = Path(__file__).with_name("eventos.db")
DIAS, USUARIOS, INICIO = 30, 120, 1_793_491_200  # 01/11/2026 00:00 UTC; simulação reproduzível
FIM_TREINO = INICIO + 15 * 86400
ANOMALIAS = ["autenticação", "falha de decifragem", "arquivo alterado", "acesso atípico", "volume de eventos"]
ATRIBUTOS = ["login_falha", "decifrar_falha", "arquivo_alterado", "ips_novos", "total"]  # um por anomalia


def conectar(caminho=None):
    con = sqlite3.connect(caminho or DB)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS eventos(ts INTEGER NOT NULL, usuario TEXT NOT NULL, tipo TEXT NOT NULL,
                                           ip TEXT NOT NULL, simulado INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_eventos ON eventos(simulado, usuario, ts);
        CREATE TABLE IF NOT EXISTS gabarito(usuario TEXT, hora INTEGER, anomalia TEXT);""")
    return con


def registrar(tipo, usuario="local", ip="127.0.0.1"):
    con = conectar()
    with con:
        con.execute("INSERT INTO eventos VALUES(?,?,?,?,0)", (int(time.time()), usuario, tipo, ip))
    con.close()


def simular(con, semente=2026):
    """Tráfego normal em horário comercial + 5 tipos de anomalia do enunciado, de intensidade variada."""
    rng = np.random.default_rng(semente)
    ev, gab = [], []

    def add(u, hora, tipo, n, ips):
        for t in rng.integers(0, 3600, n):
            ev.append((INICIO + hora * 3600 + int(t), f"u{u:03d}", tipo, str(rng.choice(ips)), 1))

    for u in range(USUARIOS):
        ritmo, meu_ip = rng.gamma(4, 1.5), [f"10.0.{u}.1", f"10.0.{u}.2"]
        ips = meu_ip if u % 4 == 0 else meu_ip[:1]
        for d in range(DIAS):
            fim_de_semana = (d % 7) in (0, 6)  # 01/11/2026 é domingo
            for h in range(24):
                if rng.random() > (0.03 if h < 6 else 0.08 if fim_de_semana else 0.75 if 8 <= h < 18 else 0.12):
                    continue
                hora, n = 24 * d + h, 1 + rng.poisson(ritmo)
                add(u, hora, "login_ok", 1, ips)
                add(u, hora, "login_falha", rng.poisson(0.15), ips)
                add(u, hora, "decifrar_falha", rng.poisson(0.10), ips)
                add(u, hora, "arquivo_alterado", rng.poisson(0.05), ips)
                for tipo, k in zip(("cifrar", "decifrar_ok", "acesso"), rng.multinomial(n, (0.3, 0.3, 0.4))):
                    add(u, hora, tipo, k, ips)

    for _ in range(300):
        u, d, qual = rng.integers(USUARIOS), rng.integers(DIAS), int(rng.integers(5))
        h = rng.integers(0, 6) if qual == 3 else rng.integers(8, 20)
        hora, ips = int(24 * d + h), [f"10.0.{u}.1"]
        if qual < 3:
            add(u, hora, ["login_falha", "decifrar_falha", "arquivo_alterado"][qual], int(rng.integers(3, 25)), ips)
        elif qual == 3:
            add(u, hora, "acesso", int(rng.integers(5, 30)), [f"203.0.113.{i}" for i in rng.integers(1, 250, rng.integers(2, 6))])
        else:
            add(u, hora, "acesso", int(rng.integers(40, 200)), ips)
        gab.append((f"u{u:03d}", INICIO + hora * 3600, ANOMALIAS[qual]))
    with con:
        con.executemany("INSERT INTO eventos VALUES(?,?,?,?,?)", ev)
        con.executemany("INSERT INTO gabarito VALUES(?,?,?)", gab)


def janelas(con, simulado=1):
    """Agrega os eventos em janelas usuário × hora. Devolve [(usuario, hora)], contagens por atributo."""
    linhas = con.execute("""
        WITH conhecidos AS (SELECT usuario, ip FROM eventos WHERE simulado=1 AND ts < ?
                            GROUP BY usuario, ip HAVING COUNT(DISTINCT ts/3600) > 1)
        SELECT usuario, ts/3600*3600 AS hora, SUM(tipo='login_falha'), SUM(tipo='decifrar_falha'),
               SUM(tipo='arquivo_alterado'),
               COUNT(DISTINCT CASE WHEN c.ip IS NULL AND e.ip <> '127.0.0.1' THEN e.ip END), COUNT(*)
        FROM eventos e LEFT JOIN conhecidos c USING (usuario, ip)
        WHERE simulado=? GROUP BY usuario, hora ORDER BY hora""", (FIM_TREINO, simulado)).fetchall()
    return [l[:2] for l in linhas], np.array([l[2:] for l in linhas], float).reshape(-1, len(ATRIBUTOS))


class ModeloComportamental:
    """Rede neural 4-16-5 que prevê quantos eventos de cada tipo cada usuário deveria gerar naquela hora.

    Treino sem rótulos, com perda de Poisson. Nota da janela = maior desvio (deviance) acima do previsto.
    """

    QUANTIL = 0.9875  # escolhido em dados de validação (sementes 1 a 3), nunca no conjunto de teste

    def __init__(self, chaves, X, epocas=40, semente=7):
        rng = np.random.default_rng(semente)
        self.perfil = {}
        usuarios = np.array([u for u, _ in chaves])
        for u in set(usuarios.tolist()):
            m = usuarios == u
            self.perfil[u] = np.log(np.median(X[m, 4]))
        self.perfil_padrao = np.median(list(self.perfil.values()))
        C = self._contexto(chaves)
        self.media, self.desvio = C.mean(0), C.std(0) + 1e-6
        Z, Y = (C - self.media) / self.desvio, np.minimum(X, np.quantile(X, 0.99, axis=0))
        self.P = [rng.normal(0, 1 / np.sqrt(Z.shape[1]), (Z.shape[1], 16)), rng.normal(0, 0.025, (16, Y.shape[1])),
                  np.zeros(16), np.log(Y.mean(0) + 1e-3)]
        m, v, passo = [np.zeros_like(p) for p in self.P], [np.zeros_like(p) for p in self.P], 0
        for _ in range(epocas):
            ordem = rng.permutation(len(Z))
            for i in range(0, len(Z), 256):
                z, y = Z[ordem[i:i + 256]], Y[ordem[i:i + 256]]
                oculta, taxa = self._rede(z)
                d = (taxa - y) / len(z)
                dh = (d @ self.P[1].T) * (1 - oculta ** 2)
                passo += 1
                for j, g in enumerate((z.T @ dh, oculta.T @ d, dh.sum(0), d.sum(0))):  # Adam
                    m[j] = 0.9 * m[j] + 0.1 * g
                    v[j] = 0.999 * v[j] + 0.001 * g * g
                    self.P[j] -= 0.005 * (m[j] / (1 - 0.9 ** passo)) / (np.sqrt(v[j] / (1 - 0.999 ** passo)) + 1e-8)
        self.limiar = float(np.quantile(self.desvios(chaves, X).max(1), self.QUANTIL))

    def _contexto(self, chaves):
        h = np.array([hora // 3600 % 24 for _, hora in chaves])
        p = np.array([self.perfil.get(u, self.perfil_padrao) for u, _ in chaves])
        a = 2 * np.pi * h / 24
        return np.column_stack([p, np.sin(a), np.cos(a), h < 6]).astype(float)

    def _rede(self, z):
        oculta = np.tanh(z @ self.P[0] + self.P[2])
        return oculta, np.exp(np.clip(oculta @ self.P[1] + self.P[3], -8, 6))

    def desvios(self, chaves, X):
        esperado = self._rede((self._contexto(chaves) - self.media) / self.desvio)[1] + 0.02
        return 2 * (X * np.log(np.maximum(X, 1e-9) / esperado) - (X - esperado)) * (X > esperado)


def _placar(previsto, real):
    vp, fp, fn = int((previsto & real).sum()), int((previsto & ~real).sum()), int((~previsto & real).sum())
    p, r = vp / max(vp + fp, 1), vp / max(vp + fn, 1)
    return {"vp": vp, "fp": fp, "fn": fn, "precisao": p, "recall": r, "f1": 2 * p * r / max(p + r, 1e-9)}


def treinar(con):
    """Treina sem rótulos nos 15 primeiros dias; o gabarito só entra na avaliação dos 15 últimos."""
    chaves, X = janelas(con)
    treino = np.array([h for _, h in chaves]) < FIM_TREINO
    modelo = ModeloComportamental([k for k, t in zip(chaves, treino) if t], X[treino])
    rotulo = {(u, h): a for u, h, a in con.execute("SELECT * FROM gabarito")}
    real, tipos = np.array([k in rotulo for k in chaves]), np.array([rotulo.get(k, "") for k in chaves])
    ia = modelo.desvios(chaves, X).max(1) > modelo.limiar
    z = ((X - X[treino].mean(0)) / (X[treino].std(0) + 1e-6)).max(1)  # regra fixa: z-score, mesmo quantil
    regra, teste = z > np.quantile(z[treino], modelo.QUANTIL), ~treino
    return modelo, {
        "eventos": con.execute("SELECT COUNT(*) FROM eventos WHERE simulado=1").fetchone()[0],
        "usuarios": USUARIOS, "dias": DIAS, "janelas": len(chaves), "janelas_teste": int(teste.sum()),
        "anomalias_teste": int((real & teste).sum()), "ia": _placar(ia[teste], real[teste]),
        "regra_fixa": _placar(regra[teste], real[teste]),
        "recall_por_tipo": {a: float(ia[teste & (tipos == a)].mean()) for a in ANOMALIAS},
    }


def preparar():
    con = conectar()
    if not con.execute("SELECT 1 FROM eventos WHERE simulado=1 LIMIT 1").fetchone():
        simular(con)
    return con


def alertas(con, modelo, limite=12):
    """Janelas anormais: as reais (uso do painel) primeiro, depois as simuladas mais recentes."""
    saida = []
    for simulado in (0, 1):
        chaves, X = janelas(con, simulado)
        if not len(X):
            continue
        d = modelo.desvios(chaves, X)
        nota = d.max(1)
        for i in sorted(np.flatnonzero(nota > modelo.limiar), key=lambda i: -chaves[i][1])[:limite - len(saida)]:
            j = int(d[i].argmax())
            saida.append({"usuario": chaves[i][0], "hora": chaves[i][1], "nota": float(nota[i] / modelo.limiar),
                          "motivo": ANOMALIAS[j], "valor": int(X[i, j]), "simulado": simulado})
    return saida


if __name__ == "__main__":
    import json
    print(json.dumps(treinar(preparar())[1], indent=1, ensure_ascii=False))
