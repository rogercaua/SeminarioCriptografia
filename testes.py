"""Rode com: python -m unittest testes"""
import hashlib
import unittest
from unittest import mock

import numpy as np

import app
import cifra
import conferir
import estego
import eventos
import exemplos
import metricas
import nist
from aes_ref import aes256

IT = 1000  # menos iterações só para o teste ser rápido


def aleatoria(h, w, c, semente=0):
    return np.random.default_rng(semente).integers(0, 256, (h, w, c), np.uint8)


class Motor(unittest.TestCase):
    def test_motor_com_parametros_do_aes_bate_com_fips197(self):
        a = aes256(bytes(range(32)))
        p = np.frombuffer(bytes.fromhex("00112233445566778899aabbccddeeff"), np.uint8).reshape(1, 16)
        c = a.cifrar(p)
        self.assertEqual(c.tobytes().hex(), "8ea2b7ca516745bfeafc49904b496089")
        self.assertTrue((a.decifrar(c) == p).all())

    def test_vitral_e_bijetora_para_varias_chaves(self):
        for s in range(20):
            chave = np.random.default_rng(s).bytes(32)
            v, b = cifra.vitral(chave), aleatoria(500, 16, 1, s)[:, :, 0]
            self.assertTrue((v.decifrar(v.cifrar(b)) == b).all())
            for S in v.sboxes:
                self.assertEqual(len(set(S.tolist())), 256)
                self.assertFalse((S == np.arange(256)).any())
            self.assertTrue(all(sorted(d) == [0, 1, 2, 3] for d in v.deslocamentos))

    def test_contador_nao_repete_entre_lotes(self):
        # o resultado não pode depender do tamanho do lote
        v, d = cifra.vitral(bytes(32)), np.zeros(1000, np.uint8)
        ref, antes = cifra.ctr(v, bytes(16), d), cifra.BLOCOS_POR_LOTE
        cifra.BLOCOS_POR_LOTE = 7
        try:
            self.assertTrue((cifra.ctr(v, bytes(16), d) == ref).all())
        finally:
            cifra.BLOCOS_POR_LOTE = antes
        self.assertEqual(len({ref[i:i + 16].tobytes() for i in range(0, 992, 16)}), 62)


class Conferencia(unittest.TestCase):
    def test_rastro_bate_com_os_passos_publicados_na_fips197(self):  # apêndice C.3, rodada 1
        a = aes256(bytes(range(32)))
        p = conferir.rastro(bytes.fromhex("00112233445566778899aabbccddeeff"), a.sboxes, a.deslocamentos, a.matriz, a.poli, a.subchaves)
        for passo, valor in (("substituicao", "63cab7040953d051cd60e0e7ba70e18c"), ("permutacao", "6353e08c0960e104cd70b751bacad0e7"),
                             ("mistura", "5f72641557f5bc92f7be3b291db9f91a"), ("subchave", "101112131415161718191a1b1c1d1e1f")):
            self.assertEqual(bytes(p[1][passo]).hex(), valor)
        self.assertEqual(bytes(p[-1]["saida"]).hex(), "8ea2b7ca516745bfeafc49904b496089")

    def test_duas_implementacoes_concordam(self):
        for s, n in enumerate([0, 1, 14, 15, 16, 999, 3000]):
            dados = aleatoria(1, n, 1, s).tobytes()
            pac = cifra.cifrar(dados, f"senha{s}", f"ação{s}.bin", iteracoes=1)
            r = conferir.conferir(cifra.moldura(f"ação{s}.bin", dados), pac, f"senha{s}", iteracoes=1)
            self.assertTrue(r["tamanho_ok"] and r["etiqueta_ok"])
            self.assertEqual(r["certos"], r["blocos"])

    def test_conferencia_acusa_bloco_errado_e_senha_errada(self):
        claro = cifra.moldura("a", bytes(768))
        pac = cifra.cifrar(bytes(768), "s", "a", iteracoes=1)
        mau = pac[:100] + bytes([pac[100] ^ 1]) + pac[101:]
        r = conferir.conferir(claro, mau, "s", iteracoes=1)
        self.assertEqual(r["blocos"] - r["certos"], 1)
        r = conferir.conferir(claro, pac, "x", iteracoes=1)
        self.assertFalse(r["etiqueta_ok"])
        self.assertEqual(r["certos"], 0)

    def test_conferencia_acusa_cifra_sabotada(self):
        # a ida e volta continua perfeita com a cifra alterada; só a segunda implementação percebe
        dados = aleatoria(1, 767, 1).tobytes()
        for nome, valor in (("RODADAS", 3), ("MATRIZ", cifra.circulante((2, 3, 1, 1))), ("ctr", lambda c, iv, x: x.copy())):
            with mock.patch.object(cifra, nome, valor):
                pac = cifra.cifrar(dados, "s", iteracoes=1)
                self.assertEqual(cifra.decifrar(pac, "s", iteracoes=1), ("", dados))
            self.assertEqual(conferir.conferir(cifra.moldura("", dados), pac, "s", iteracoes=1)["certos"], 0)


class Dados(unittest.TestCase):
    def test_ida_e_volta_em_todos_os_tipos(self):
        tipos = {n: f() for n, f in exemplos.TODOS.items()}
        tipos |= {"vazio": b"", "um byte": b"\0", "texto.txt": "ação 🔐 漢字\r\n".encode(), "x" * 255: b"\xff" * 17}
        for nome, dados in tipos.items():
            pac = cifra.cifrar(dados, "s", nome, iteracoes=1)
            self.assertEqual(cifra.decifrar(pac, "s", iteracoes=1), (nome, dados))
            self.assertNotIn(nome.encode(), pac)  # o nome também vai cifrado

    def test_qualquer_bit_trocado_e_rejeitado(self):
        pac = cifra.cifrar(b"segredo", "s", "a.txt", iteracoes=1)
        for i in range(8 * len(pac)):
            mau = bytearray(pac)
            mau[i // 8] ^= 1 << i % 8
            with self.assertRaises(ValueError):
                cifra.decifrar(bytes(mau), "s", iteracoes=1)
        for i in range(len(pac)):  # e qualquer corte
            with self.assertRaises(ValueError):
                cifra.decifrar(pac[:i], "s", iteracoes=1)

    def test_senha_errada_arquivo_comum_e_nome_longo(self):
        with self.assertRaises(cifra.FalhaAutenticacao):
            cifra.decifrar(cifra.cifrar(b"x", "certa", iteracoes=IT), "errada", iteracoes=IT)
        for comum in (b"", b"VTR1" + bytes(200), exemplos.imagem()):
            with self.assertRaises(ValueError):
                cifra.decifrar(comum, "s", iteracoes=1)
        with self.assertRaises(ValueError):
            cifra.cifrar(b"x", "s", "ç" * 128)

    def test_mesmo_dado_nunca_gera_a_mesma_saida(self):
        self.assertEqual(len({cifra.cifrar(b"x" * 50, "s", iteracoes=1) for _ in range(50)}), 50)


class Painel(unittest.TestCase):
    def setUp(self):
        lento = hashlib.pbkdf2_hmac
        rapido = mock.patch.object(hashlib, "pbkdf2_hmac", lambda h, s, salt, _: lento(h, s, salt, 1))
        for alvo in (rapido, mock.patch.object(eventos, "registrar")):
            alvo.start()
            self.addCleanup(alvo.stop)

    def test_cada_tipo_passa_por_todas_as_operacoes(self):
        url = lambda b: "data:," + app.b64(b)
        for nome, f in {**exemplos.TODOS, "curto.txt": lambda: b"a", "sem_extensao": lambda: bytes(40)}.items():
            dados = f()
            r = app.cifrar({"dados": url(dados), "nome": "../" + nome, "senha": "s"})
            p, c = r["provas"], r["provas"]["conferencia"]
            self.assertTrue(p["nome_ok"] and not p["diferentes"] and c["etiqueta_ok"] and c["certos"] == c["blocos"], nome)
            pac = "data:," + r["pacote"]
            volta = app.decifrar({"dados": pac, "senha": "s"})
            self.assertEqual((volta["nome"], volta["dados"]), (nome, app.b64(dados)))
            self.assertTrue(app.adulterar({"dados": pac, "senha": "s"})["recusa"])
            self.assertTrue(app.tentar({"dados": pac, "senha": "s"})["ok"])
            self.assertFalse(app.tentar({"dados": pac, "senha": "x"})["ok"])
            self.assertGreaterEqual(app.diferencial({"dados": url(dados)})["total"], 1)

    def test_entradas_ruins_viram_erro_claro(self):
        for d in ({}, {"dados": 1}, {"dados": "data:,"}, {"dados": "data:,não é base64!"}, {"dados": "data:,AAAA"}):
            with self.assertRaises(ValueError):
                app.decifrar({"senha": "s", **d})
        with self.assertRaises(ValueError):
            app.cifrar({"dados": "data:," + app.b64(bytes(app.MAX_BYTES + 1)), "senha": "s"})


class Estego(unittest.TestCase):
    def test_esconde_e_recupera(self):
        capa = aleatoria(100, 100, 3, 1)
        e = estego.esconder(cifra.cifrar(b"segredo" * 100, "s", "a.txt", iteracoes=IT), capa)
        self.assertLessEqual(np.abs(e.astype(int) - capa).max(), 1)
        self.assertEqual(cifra.decifrar(estego.extrair(e), "s", iteracoes=IT), ("a.txt", b"segredo" * 100))

    def test_capa_pequena_e_capa_vazia(self):
        with self.assertRaises(ValueError):
            estego.esconder(bytes(1000), aleatoria(10, 10, 3))
        with self.assertRaises(ValueError):
            estego.extrair(aleatoria(50, 50, 3))


class Metricas(unittest.TestCase):
    """Confere o instrumento de medida contra valores publicados."""

    def test_exemplos_da_sp800_22(self):
        b = lambda s: np.array([int(c) for c in s], np.uint8)
        self.assertAlmostEqual(nist.frequencia(b("1011010101")), 0.527089, 5)
        self.assertAlmostEqual(nist.frequencia_blocos(b("0110011010"), 3), 0.801252, 5)
        self.assertAlmostEqual(nist.corridas(b("1001101011")), 0.147232, 5)
        self.assertAlmostEqual(nist.somas_acumuladas(b("1011010111")), 0.4116588, 5)
        s1, s2 = nist.serial(b("0011011101"), 3)
        self.assertAlmostEqual(s1, 0.808792, 5)
        self.assertAlmostEqual(s2, 0.670320, 5)
        self.assertAlmostEqual(nist.entropia_aproximada(b("0100110101"), 3), 0.261961, 5)

    def test_sbox_do_aes_tem_os_valores_conhecidos(self):
        m = metricas.metricas_sbox(metricas.SBOX_AES)
        self.assertEqual((m["nao_linearidade"], m["uniformidade_diferencial"], m["grau_algebrico"], m["pontos_fixos"]), (112, 4, 7, 0))

    def test_sbox_da_vitral_mantem_nl_e_du_do_aes(self):
        for S in cifra.vitral(b"k" * 32).sboxes:
            m = metricas.metricas_sbox(S)
            self.assertEqual((m["nao_linearidade"], m["uniformidade_diferencial"]), (112, 4))

    def test_matriz_mds_e_criticos_npcr(self):
        self.assertEqual(metricas.numero_de_ramos(cifra.MATRIZ, cifra.POLI), 5)
        c = metricas.criticos_npcr_uaci(512 * 512)  # valores publicados por Wu et al. (2011)
        self.assertAlmostEqual(c["npcr_min"], 99.5893, 3)
        self.assertAlmostEqual(c["uaci_min"], 33.3730, 3)
        self.assertAlmostEqual(c["uaci_max"], 33.5541, 3)


class IA(unittest.TestCase):
    def test_modelo_separa_rajada_do_normal(self):
        rng = np.random.default_rng(0)
        chaves = [(f"u{i % 20}", 3600 * (i % 24)) for i in range(3000)]
        X = np.column_stack([rng.poisson(l, 3000) for l in (0.15, 0.1, 0.05, 0, 8)]).astype(float)
        m = eventos.ModeloComportamental(chaves, X, epocas=10)
        nota = lambda linha: m.desvios([("novo", 36000)], np.array([linha], float)).max()
        self.assertGreater(nota([0, 20, 0, 0, 28]), m.limiar)
        self.assertLess(nota([0, 0, 0, 0, 8]), m.limiar)


if __name__ == "__main__":
    unittest.main()
