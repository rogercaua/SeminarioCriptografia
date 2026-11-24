"""Desenha o esquema criptográfico da VITRAL-256 Dados. Uso: python gerar_esquema.py saida.svg"""
import sys

CAFE, VERDE, OCRE, TIJOLO, LINHA, PAPEL = "#230903", "#12735F", "#B0702A", "#9A3412", "#D6D1CC", "#FCFBFA"
AREIA, MENTA = "#F3E7D6", "#DCE8DE"
out = []


def t(x, y, s, f=24, c=CAFE, b=0, a="middle"):
    out.append(f'<text x="{x}" y="{y}" font-size="{f}" fill="{c}" text-anchor="{a}" font-weight="{700 if b else 400}">{s}</text>')


def box(x, y, w, h, *ls, fill=PAPEL, st=CAFE, c=CAFE):
    out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{st}" stroke-width="2.5"/>')
    y0 = y + h / 2 - (len(ls) - 1) * 16 + 9
    for i, l in enumerate(ls):
        t(x + w / 2, y0 + i * 32, l, 24, c, i == 0)


def seta(*p, c=CAFE, d=""):
    out.append(f'<polyline points="{" ".join(f"{a},{b}" for a, b in p)}" fill="none" stroke="{c}" stroke-width="3" stroke-dasharray="{d}" marker-end="url(#s{c[1:]})"/>')


def faixa(y, h, titulo):
    out.append(f'<rect x="1" y="{y}" width="1662" height="{h}" rx="14" fill="#fff" stroke="{LINHA}" stroke-width="2"/>')
    t(20, y + 33, titulo, 26, VERDE, 1, "start")


faixa(1, 171, "1. Da senha às chaves")
faixa(181, 160, "2. Cifragem")
faixa(350, 194, "3. Bloco VITRAL")
faixa(553, 156, "4. Arquivo .vtr e conferência")

# 1
box(20, 46, 220, 52, "Senha")
box(20, 108, 220, 52, "Salt: 16 bytes")
box(310, 58, 250, 90, "PBKDF2", "600.000 iterações", fill=AREIA, st=OCRE)
seta((240, 72), (275, 72), (275, 90), (306, 90))
seta((240, 134), (275, 134), (275, 116), (306, 116))
box(640, 46, 200, 52, "K cifra", fill=CAFE, c="#fff")
box(640, 108, 200, 52, "K mac", fill=VERDE, st=VERDE, c="#fff")
seta((560, 90), (600, 90), (600, 72), (636, 72))
seta((560, 116), (600, 116), (600, 134), (636, 134))
box(910, 46, 200, 52, "SHAKE-256", fill=AREIA, st=OCRE)
seta((840, 72), (906, 72))
box(1180, 46, 464, 114, "17 subchaves · 4 S-boxes", "16 ordens de permutação", fill=MENTA, st=VERDE)
seta((1110, 72), (1176, 72))

# 2
box(20, 228, 220, 90, "Dado + nome", "qualquer tipo")
box(310, 228, 230, 90, "IV sintético", "HMAC(salt, dado)", fill=MENTA, st=VERDE)
seta((240, 273), (306, 273))
seta((660, 160), (660, 196), (470, 196), (470, 224), c=VERDE)
box(610, 228, 200, 90, "Contador", "IV ⊕ i")
seta((540, 273), (606, 273))
box(880, 228, 230, 90, "Bloco VITRAL", "16 rodadas", fill=AREIA, st=OCRE)
seta((810, 273), (876, 273))
seta((1240, 160), (1240, 196), (995, 196), (995, 224))
out.append(f'<circle cx="1240" cy="273" r="26" fill="{TIJOLO}"/><path d="M1225 273h30M1240 258v30" stroke="#fff" stroke-width="4"/>')
seta((1110, 273), (1210, 273))
t(1158, 262, "fluxo")
seta((130, 318), (130, 331), (1240, 331), (1240, 303))
box(1340, 228, 304, 90, "Dado cifrado", "parece ruído", fill=CAFE, c="#fff")
seta((1266, 273), (1336, 273))

# 3
Y, H = 420, 76
for x, w, a, b, st in ((20, 200, "⊕ K[0]", "só no início", TIJOLO), (290, 220, "Substituição", "S-box da linha", CAFE),
                       (580, 230, "Permutação", "ordem da chave", CAFE), (880, 220, "Mistura", "circ(1,5,2,1)", CAFE),
                       (1170, 180, "⊕ K[r]", "subchave", TIJOLO)):
    box(x, Y, w, H, a, b, st=st)
for a, b in ((220, 290), (510, 580), (810, 880), (1100, 1170), (1350, 1430)):
    seta((a, 458), (b - 4, 458))
t(1440, 466, "fluxo", 24, CAFE, 1, "start")
t(400, 400, "confusão", 24, TIJOLO, 1)
t(840, 400, "difusão", 24, TIJOLO, 1)
out.append(f'<path d="M290 416v-7h220v7M580 416v-7h520v7" fill="none" stroke="{TIJOLO}" stroke-width="2.5"/>')
seta((1260, 496), (1260, 520), (400, 520), (400, 500), c=VERDE, d="8 6")
out.append('<rect x="585" y="505" width="490" height="32" fill="#fff"/>')
t(830, 529, "repete 16 vezes (a última sem mistura)", 24, VERDE)

# 4
for x, w, a, b, f, c in ((20, 100, "VTR2", "4 B", PAPEL, CAFE), (120, 100, "salt", "16 B", PAPEL, CAFE),
                         (220, 170, "IV/etiqueta", "16 B", VERDE, "#fff"), (390, 140, "cifrado", "n bytes", CAFE, "#fff")):
    out.append(f'<rect x="{x}" y="602" width="{w}" height="92" fill="{f}" stroke="{CAFE}" stroke-width="2"/>')
    t(x + w / 2, 640, a, 24, c, 1)
    t(x + w / 2, 673, b, 24, c)
seta((530, 648), (706, 648))
t(616, 636, "direto ou")
t(616, 678, "em imagem")
box(710, 602, 350, 92, "Quem recebe", "decifra e refaz o HMAC", fill=MENTA, st=VERDE)
box(1150, 594, 494, 50, "Etiqueta igual: devolve o arquivo", fill=VERDE, st=VERDE, c="#fff")
box(1150, 652, 494, 50, "Etiqueta diferente: recusa tudo", fill=TIJOLO, st=TIJOLO, c="#fff")
seta((1060, 636), (1105, 636), (1105, 619), (1146, 619), c=VERDE)
seta((1060, 660), (1105, 660), (1105, 677), (1146, 677), c=TIJOLO)

pontas = "".join(f'<marker id="s{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0L10 5L0 10z" fill="{c}"/></marker>' for c in (CAFE, VERDE, TIJOLO))
with open(sys.argv[1], "w") as f:
    f.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1664 710" width="1664" height="710" font-family="Noto Sans, Arial, sans-serif"><defs>{pontas}</defs><rect width="1664" height="710" fill="#F4F2F3"/>{"".join(out)}</svg>')
