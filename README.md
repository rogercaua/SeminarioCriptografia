# VITRAL-256 Dados: criptografia de qualquer tipo de dado

Cifra simétrica derivada do AES-256 para texto digitado, imagem, áudio, vídeo, PDF, planilha, ZIP ou qualquer outro arquivo.
Inclui painel local, esteganografia, análise de ataques, métricas e detecção de anomalias com IA.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest testes   # 20 testes
.venv/bin/python metricas.py          # cerca de 2 min; grava resultados/metricas.json
.venv/bin/python app.py               # painel em http://127.0.0.1:8257
```

## Como funciona

1. Você escreve um texto ou escolhe um arquivo, e informa uma senha.
2. O conteúdo e o nome são cifrados juntos. A saída é um arquivo `.vtr`, e também Base64 quando é curta.
3. Com a mesma senha, o arquivo volta idêntico, byte a byte, com o nome original. Senha errada ou arquivo alterado são recusados.

Formato `VTR2`: `"VTR2"` (4 bytes), salt (16), IV/etiqueta (16) e o cifrado de `tamanho do nome (1) + nome + conteúdo`.
Chaves por PBKDF2 (600.000 iterações), IV sintético por HMAC-SHA-256 do conteúdo inteiro e modo contador.

Arquivos: `cifra.py` (cifra e formato), `conferir.py` (segunda implementação), `exemplos.py` (um exemplo de cada tipo),
`estego.py`, `eventos.py`, `metricas.py`, `nist.py`, `imagens.py`, `aes_ref.py`, `app.py`, `painel.html`, `testes.py`,
`gerar_esquema.py` (gera o SVG do esquema; imagem pronta em `esquema_criptografico.png`).

Conferir fora do painel (cerca de 40 KB/s): `.venv/bin/python conferir.py original cifrado.vtr`

## Resultados (`resultados/metricas.json`)

| Tipo | Entropia original | Entropia cifrada | Blocos repetidos: original | ECB | VITRAL | NPCR médio |
|---|---|---|---|---|---|---|
| texto (TXT) | 4,299 | 7,9958 | 96,0% | 96,0% | 0% | 99,613% |
| imagem (BMP) | 4,762 | 7,9990 | 89,1% | 89,1% | 0% | 99,606% |
| áudio (WAV) | 7,484 | 7,9966 | 49,1% | 49,1% | 0% | 99,605% |
| tabela (CSV) | 3,981 | 7,9962 | 0% | 0% | 0% | 99,607% |
| PDF | 7,937 | 7,9905 | 0,1% | 0,1% | 0% | 99,623% |
| ZIP | 7,923 | 7,9895 | 0,5% | 0,5% | 0% | 99,603% |

Nas 30 trocas por tipo, 342 de 360 medidas (95%) ficaram na faixa de aceitação de 5%. A imagem teve NPCR em 25 de 30,
abaixo do esperado; repetida com 1.500 trocas, deu 94,3%, próximo do ideal de 95%.
NIST SP 800-22: 11 de 11. Bits adulterados recusados: 6.440 de 6.440.

## Limites

- Até 44 MiB por arquivo no painel (tudo em memória).
- O salt, o marcador `VTR2` e o tamanho total ficam visíveis. O painel sugere `nome.ext.vtr`: renomeie se o nome for sigiloso.
- JPG, PDF, ZIP e vídeo já são compactados, então o original também parece aleatório. Para mostrar padrões, use BMP, WAV ou texto.
- Na esteganografia, só a capa precisa ser imagem; o segredo pode ser qualquer arquivo que caiba.
- Uso didático. Para dados reais, use AES-256-GCM de uma biblioteca auditada.
