# VITRAL-256 Dados: criptografia de qualquer tipo de dado

Versão independente da VITRAL-256 anterior (só imagens, pasta `vitral256`, fora deste repositório). A cifra de bloco é a mesma; o que mudou é o que entra nela:
texto digitado, imagem, áudio, vídeo, PDF, planilha, ZIP ou qualquer outro arquivo. As duas podem rodar ao mesmo tempo.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest testes   # 20 testes
.venv/bin/python metricas.py          # cerca de 2 min; grava resultados/metricas.json
.venv/bin/python app.py               # painel em http://127.0.0.1:8257
```

| | `vitral256` | `vitral256-dados` |
|---|---|---|
| Entrada | pixels de uma imagem | bytes de qualquer arquivo, ou texto |
| Saída | PNG de ruído | arquivo `.vtr`, e Base64 quando é curto |
| Volta | mesmos pixels | mesmo arquivo, byte a byte, com o nome original |
| Formato | `VTR1` | `VTR2` (um não abre o outro) |
| Porta | 8256 | 8257 |

Formato `VTR2`: `"VTR2"` (4 bytes), salt (16), IV/etiqueta (16) e o cifrado de `tamanho do nome (1) + nome + conteúdo`.
Chaves por PBKDF2 (600.000 iterações), IV sintético por HMAC-SHA-256 do conteúdo inteiro e modo contador.

Arquivos: `cifra.py` (cifra e formato), `conferir.py` (segunda implementação), `exemplos.py` (um exemplo de cada tipo),
`estego.py`, `eventos.py`, `metricas.py`, `nist.py`, `imagens.py`, `aes_ref.py`, `app.py`, `painel.html`, `testes.py`.

Conferir fora do painel (cerca de 40 KB/s): `.venv/bin/python conferir.py original cifrado.vtr`

## Resultados (`resultados/metricas.json`)

| Tipo | Entropia original | Entropia cifrada | Blocos repetidos: original | ECB | VITRAL | NPCR médio |
|---|---|---|---|---|---|---|
| texto (TXT) | 4,299 | 7,9956 | 96,0% | 96,0% | 0% | 99,607% |
| imagem (BMP) | 4,762 | 7,9990 | 89,1% | 89,1% | 0% | 99,606% |
| áudio (WAV) | 7,484 | 7,9959 | 49,1% | 49,1% | 0% | 99,597% |
| tabela (CSV) | 3,981 | 7,9964 | 0% | 0% | 0% | 99,605% |
| PDF | 7,937 | 7,9901 | 0,1% | 0,1% | 0% | 99,619% |
| ZIP | 7,923 | 7,9889 | 0,5% | 0,5% | 0% | 99,599% |

Nas 30 trocas por tipo, 335 de 360 medidas (93%) ficaram na faixa de aceitação de 5%. O áudio teve NPCR em 24 de 30,
abaixo do esperado; repetido com 1.500 trocas, deu 95,2%, o valor ideal.
NIST SP 800-22: 11 de 11. Bits adulterados recusados: 6.440 de 6.440.

## Limites

- Até 44 MiB por arquivo no painel (tudo em memória).
- O salt, o marcador `VTR2` e o tamanho total ficam visíveis. O painel sugere `nome.ext.vtr`: renomeie se o nome for sigiloso.
- JPG, PDF, ZIP e vídeo já são compactados, então o original também parece aleatório. Para mostrar padrões, use BMP, WAV ou texto.
- Na esteganografia, só a capa precisa ser imagem; o segredo pode ser qualquer arquivo que caiba.
- Uso didático. Para dados reais, use AES-256-GCM de uma biblioteca auditada.
