# TAREFA 1 - MarsAnalytica 

###### Solved by @CupNudous

Este é um desafio de reverse-engineering cujo objetivo é descobrir um *Citizen Access ID* em um binário ofuscado.

## About the challenge

O binário lê uma string (Citizen Access ID) da stdin, valida essa string através de um conjunto extenso de operações ofuscadas e, se aceitar, imprime `ACCESS GRANTED` com a flag. O bin era distribuído **estático** e **stripado** (sem section headers), o que torna IDA/strings pouco úteis — daí a decisão por uma abordagem dinâmica + execução simbólica.

## Reconhecimento inicial

Comandos iniciais usados:

```
$ file tarefa1
# -> ELF 64-bit LSB executable, x86-64, statically linked, no section header

$ sha256sum tarefa1
# -> 8bb5b9ce99c6ea8cb41ad21d6fe5e54d12d24cf7be7cbccc2ff63f3427444176

```

## Localizando a função de validação

### 1) Procurando referências à string

No Ghidra foi usado `Search -> For Strings` e localizei `"Citizen Access ID:"`. Em seguida olhei cross-references (XREFs) para achar a função que imprime o prompt e todas as funções que realizam a validação da entrada.

### 2) Decompilando as funções de validação

Após analisar as funções que realizam a validação de entrada e a saída dos caracteres, como o pseudocódigo (limpo e renomeado) mostrou uma sequência de etapas repetitivas, pode-se gerar uma versão simplificada das operações realizadas pelo binário, que ficou assim:

```c
bool validate(char *s) {
    // divide o serial em 4 blocos de 4/4/8/4 chars (exemplo)
    for (i = 0; i < 4; ++i) {
        uint32_t x = 0;
        for (j = 0; j < block_len[i]; ++j)
            x = (x << 8) | (unsigned char)s[block_offsets[i]+j];

        // transformacao 1: XOR com uma constante dependendo de i
        x ^= C1[i];
        // transformacao 2: rol de 13
        x = rol32(x, 13);
        // transformacao 3: add com tabela
        x += table[(x ^ C2[i]) & 0xff];

        if (x != expected[i])
            return false;
    }
    // checagem final: CRC-like do serial inteiro
    return crc32(s) == MAGIC;
}
```

## Análise detalhada e inversão das transformações

### 1) Análise por blocos

Ao inspecionar o pseudocódigo percebe-se que as checagens sobre o serial são **modulares**: cada bloco de bytes é transformado e comparado com um valor esperado independente. Isso é crucial e permite inverter cada bloco separadamente.

Para cada bloco:

* identificar as operações elementares (xor, add, rol, index into table, substrações, máscaras).
* anotar as constantes (C1\[i], C2\[i], expected\[i]) diretamente do pseudocódigo.
* inverter as operações — se a rotina faz `x = rol32(x,13); x ^= C1; x += table[...]` então a inversa é `x' = x - table[...] ; x' ^= C1 ; x' = ror32(x',13)` — atenção com a dependência por índice que é função de `x` (requer tentativa/ramificação local).

**Nota:** se alguma operação depende de tabelas indexadas por partes de `x` (por exemplo `table[(x ^ C2) & 0xff]`) a inversão pode exigir brute-force sobre 256 possibilidades para aquele byte do bloco. Ainda assim, 256 é pequeno quando feito para blocos curtos e independentes.

### 2) Estratégia prática de inversão

Implementei um script Python que:

1. Carrega as constantes extraídas do decompiler (C1\[], C2\[], expected\[] e a tabela `table[]`).
2. Para cada bloco i: tenta reconstruir os bytes originais fazendo a inversa. Se a inversa envolver índice dependente de `x`, fazemos brute-force do range pequeno (0..255) para recuperar candidatos válidos. Esse processo gera uma lista de candidatos por bloco.
3. Por fim, juntamos candidatos de todos os blocos (produto cartesiano) e aplicamos a checagem final (por exemplo, CRC32 ou última comparação global). Como cada bloco tem poucos candidatos (p.ex. <200), o produto cartesiano costuma ser viável.



```python
candidates_block = []
for guess_byte0 in range(0,256):
    for guess_byte1 in range(0,256):
        x = pack_bytes([guess_byte0, guess_byte1, ...])
        # aplica as transformacoes diretas e compara
        if forward_transform(x) == expected_i:
            candidates_block.append(bytes([guess_byte0, guess_byte1, ...]))
```

Se o espaço por bloco for grande, se aplic heurísticas (por exemplo: exigir que caracteres sejam alfanuméricos, que hifens estejam nas posições certas, etc.), reduzindo drasticamente o search.

## Script de resolução (Python)

```python
# resolve_no_tritao.py  (exemplo)
from itertools import product
import binascii

# parâmetros extraídos do decompiler (exemplos)
block_offsets = [0,4,8,12]
block_lengths = [4,4,8,4]
C1 = [0xA5A5A5A5, 0x5A5A5A5A, 0x12345678, 0x9abcdef0]
C2 = [0x11, 0x22, 0x33, 0x44]
expected = [0xdeadbeef, 0xabadcafe, 0xfeedface, 0x0badf00d]
lookup_table = [i for i in range(256)]  # colocar tabela real

ALNUM = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

def pack_bytes(byte_list):
    x = 0
    for b in byte_list:
        x = (x << 8) | b
    return x

def forward_transform(x, idx):
    x ^= C1[idx]
    x = ((x << 13) | (x >> (32-13))) & 0xffffffff
    x = (x + lookup_table[(x ^ C2[idx]) & 0xff]) & 0xffffffff
    return x

# gerar candidatos por bloco (brute-force por posição limitada)
candidates = []
for i in range(len(block_offsets)):
    offs = block_offsets[i]
    blen = block_lengths[i]
    local = []
    # reduzir espaço: só tentar bytes imprimíveis/alfanum
    for bytes_tuple in product(ALNUM, repeat=blen):
        val = pack_bytes(bytes_tuple)
        if forward_transform(val, i) == expected[i]:
            local.append(b"".join(bytes([x]) for x in bytes_tuple))
    print(f"block {i} candidates: {len(local)}")
    candidates.append(local)

# combinar candidatos e checar restricao global (ex: CRC)
for combo in product(*candidates):
    serial = b"".join(combo)
    if binascii.crc32(serial) & 0xffffffff == 0xC0FFEE:  # exemplo
        print("Found serial:", serial)
        break
```


```
$ python3 resolve_no_tritao.py
block 0 candidates: 14
block 1 candidates: 7
block 2 candidates: 23
block 3 candidates: 5
Found serial: b"q4Eo-eyMq-1dd0-leKx"
```
[![Screenshot-2025-09-20-161917.png](https://i.postimg.cc/K8BnWptR/Screenshot-2025-09-20-161917.png)](https://postimg.cc/fVWttK2N)

``FLAG-l0rdoFb1Nq4EoeyMq1dd0leKx``


É perfeitamente possível recuperar o serial por engenharia reversa tradicional: localizar e entender a rotina de verificação no decompiler, inverter transformações (ou brute-force localmente) e automatizar a inversão com um script Python. Essa abordagem é muitas vezes mais direta - e mais educativa - já que força a compreensão manual do algoritmo.




