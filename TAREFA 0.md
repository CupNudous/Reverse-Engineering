# TAREFA 0 - std::string

###### Solved by @CupNudous

Este é um desafio de reverse-engineering cujo objetivo é descobrir a **senha** esperada por um binário fornecido. 

## About the Challenge

O binário lê uma senha da entrada padrão e valida-a internamente, imprimindo `Your password is correct!` em caso de sucesso ou `Incorrect password...` em caso contrário. Não havia código-fonte disponível; todo o progresso foi obtido via análise estática (strings / disassembly) e reconstrução do algoritmo de verificação.


#### Reconhecimento inicial

Comandos usados:

```
file tarefa0.bin
strings tarefa0.bin | egrep -i "Password:|Incorrect password|Your password|[A-Za-z0-9]{6,}"
```


* `file` mostrou que o binário é um ELF x86\_64.
* `strings` revelou mensagens claras de validação (`Password:`, `Incorrect password...`, `Your password is correct!`) e várias strings curtas em `.rodata` que pareciam ofuscadas.


#### Função "xored"

Ao analisar a disassembly com `objdump -d` e navegando com `r2` / `radare2`, identifiquei uma função recorrente que realiza operações byte-a-byte entre duas `std::string` e concatena resultados. Pelo padrão e pelas chamadas, ela recebe o nome de `xored`.

Trecho de comportamento observado (resumido):

* percorre dois buffers de bytes;
* aplica `XOR` entre bytes correspondentes;
* concatena o restante do maior (comportamento observado na disassembly);
* o programa chama essa rotina várias vezes em cadeia, usando constantes em `.rodata` como insumos.



#### Extrair as strings

As strings em `.rodata` não eram a senha final — eram insumos. A disassembly mostra em que ordem elas são passadas para `xored`. Combinando a ordem das chamadas e as literais encontradas, é possível reproduzir o processo fora do binário.

Exemplo de strings encontradas em `.rodata`:

```
zg2z8h4z2z
S5do7apOWcl``clx
...
```

#### Reproduzir o XOR em Python

Para garantir que a lógica foi corretamente entendida, implementei uma reprodução em Python que emula o comportamento `xored` e encadeia as operações na mesma ordem do binário.

Código usado para reproduzir a cadeia:

```python
# refaz_o_xor_da_silva.py

def xored(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    out = bytearray()
    for i in range(n):
        out.append(a[i] ^ b[i])
    if len(a) > n:
        out.extend(a[n:])
    elif len(b) > n:
        out.extend(b[n:])
    return bytes(out)

# strings extraídas (substituir pelos literais exatos do .rodata)
s1 = b"zg2z8h4z2z"
s2 = b"S5do7apOWcl``clx"
# aplicar encadeamento conforme ordem da disassembly
step1 = xored(s1, s2)
# ... continuar com outras strings se houver
print(step1.decode('utf-8', errors='ignore'))
```

---

#### Testar a senha gerada no binário original

A reprodução em Python produziu a senha final, que então testei contra o binário localmente.

Como testar:

```
echo -n "C4rrect_P4ssw0rd" | ./tarefa0.bin
# ou
./tarefa0.bin
# quando pedir 'Password:', digitar: C4rrect_P4ssw0rd
```

Saída esperada: `Your password is correct!` — confirmando que a senha está correta.

[![Screenshot-2025-09-20-152902.png](https://i.postimg.cc/wxGYG1j1/Screenshot-2025-09-20-152902.png)](https://postimg.cc/G9GfBhYR)

**Senha:**

```
C4rrect_P4ssw0rd
```

Explicação curta: a cadeia de XORs aplicada, na ordem observada na disassembly e usando as strings constantes do `.rodata`, produz esse literal que é comparado internamente pelo binário com a entrada do usuário.

* O uso de constantes armazenadas no binário e de operações reversíveis (XOR) permite recuperar valores secretos se o algoritmo e as literais puderem ser examinadas estaticamente.
* Técnicas de ofuscação mais robustas (ex.: derivação via KDF/HMAC, remoção de literais ou carregamento via rede em tempo de execução) dificultariam a recuperação.

