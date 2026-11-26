# DES y Triple DES desde cero en Python

[![CI](https://github.com/KevinAndrey96/python-des-block-cipher-from-scratch/actions/workflows/ci.yml/badge.svg)](https://github.com/KevinAndrey96/python-des-block-cipher-from-scratch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-3776AB)
![Cobertura](https://img.shields.io/badge/cobertura-100%25-brightgreen)
![mypy](https://img.shields.io/badge/mypy-strict-2A6DB2)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-yellow.svg)](LICENSE)

Implementación didáctica del **Data Encryption Standard** escrita directamente a partir de [FIPS PUB 46-3](https://csrc.nist.gov/pubs/fips/46-3/final): permutaciones, expansión, cajas S, red de Feistel de 16 rondas y programación de claves, más **Triple DES** (EDE, NIST SP 800-67), los modos **ECB** y **CBC** con relleno PKCS #7 y una traza ronda a ronda. Cada bloque coincide con OpenSSL en cientos de casos aleatorios por ejecución de las pruebas.

> **Solo para estudio.** DES tiene una clave efectiva de 56 bits y fue roto por búsqueda exhaustiva en 1998; NIST retiró Triple DES para cifrar datos nuevos desde 2024. Esta implementación tampoco es de tiempo constante. Para proteger archivos de verdad, usa [python-aes-gcm-file-encryption](https://github.com/KevinAndrey96/python-aes-gcm-file-encryption).

## Contenido

- [Cómo funciona DES](#cómo-funciona-des)
- [Propiedades que verifican las pruebas](#propiedades-que-verifican-las-pruebas)
- [Uso](#uso)
- [Arquitectura](#arquitectura)
- [Pruebas y calidad](#pruebas-y-calidad)
- [Historia del proyecto](#historia-del-proyecto)

## Cómo funciona DES

Un bloque de 64 bits pasa por la permutación inicial $IP$, se divide en mitades $L_0, R_0$ de 32 bits y recorre 16 rondas de Feistel:

$$
L_i = R_{i-1}, \qquad R_i = L_{i-1} \oplus f(R_{i-1}, K_i), \qquad
f(R, K) = P\big(S(E(R) \oplus K)\big).
$$

$E$ expande la mitad a 48 bits, se mezcla con la subclave $K_i$, las ocho cajas S reducen cada grupo de 6 bits a 4 (la única parte no lineal del cifrado) y $P$ permuta el resultado. Al final se intercambian las mitades y se aplica $IP^{-1}$. Las 16 subclaves de 48 bits salen de la clave de 64 bits: $PC_1$ descarta los 8 bits de paridad, dos registros de 28 bits rotan 1 o 2 posiciones por ronda y $PC_2$ elige 48 bits. Descifrar es la misma red con las subclaves en orden inverso.

La traza del ejemplo clásico (clave `133457799BBCDFF1`, bloque `0123456789ABCDEF`):

```text
ronda  1  K=1B02EFFC7072  L=F0AAF0AA  R=EF4A6544
ronda  2  K=79AED9DBC9E5  L=EF4A6544  R=CC017709
...
ronda 16  K=CB3D8B0E17F5  L=43423234  R=0A4CD995
salida    85E813540F0AB405
```

Triple DES aplica $C = E_{K_3}\big(D_{K_2}(E_{K_1}(P))\big)$. Con claves de 16 bytes se usa $K_3 = K_1$, y con $K_1 = K_2 = K_3$ equivale a DES simple, la compatibilidad hacia atrás que motivó el diseño EDE.

## Propiedades que verifican las pruebas

- **Vectores publicados**: el ejemplo de FIPS y de la literatura, el vector `Now is t` de NIST, vectores de bit variable de NIST SP 800-17 y el ejemplo de Triple DES de SP 800-67.
- **Oráculo independiente**: Hypothesis genera claves y bloques aleatorios y compara DES, Triple DES y CBC con OpenSSL a través de `cryptography`.
- **Complementación**: $E_{\overline{K}}(\overline{P}) = \overline{E_K(P)}$, la simetría que reduce a la mitad el costo de la búsqueda exhaustiva.
- **Claves débiles**: con `0101010101010101` y similares todas las subclaves son iguales, así que cifrar dos veces devuelve el original.
- **ECB frente a CBC**: bloques iguales producen cifrados iguales en ECB y distintos en CBC.

## Uso

Requiere Python 3.12 o superior y [uv](https://docs.astral.sh/uv/). Las claves se dan en hexadecimal: 8 bytes para DES, 16 o 24 para Triple DES.

```bash
uv sync
uv run des block -k 133457799BBCDFF1 0123456789ABCDEF
# 85E813540F0AB405
uv run des block -k 133457799BBCDFF1 --decrypt 85E813540F0AB405
# 0123456789ABCDEF
uv run des trace -k 133457799BBCDFF1 0123456789ABCDEF
uv run des encrypt -k 133457799BBCDFF1 "mensaje secreto"
# IV aleatorio de 8 bytes seguido del criptograma, en hex
uv run des decrypt -k 133457799BBCDFF1 <hex anterior>
# mensaje secreto
```

`encrypt` y `decrypt` usan CBC por defecto con un IV aleatorio antepuesto al resultado; con `--iv` se fija el vector y la salida es solo el criptograma, y `--mode ecb` existe para comparar. Una clave débil produce un aviso; una clave, bloque o relleno inválidos terminan con código 2 y un mensaje en la salida de error.

Como librería:

```python
from des import DES, TripleDES, decrypt_cbc, encrypt_cbc

DES(bytes.fromhex("133457799BBCDFF1")).encrypt_block(bytes.fromhex("0123456789ABCDEF")).hex()
# '85e813540f0ab405'

clave = TripleDES(bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"))
cifrado = encrypt_cbc(clave, b"\x00" * 8, b"hola")
decrypt_cbc(clave, b"\x00" * 8, cifrado)   # b'hola'
```

## Arquitectura

```text
src/des/
  tables.py   tablas de FIPS 46-3 tal como aparecen en el estándar
  cipher.py   permutaciones, programación de claves, Feistel, DES, Triple DES y traza
  modes.py    PKCS #7, ECB y CBC para cualquier cifrador de bloque de 64 bits
  cli.py      comandos block, trace, encrypt y decrypt
```

El paquete no tiene dependencias; `cryptography` se usa solo en las pruebas como referencia. Los errores se reportan con `KeySizeError` y `PaddingError`, subclases de `ValueError`.

## Pruebas y calidad

```bash
uv run pytest --cov
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy
```

39 pruebas con cobertura del 100 % de líneas y ramas. El pipeline de GitHub Actions ejecuta Ruff y mypy en modo estricto, las pruebas en Python 3.12, 3.13 y 3.14, una prueba de humo del comando instalado y la construcción del paquete con `twine check`.

## Historia del proyecto

El proyecto nació en abril de 2020 como laboratorio de la clase de criptografía, acompañado de un [video explicativo](https://youtu.be/hylTwYFX2Ko): un script que cifraba una imagen con la librería `pyDes` en modo CBC, con un vector de inicialización fijo y la imagen convertida a base64 antes de cifrar. En 2026 se reescribió para que el algoritmo deje de ser una caja negra: DES y Triple DES implementados desde el estándar, modos de operación propios, traza de rondas y verificación contra OpenSSL; además se eliminaron del historial el entorno virtual, los archivos del IDE y la imagen de prueba que se habían versionado. El código original se conserva en el tag [`v0.1-python-coursework-2020`](https://github.com/KevinAndrey96/python-des-block-cipher-from-scratch/tree/v0.1-python-coursework-2020).

## Autor

**Kevin Andrey Herrera Silva** · [GitHub](https://github.com/KevinAndrey96)

## Licencia

Distribuido bajo la [licencia MIT](LICENSE).
