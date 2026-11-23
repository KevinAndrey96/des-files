# Cifrado y Descifrado de Archivos con DES (Modo CBC) en Python

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Cryptography-DES--CBC-orange.svg)](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Implementación didáctica e interactiva en Python para el cifrado y descifrado de archivos binarios utilizando el algoritmo simétrico **DES (Data Encryption Standard)** en modo **CBC (Cipher Block Chaining)** con vector de inicialización (IV), relleno **PKCS#5** y serialización **Base64**.

---

## 🔐 Fundamento Criptográfico e Histórico

Publicado en 1977 como estándar federal (**FIPS PUB 46**) desarrollado por IBM, **DES** es uno de los algoritmos fundamentales en la historia de la criptografía moderna de clave simétrica basada en la red de Feistel.

### 1. Parámetros del Algoritmo DES

- **Tamaño de Bloque**: 64 bits (8 bytes).
- **Longitud de Clave Nominal**: 64 bits (8 caracteres), de los cuales 56 bits corresponden a entropía efectiva y 8 bits son bits de paridad.
- **Rondas de Feistel**: 16 rondas con generación de subclaves de 48 bits mediante permutaciones con compresión (PC-1 y PC-2) y cajas de sustitución no lineales (S-Boxes).

### 2. Modo de Operación CBC (Cipher Block Chaining)

El modo CBC encadena cada bloque de texto plano con el bloque cifrado inmediatamente anterior mediante una operación XOR ($\oplus$) antes de aplicar la transformación DES. Esto garantiza que bloques idénticos de texto plano produzcan bloques de texto cifrado completamente diferentes:

$$C_0 = \text{DES}_K(P_0 \oplus \text{IV})$$
$$C_i = \text{DES}_K(P_i \oplus C_{i-1}), \quad i \ge 1$$

Para el descifrado:

$$P_0 = \text{DES}^{-1}_K(C_0) \oplus \text{IV}$$
$$P_i = \text{DES}^{-1}_K(C_i) \oplus C_{i-1}, \quad i \ge 1$$

El script implementa un Vector de Inicialización (IV) de 8 bytes y relleno conforme al estándar **PKCS#5** para alinear el tamaño del mensaje a múltiplos exactos de 8 bytes.

> [!NOTE]
> Debido al tamaño de clave efectivo de 56 bits, DES es vulnerable a ataques de fuerza bruta en hardware moderno y fue sucedido formalmente por AES. Este repositorio tiene un propósito puramente educativo, histórico y de análisis forense computacional.

---

## 📂 Estructura del Repositorio

```text
des-files/
├── main.py        # Script interactivo de consola para cifrar y descifrar
├── imagen.jpg     # Archivo de imagen de prueba para validacion
└── Video.txt      # Enlace a demostracion multimedia en YouTube
```

---

## 🚀 Requisitos e Instalación

### Prerrequisitos

- **Python** (versión 3.8 o superior).

### Instalación de Dependencias

El script requiere el paquete `pyDes`:

```bash
pip install pyDes
```

---

## 💻 Guía de Uso

Ejecuta el script principal desde tu terminal:

```bash
python main.py
```

### 1. Cifrar un Archivo

1. Selecciona la opción `1`.
2. Ingresa el nombre del archivo a cifrar (ejemplo: `imagen.jpg`).
3. Ingresa una clave secreta de exactamente **8 caracteres** (8 bytes) (ejemplo: `DESCRYPT`).
4. El script leerá el archivo, lo serializará a Base64, aplicará el cifrado DES-CBC con padding PKCS#5 y sobrescribirá el archivo con los bytes cifrados.

### 2. Descifrar un Archivo

1. Selecciona la opción `2`.
2. Ingresa el nombre del archivo cifrado.
3. Proporciona la misma clave de 8 caracteres.
4. El contenido será descifrado e interpretado en Base64 para reconstruir el archivo binario original en su forma intacta.

---

## 📹 Demostración en Video

Demostración práctica del funcionamiento paso a paso en YouTube:
[Demostración en YouTube](https://youtu.be/hylTwYFX2Ko)

---

## 📄 Licencia

Distribuido bajo la Licencia MIT. Consulta el archivo `LICENSE` para más información.
