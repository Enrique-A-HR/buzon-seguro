# Buzón Seguro

Aplicación de línea de comandos para intercambiar archivos **cifrados, firmados y auditables** entre usuarios. Funciona igual en Windows, macOS y Linux.

## Requisitos

- Python **3.10 o superior**
- Biblioteca oficial [`cryptography`](https://cryptography.io) (ver `requirements.txt`)

```bash
python -m pip install -r requirements.txt
```

## Inicio rápido

Alice quiere enviarle un archivo a Bob. Cada comando se ejecuta en una terminal (PowerShell, CMD, Terminal...).

```bash
# 1. Cada persona crea su identidad (pide contraseña con getpass)
python buzon.py generar alice
python buzon.py generar bob

# 2. Alice consulta las huellas de Bob y las compara con él POR OTRO CANAL (llamada, en persona)
python buzon.py huella bob

# 3. Alice marca a Bob como verificado (debe escribir las huellas que Bob le dio)
python buzon.py verificar alice bob

# 4. Alice cifra y firma el archivo para Bob
python buzon.py cifrar informe.pdf alice bob        # genera informe.pdf.buzon

# 5. Bob verifica la firma, descifra y comprueba la integridad
python buzon.py descifrar informe.pdf.buzon bob     # genera recibido_informe.pdf

# 6. Cualquiera puede auditar la bitácora
python buzon.py auditar
```

Si algo falla y quieres ver el motivo técnico real, añade `--debug` **antes** del comando:

```bash
python buzon.py --debug descifrar informe.pdf.buzon bob
```

## Comandos

| Comando | Descripción |
|---|---|
| `generar <nombre>` | Crea las claves X25519 y Ed25519 de un usuario (RF1). |
| `huella <nombre>` | Muestra las huellas SHA-256 de sus claves públicas (RF2). |
| `verificar <propietario> <contacto>` | El propietario marca a un contacto como verificado tras comparar las huellas (RF2). |
| `contactos <propietario>` | Lista los contactos verificados y si siguen vigentes. |
| `cifrar <archivo> <remitente> <destinatario>` | Cifra y firma. **Se bloquea si el destinatario no está verificado** (RF2, RF3, RF4). |
| `descifrar <paquete.buzon> <destinatario>` | Verifica la firma, descifra y valida el hash interno (RF5, RF6). |
| `auditar` | Valida la bitácora encadenada e indica la primera línea alterada (RF7). |

Los nombres de usuario admiten solo letras, números, `-` y `_` (máximo 32 caracteres). El programa devuelve código de salida `0` si todo fue bien y `1` si hubo un error.

## Verificación estricta de contactos (RF2)

- La huella es el SHA-256 de la clave pública en formato DER, por lo que es idéntica en cualquier sistema operativo.
- `verificar` exige la contraseña del propietario y que **escriba o pegue las dos huellas** recibidas por otro canal. Si no coinciden exactamente, no se verifica.
- Se guarda la huella verificada en `keys/<propietario>/contactos_verificados.json`. Si las claves públicas del contacto cambian después, la verificación deja de ser vigente y el cifrado se bloquea de nuevo.
- Al recibir un paquete de un remitente no verificado, el archivo se descifra pero se muestra un aviso.

## Cómo se protege un envío

1. Se calcula el SHA-256 del archivo original y se incluye **dentro** del contenido cifrado (RF6).
2. Se genera un par X25519 **efímero** por cada envío y se acuerda una clave con ECDH contra la clave pública del destinatario.
3. La clave se deriva con **HKDF-SHA256** (32 bytes).
4. Se cifra con **AES-256-GCM**, nonce aleatorio de 12 bytes (`os.urandom`). Los metadatos van como **AAD**.
5. Se firma con **Ed25519**: `clave efímera + nonce + metadatos (AAD) + texto cifrado`.
6. Al recibir, **primero se verifica la firma** y solo después se descifra. Cualquier fallo muestra el mismo mensaje genérico.

## Formato del paquete `.buzon`

Archivo JSON; los campos binarios van en Base64 y las claves de `metadatos` en orden alfabético fijo:

```json
{
  "version": "buzon-seguro-v1",
  "metadatos": {
    "archivo": "informe.pdf",
    "destinatario": "bob",
    "fecha": "2026-01-01T12:00:00+00:00",
    "remitente": "alice"
  },
  "efimera_pub": "<base64, 32 bytes>",
  "nonce": "<base64, 12 bytes>",
  "cifrado": "<base64>",
  "firma": "<base64>"
}
```

## Bitácora encadenada (RF7)

`bitacora.log` tiene un registro por línea:

```
fecha|evento|remitente|destinatario|archivo|hash_SHA256_de_la_línea_anterior
```

La primera línea usa 64 ceros como hash previo. `auditar` recorre la cadena y, si encuentra una incoherencia, indica la **primera línea alterada**.

Limitaciones propias de una cadena de hashes: no detecta que se borren o modifiquen las **últimas** líneas si el atacante rehace la cadena completa desde ese punto, ni que se trunque el final del archivo. Para mayor garantía, conserva copias externas del último hash.

## Estructura de carpetas

```
buzon.py
requirements.txt
README.md
keys/<usuario>/          Claves privadas PKCS#8 cifradas + contactos verificados  (PRIVADO)
directorio/              Claves públicas compartidas
bitacora.log             Registro encadenado de envíos y recepciones
```

Para que dos personas en equipos distintos se comuniquen, cada una debe tener en su `directorio/` las claves públicas de la otra. **Nunca** se copian las claves privadas.

## Seguridad e higiene

- Ninguna contraseña ni clave privada está en el código: las contraseñas se piden con `getpass` (mínimo 8 caracteres).
- Las claves privadas se crean con permisos `0600` (en Windows, los permisos de archivo funcionan de forma distinta; protege tu carpeta de usuario).
- Todo valor aleatorio proviene de CSPRNG (`os.urandom` y los generadores de `cryptography`).
- No se usan algoritmos prohibidos (AES-ECB, DES, 3DES, RC4, MD5, SHA-1, RSA débil). No hay criptografía casera.
- **No subas la carpeta `keys/` a ningún repositorio.** El archivo `.gitignore` incluido ya la excluye.
- Haz una copia de seguridad de `keys/`: sin la clave privada o su contraseña no se pueden recuperar los archivos.

## Problemas frecuentes

| Mensaje | Qué hacer |
|---|---|
| `Falta la biblioteca 'cryptography'` | `python -m pip install -r requirements.txt` |
| `Cifrado bloqueado: ... no está verificado` | Ejecuta `verificar <tú> <destinatario>` tras comparar huellas. |
| `sus claves públicas cambiaron` | Alguien cambió la clave del contacto. Confirma por otro canal antes de volver a verificar. |
| `Fallo de autenticación o integridad` | Contraseña incorrecta, paquete alterado, destinatario equivocado o falta la clave del remitente. Usa `--debug` para el motivo real. |
| `Ya existe un archivo 'recibido_...'` | Renombra o borra el archivo anterior y repite. |
