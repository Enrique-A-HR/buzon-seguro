#!/usr/bin/env python3
"""Buzón Seguro: intercambio de archivos cifrados, firmados y auditables.

Primitivas (todas de la biblioteca oficial `cryptography`, nada casero):
    - X25519  : acuerdo de clave (ECDH) para el cifrado
    - HKDF-SHA256 : derivación de la clave simétrica
    - AES-256-GCM : cifrado autenticado (nonce aleatorio de 12 bytes)
    - Ed25519 : firma digital
    - SHA-256 : huellas, integridad interna y bitácora encadenada

Uso (la opción --debug va ANTES del comando):
    python buzon.py generar alice
    python buzon.py huella alice
    python buzon.py verificar bob alice      # bob verifica a alice
    python buzon.py contactos bob
    python buzon.py cifrar documento.pdf alice bob
    python buzon.py descifrar documento.pdf.buzon bob
    python buzon.py auditar
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("Se requiere Python 3.10 o superior.")

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: F401
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ModuleNotFoundError:
    sys.exit("Falta la biblioteca 'cryptography'. Instálala con:\n"
             "    python -m pip install -r requirements.txt")

# ----------------------------------------------------------------------
# Constantes
# ----------------------------------------------------------------------
VERSION_PAQUETE = "buzon-seguro-v1"          # campo "version" del Anexo B
HKDF_INFO = VERSION_PAQUETE.encode("utf-8")  # contexto de la derivación HKDF
HASH_GENESIS = "0" * 64                      # "hash previo" de la primera línea
MIN_PASSWORD = 8                             # longitud mínima de contraseña
MAX_BYTES = 64 * 1024 * 1024                 # tamaño máximo de archivo a cifrar
CAMPOS_METADATOS = {"remitente", "destinatario", "fecha", "archivo"}

DIR_KEYS = Path("keys")             # claves privadas (NO compartir)
DIR_DIRECTORIO = Path("directorio")  # claves públicas (directorio compartido)
ARCHIVO_LOG = Path("bitacora.log")

RE_HASH = re.compile(r"[0-9a-f]{64}")

DEBUG = False  # se activa con --debug


# ----------------------------------------------------------------------
# Utilidades generales
# ----------------------------------------------------------------------
def b64_enc(data: bytes) -> str:
    """Bytes -> texto Base64."""
    return base64.b64encode(data).decode("ascii")


def b64_dec(data: str) -> bytes:
    """Texto Base64 -> bytes (rechaza caracteres fuera del alfabeto)."""
    return base64.b64decode(data.encode("ascii"), validate=True)


def nombre_valido(nombre: str) -> bool:
    """Solo letras, números, '-' y '_' (evita path traversal)."""
    return isinstance(nombre, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", nombre) is not None


def exigir_nombre(nombre: str) -> bool:
    if not nombre_valido(nombre):
        print(f"[-] Nombre inválido '{nombre}'. Usa 1-32 caracteres: letras, números, '-' o '_'.")
        return False
    return True


def mostrar_error_debug() -> None:
    """Imprime el traceback completo solo si se usó --debug."""
    if DEBUG:
        traceback.print_exc()


def escribir_privada(ruta: Path, contenido: bytes) -> None:
    """Crea un archivo nuevo con permisos 0600 desde el primer instante.

    - O_EXCL: falla si el archivo ya existe (nunca sobrescribe una clave).
    - O_BINARY: en Windows evita que se traduzcan los saltos de línea.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(ruta, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(contenido)


def derivar_clave(secreto_compartido: bytes) -> bytes:
    """HKDF-SHA256 -> clave de 32 bytes para AES-256-GCM."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(secreto_compartido)


def cargar_publica(ruta: Path, tipo):
    """Carga una clave pública PEM y comprueba que sea del tipo esperado."""
    clave = serialization.load_pem_public_key(ruta.read_bytes())
    if not isinstance(clave, tipo):
        raise TypeError(f"La clave de {ruta} no es del tipo esperado ({tipo.__name__}).")
    return clave


def cargar_privada(ruta: Path, password: bytes, tipo):
    """Carga una clave privada PKCS#8 cifrada y comprueba su tipo."""
    clave = serialization.load_pem_private_key(ruta.read_bytes(), password=password)
    if not isinstance(clave, tipo):
        raise TypeError(f"La clave de {ruta} no es del tipo esperado ({tipo.__name__}).")
    return clave


def pedir_password_nueva(nombre: str) -> bytes | None:
    """Pide (con getpass) una contraseña nueva y su confirmación."""
    pwd = getpass.getpass(f"Contraseña para la clave privada de {nombre}: ")
    if len(pwd) < MIN_PASSWORD:
        print(f"[-] La contraseña debe tener al menos {MIN_PASSWORD} caracteres.")
        return None
    if pwd != getpass.getpass("Repite la contraseña: "):
        print("[-] Las contraseñas no coinciden.")
        return None
    return pwd.encode("utf-8")


def construir_aad(metadatos: dict) -> bytes:
    """Serialización canónica de los metadatos (claves ordenadas).

    Se usa tanto como AAD de AES-GCM como parte de lo que se firma.
    """
    return json.dumps(metadatos, sort_keys=True).encode("utf-8")


def validar_metadatos(m) -> None:
    """Comprueba que los metadatos del paquete tengan exactamente la forma esperada."""
    if not isinstance(m, dict) or set(m) != CAMPOS_METADATOS:
        raise ValueError("Metadatos con campos inesperados")
    if not all(isinstance(v, str) for v in m.values()):
        raise ValueError("Metadatos con valores no textuales")
    if not nombre_valido(m["remitente"]) or not nombre_valido(m["destinatario"]):
        raise ValueError("Remitente o destinatario inválido")


def nombre_archivo_seguro(nombre: str) -> str:
    """Quita cualquier ruta del nombre (acepta '/' y '\\') para evitar path traversal."""
    base = PurePosixPath(nombre.replace("\\", "/")).name
    if base in ("", ".", ".."):
        raise ValueError("Nombre de archivo inválido")
    return base


# ----------------------------------------------------------------------
# RF2: huellas digitales y contactos verificados
# ----------------------------------------------------------------------
def huella_de_clave_publica(clave) -> str:
    """SHA-256 de la clave pública en formato DER (SubjectPublicKeyInfo).

    Se usa DER y no el texto PEM para que la huella sea idéntica en cualquier
    sistema operativo (no depende de saltos de línea \\n o \\r\\n).
    """
    der = clave.public_bytes(serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def huellas_de(nombre: str) -> tuple[str, str]:
    """Devuelve (huella X25519, huella Ed25519) de la identidad pública de `nombre`."""
    x_pub = cargar_publica(DIR_DIRECTORIO / f"{nombre}_x25519_pub.pem", x25519.X25519PublicKey)
    ed_pub = cargar_publica(DIR_DIRECTORIO / f"{nombre}_ed25519_pub.pem", ed25519.Ed25519PublicKey)
    return huella_de_clave_publica(x_pub), huella_de_clave_publica(ed_pub)


def ruta_contactos(propietario: str) -> Path:
    """Archivo donde `propietario` guarda a quién ha verificado."""
    return DIR_KEYS / propietario / "contactos_verificados.json"


def leer_contactos(propietario: str) -> dict:
    """Lee los contactos verificados. Si el archivo falta o está dañado, no hay ninguno."""
    ruta = ruta_contactos(propietario)
    if not ruta.exists():
        return {}
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        return datos if isinstance(datos, dict) else {}
    except (OSError, ValueError):
        return {}  # modo estricto: ante la duda, nadie está verificado


def guardar_contactos(propietario: str, contactos: dict) -> None:
    ruta_contactos(propietario).write_text(
        json.dumps(contactos, indent=2, sort_keys=True), encoding="utf-8")


def estado_verificacion(propietario: str, contacto: str) -> tuple[bool, str]:
    """¿`propietario` ha verificado a `contacto` y sus claves siguen siendo las mismas?"""
    try:
        hx, hed = huellas_de(contacto)
    except Exception:
        return False, "no se pudieron leer sus claves públicas del directorio"

    registro = leer_contactos(propietario).get(contacto)
    if not isinstance(registro, dict):
        return False, "no está verificado"
    if not (hmac.compare_digest(str(registro.get("x25519", "")), hx)
            and hmac.compare_digest(str(registro.get("ed25519", "")), hed)):
        return False, "sus claves públicas cambiaron desde que se verificó"
    return True, ""


def normalizar_huella(texto: str) -> str:
    """Quita espacios, ':' y '-' y pasa a minúsculas (para comparar huellas pegadas)."""
    return re.sub(r"[\s:\-]", "", texto).lower()


def mostrar_huella(nombre: str) -> bool:
    """RF2: muestra las huellas SHA-256 de las claves públicas de `nombre`."""
    if not exigir_nombre(nombre):
        return False
    try:
        hx, hed = huellas_de(nombre)
    except Exception:
        print(f"[-] No se encontraron claves públicas válidas para '{nombre}' en el directorio.")
        mostrar_error_debug()
        return False

    print(f"--- Huellas de claves públicas de {nombre} ---")
    print(f"X25519 (Cifrado): {hx}")
    print(f"Ed25519 (Firma):  {hed}")
    return True


def verificar_contacto(propietario: str, contacto: str) -> bool:
    """RF2: marca a `contacto` como verificado para `propietario`.

    Para evitar un 'clic por inercia', el usuario debe ESCRIBIR las dos huellas
    que obtuvo por otro canal (llamada, en persona...). Solo si coinciden
    exactamente con las del directorio se guarda la verificación.
    """
    if not exigir_nombre(propietario) or not exigir_nombre(contacto):
        return False

    ruta_priv = DIR_KEYS / propietario / "x25519_priv.pem"
    if not ruta_priv.exists():
        print(f"[-] No existe la identidad de '{propietario}'. Créala con: generar {propietario}")
        return False
    try:
        hx, hed = huellas_de(contacto)
    except Exception:
        print(f"[-] No se encontraron claves públicas válidas para '{contacto}' en el directorio.")
        mostrar_error_debug()
        return False

    # Solo el dueño de la identidad puede decidir en quién confía.
    pwd = getpass.getpass(f"Contraseña de {propietario}: ").encode("utf-8")
    try:
        cargar_privada(ruta_priv, pwd, x25519.X25519PrivateKey)
    except Exception:
        print("[-] Contraseña incorrecta o clave dañada.")
        mostrar_error_debug()
        return False

    print(f"Compara con {contacto} (por otro canal) las huellas de sus claves públicas.")
    print("Escribe o pega las huellas que RECIBISTE de esa persona:")
    recibida_x = normalizar_huella(input("  Huella X25519: "))
    recibida_ed = normalizar_huella(input("  Huella Ed25519: "))

    if not (hmac.compare_digest(recibida_x, hx) and hmac.compare_digest(recibida_ed, hed)):
        print("[-] Las huellas NO coinciden. El contacto no se marcó como verificado.")
        print("    Podrías tener una clave pública falsa o equivocada: no confíes en ella.")
        return False

    contactos = leer_contactos(propietario)
    contactos[contacto] = {
        "x25519": hx,
        "ed25519": hed,
        "verificado_el": datetime.now(timezone.utc).isoformat(),
    }
    guardar_contactos(propietario, contactos)
    print(f"[+] '{contacto}' quedó marcado como verificado para '{propietario}'.")
    return True


def listar_contactos(propietario: str) -> bool:
    """Muestra los contactos verificados de `propietario` y si siguen vigentes."""
    if not exigir_nombre(propietario):
        return False
    contactos = leer_contactos(propietario)
    if not contactos:
        print(f"[!] '{propietario}' no tiene contactos verificados.")
        return True
    print(f"--- Contactos verificados de {propietario} ---")
    for nombre in sorted(contactos):
        ok, motivo = estado_verificacion(propietario, nombre)
        fecha = contactos[nombre].get("verificado_el", "?") if isinstance(contactos[nombre], dict) else "?"
        estado = "VIGENTE" if ok else f"NO VIGENTE ({motivo})"
        print(f"  {nombre}: {estado} | verificado el {fecha}")
    return True


# ----------------------------------------------------------------------
# RF1: generar identidad
# ----------------------------------------------------------------------
def generar_identidad(nombre: str) -> bool:
    """Crea un par X25519 (cifrado) y un par Ed25519 (firma) para `nombre`."""
    if not exigir_nombre(nombre):
        return False

    dir_usuario = DIR_KEYS / nombre
    if (dir_usuario / "x25519_priv.pem").exists() or (dir_usuario / "ed25519_priv.pem").exists():
        print(f"[-] Ya existe una identidad para '{nombre}'. Bórrala manualmente si quieres regenerarla.")
        return False

    pwd = pedir_password_nueva(nombre)
    if pwd is None:
        return False

    # Las claves privadas se guardan en PKCS#8 cifradas con la contraseña.
    proteccion = serialization.BestAvailableEncryption(pwd)

    x_priv = x25519.X25519PrivateKey.generate()      # par de cifrado
    ed_priv = ed25519.Ed25519PrivateKey.generate()   # par de firma

    dir_usuario.mkdir(parents=True, exist_ok=True)
    DIR_DIRECTORIO.mkdir(exist_ok=True)

    escribir_privada(
        dir_usuario / "x25519_priv.pem",
        x_priv.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, proteccion),
    )
    escribir_privada(
        dir_usuario / "ed25519_priv.pem",
        ed_priv.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, proteccion),
    )

    # Las claves públicas van al directorio compartido.
    for sufijo, clave in (("x25519", x_priv), ("ed25519", ed_priv)):
        (DIR_DIRECTORIO / f"{nombre}_{sufijo}_pub.pem").write_bytes(
            clave.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo))

    print(f"[+] Identidad generada con éxito para '{nombre}'.")
    return True


# ----------------------------------------------------------------------
# RF3 y RF4: cifrado híbrido y firma (Anexo B)
# ----------------------------------------------------------------------
def cifrar_documento(ruta_archivo: str, remitente: str, destinatario: str) -> bool:
    if not exigir_nombre(remitente) or not exigir_nombre(destinatario):
        return False

    origen = Path(ruta_archivo)
    if not origen.is_file():
        print(f"[-] El archivo '{ruta_archivo}' no existe.")
        return False
    if origen.stat().st_size > MAX_BYTES:
        print(f"[-] El archivo supera el límite de {MAX_BYTES // (1024 * 1024)} MB.")
        return False

    ruta_priv_firma = DIR_KEYS / remitente / "ed25519_priv.pem"
    ruta_pub_dest = DIR_DIRECTORIO / f"{destinatario}_x25519_pub.pem"
    if not ruta_priv_firma.exists():
        print(f"[-] No se encontró la clave privada de firma para '{remitente}'.")
        return False
    if not ruta_pub_dest.exists():
        print(f"[-] No se encontró la clave pública de cifrado para '{destinatario}'.")
        return False

    # RF2 (verificación estricta): sin destinatario verificado no se cifra.
    verificado, motivo = estado_verificacion(remitente, destinatario)
    if not verificado:
        print(f"[-] Cifrado bloqueado: '{destinatario}' {motivo}.")
        print(f"    Verifícalo primero con: python buzon.py verificar {remitente} {destinatario}")
        return False

    pwd = getpass.getpass(f"Contraseña de {remitente}: ").encode("utf-8")
    try:
        ed_priv = cargar_privada(ruta_priv_firma, pwd, ed25519.Ed25519PrivateKey)
        dest_pub = cargar_publica(ruta_pub_dest, x25519.X25519PublicKey)
    except Exception:
        print("[-] Contraseña incorrecta o clave dañada.")
        mostrar_error_debug()
        return False

    try:
        contenido = origen.read_bytes()

        # RF6: el SHA-256 del original viaja DENTRO del contenido cifrado.
        contenido_json = json.dumps({
            "sha256_original": hashlib.sha256(contenido).hexdigest(),
            "datos": b64_enc(contenido),
        }).encode("utf-8")

        # RF3: par X25519 efímero nuevo en cada envío + ECDH + HKDF.
        efimera_priv = x25519.X25519PrivateKey.generate()
        efimera_pub_bytes = efimera_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        clave_aes = derivar_clave(efimera_priv.exchange(dest_pub))

        # Metadatos (con claves en orden alfabético): van como AAD de GCM.
        metadatos = {
            "archivo": origen.name,
            "destinatario": destinatario,
            "fecha": datetime.now(timezone.utc).isoformat(),
            "remitente": remitente,
        }
        aad = construir_aad(metadatos)

        # AES-256-GCM con nonce aleatorio de 12 bytes (CSPRNG del sistema).
        nonce = os.urandom(12)
        cifrado = AESGCM(clave_aes).encrypt(nonce, contenido_json, aad)

        # RF4: firma Ed25519 de  efímera || nonce || AAD || cifrado
        firma = ed_priv.sign(efimera_pub_bytes + nonce + aad + cifrado)

        paquete = {
            "version": VERSION_PAQUETE,
            "metadatos": metadatos,
            "efimera_pub": b64_enc(efimera_pub_bytes),
            "nonce": b64_enc(nonce),
            "cifrado": b64_enc(cifrado),
            "firma": b64_enc(firma),
        }

        salida = origen.with_name(origen.name + ".buzon")
        with open(salida, "w", encoding="utf-8", newline="\n") as f:
            json.dump(paquete, f, indent=2)

        registrar_bitacora("ENVIO", remitente, destinatario, str(salida))
        print(f"[+] Paquete cifrado generado: {salida}")
        return True
    except Exception:
        print("[-] Error al cifrar el documento.")
        mostrar_error_debug()
        return False


# ----------------------------------------------------------------------
# RF5 y RF6: recepción segura
# ----------------------------------------------------------------------
def descifrar_documento(ruta_paquete: str, destinatario: str) -> bool:
    if not exigir_nombre(destinatario):
        return False

    origen = Path(ruta_paquete)
    if not origen.is_file():
        print(f"[-] El paquete '{ruta_paquete}' no existe.")
        return False

    pwd = getpass.getpass(f"Contraseña de {destinatario}: ").encode("utf-8")

    try:
        paquete = json.loads(origen.read_text(encoding="utf-8"))
        if not isinstance(paquete, dict) or paquete.get("version") != VERSION_PAQUETE:
            raise ValueError("Versión de paquete no soportada")

        metadatos = paquete["metadatos"]
        validar_metadatos(metadatos)
        remitente = metadatos["remitente"]
        if metadatos["destinatario"] != destinatario:
            raise ValueError("Paquete dirigido a otro destinatario")

        ed_pub = cargar_publica(DIR_DIRECTORIO / f"{remitente}_ed25519_pub.pem",
                                ed25519.Ed25519PublicKey)
        dest_priv = cargar_privada(DIR_KEYS / destinatario / "x25519_priv.pem",
                                   pwd, x25519.X25519PrivateKey)

        efimera_pub_bytes = b64_dec(paquete["efimera_pub"])
        nonce = b64_dec(paquete["nonce"])
        cifrado = b64_dec(paquete["cifrado"])
        firma = b64_dec(paquete["firma"])
        if len(efimera_pub_bytes) != 32 or len(nonce) != 12:
            raise ValueError("Longitudes inválidas")
        aad = construir_aad(metadatos)

        # 1) RF5: la firma se verifica ANTES de descifrar nada.
        ed_pub.verify(firma, efimera_pub_bytes + nonce + aad + cifrado)

        # 2) Se reconstruye la clave (ECDH + HKDF) y se descifra con GCM.
        efimera_pub = x25519.X25519PublicKey.from_public_bytes(efimera_pub_bytes)
        clave_aes = derivar_clave(dest_priv.exchange(efimera_pub))
        contenido_json = AESGCM(clave_aes).decrypt(nonce, cifrado, aad)

        # 3) RF6: se valida el hash SHA-256 interno del archivo original.
        datos = json.loads(contenido_json.decode("utf-8"))
        archivo_bytes = b64_dec(datos["datos"])
        sha_calculado = hashlib.sha256(archivo_bytes).hexdigest()
        if not hmac.compare_digest(sha_calculado, str(datos["sha256_original"])):
            raise ValueError("Hash interno no coincide")

        salida = Path("recibido_" + nombre_archivo_seguro(metadatos["archivo"]))
        # Modo "xb": falla si el archivo ya existe (nunca sobrescribe).
        with open(salida, "xb") as f:
            f.write(archivo_bytes)

    except FileExistsError:
        # Ocurre tras autenticar todo el paquete, así que no revela nada a un atacante.
        print("[-] Ya existe un archivo 'recibido_...' con ese nombre. Renómbralo o bórralo y repite.")
        return False
    except Exception:
        # RF5: mensaje genérico, sin pistas sobre qué falló exactamente.
        print("[-] Error: Fallo de autenticación o integridad en el paquete.")
        mostrar_error_debug()
        return False

    registrar_bitacora("RECEPCION", remitente, destinatario, str(origen))
    print(f"[+] Archivo descifrado exitosamente: '{salida}'")
    print(f"[+] Verificación de integridad SHA-256: CORRECTA ({sha_calculado})")

    verificado, _ = estado_verificacion(destinatario, remitente)
    if not verificado:
        print(f"[!] Aviso: '{remitente}' no está verificado por '{destinatario}'. "
              f"Compara sus huellas con: python buzon.py verificar {destinatario} {remitente}")
    return True


# ----------------------------------------------------------------------
# RF7: bitácora encadenada
# ----------------------------------------------------------------------
def _limpiar_campo(valor: str) -> str:
    """Evita que '|' o saltos de línea rompan el formato de la bitácora."""
    return re.sub(r"[|\r\n]", "_", valor)


def _leer_lineas_bitacora() -> list[str]:
    """Líneas de la bitácora sin saltos de línea (igual en Windows, macOS y Linux)."""
    return ARCHIVO_LOG.read_text(encoding="utf-8").splitlines()


def registrar_bitacora(evento: str, rem: str, dest: str, archivo: str) -> None:
    """Añade un registro:  fecha|evento|remitente|destinatario|archivo|hash_línea_anterior"""
    hash_previo = HASH_GENESIS
    if ARCHIVO_LOG.exists():
        lineas = _leer_lineas_bitacora()
        if lineas:
            hash_previo = hashlib.sha256(lineas[-1].encode("utf-8")).hexdigest()

    registro = "|".join([
        datetime.now(timezone.utc).isoformat(),
        _limpiar_campo(evento),
        _limpiar_campo(rem),
        _limpiar_campo(dest),
        _limpiar_campo(archivo),
        hash_previo,
    ])
    with open(ARCHIVO_LOG, "a", encoding="utf-8", newline="\n") as f:
        f.write(registro + "\n")


def auditar_bitacora() -> bool:
    """Valida la cadena de hashes e indica la primera línea alterada."""
    if not ARCHIVO_LOG.exists():
        print("[!] No existe ningún registro de bitácora aún.")
        return True

    lineas = _leer_lineas_bitacora()
    if not lineas:
        print("[!] La bitácora está vacía.")
        return True

    for n, linea in enumerate(lineas, start=1):
        partes = linea.split("|")
        if len(partes) != 6 or not RE_HASH.fullmatch(partes[-1]):
            print(f"[!] Alteración detectada. Primera línea alterada: {n} (estructura inválida).")
            return False

        if n == 1:
            if partes[-1] != HASH_GENESIS:
                print("[!] Alteración detectada. Primera línea alterada: 1 (hash inicial incorrecto).")
                return False
        else:
            esperado = hashlib.sha256(lineas[n - 2].encode("utf-8")).hexdigest()
            if not hmac.compare_digest(partes[-1], esperado):
                # El hash guardado en la línea n ya no corresponde a la línea n-1.
                print(f"[!] Alteración detectada. Primera línea alterada: {n - 1}.")
                print(f"    El contenido de la línea {n - 1} no coincide con el hash que guarda la línea {n}")
                print(f"    (o bien se editó el campo hash de la propia línea {n}).")
                return False

    print(f"[+] Auditoría completada: {len(lineas)} registros verificados. La bitácora está íntegra.")
    return True


# ----------------------------------------------------------------------
# Interfaz de línea de comandos
# ----------------------------------------------------------------------
def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Buzón Seguro - Sistema criptográfico")
    parser.add_argument("--debug", action="store_true",
                        help="Muestra el traceback completo de los errores (va antes del comando)")
    sub = parser.add_subparsers(dest="comando")

    p = sub.add_parser("generar", help="Generar claves para un usuario")
    p.add_argument("nombre", help="Nombre del usuario")

    p = sub.add_parser("huella", help="Mostrar huellas SHA-256 de las claves públicas")
    p.add_argument("nombre", help="Nombre del usuario")

    p = sub.add_parser("verificar", help="Marcar a un contacto como verificado")
    p.add_argument("propietario", help="Usuario que verifica (quien tomará la decisión)")
    p.add_argument("contacto", help="Contacto a verificar")

    p = sub.add_parser("contactos", help="Listar los contactos verificados de un usuario")
    p.add_argument("propietario", help="Nombre del usuario")

    p = sub.add_parser("cifrar", help="Cifrar y firmar un archivo")
    p.add_argument("archivo", help="Ruta del archivo a enviar")
    p.add_argument("remitente", help="Nombre del remitente")
    p.add_argument("destinatario", help="Nombre del destinatario")

    p = sub.add_parser("descifrar", help="Verificar y descifrar un paquete .buzon")
    p.add_argument("paquete", help="Ruta del archivo .buzon")
    p.add_argument("destinatario", help="Nombre del destinatario")

    sub.add_parser("auditar", help="Auditar la integridad de la bitácora")
    return parser


def main() -> int:
    global DEBUG
    parser = construir_parser()
    args = parser.parse_args()
    DEBUG = args.debug

    if args.comando == "generar":
        ok = generar_identidad(args.nombre)
    elif args.comando == "huella":
        ok = mostrar_huella(args.nombre)
    elif args.comando == "verificar":
        ok = verificar_contacto(args.propietario, args.contacto)
    elif args.comando == "contactos":
        ok = listar_contactos(args.propietario)
    elif args.comando == "cifrar":
        ok = cifrar_documento(args.archivo, args.remitente, args.destinatario)
    elif args.comando == "descifrar":
        ok = descifrar_documento(args.paquete, args.destinatario)
    elif args.comando == "auditar":
        ok = auditar_bitacora()
    else:
        parser.print_help()
        return 0
    return 0 if ok else 1  # código de salida útil para scripts y pruebas


if __name__ == "__main__":
    sys.exit(main())
