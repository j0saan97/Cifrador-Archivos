"""Pruebas de cifrado y descifrado en memoria (las 3 capas)."""

import secrets

import pytest

import cifrador_3capas as c3


@pytest.fixture
def blob(pw, seq, ids, key):
    return c3.encrypt_bytes(b"datos secretos", pw, seq, ids, key)


@pytest.mark.parametrize("data", [b"", b"x", "tildes: cañón, niño".encode(), b"\x00" * 100_000])
def test_ida_y_vuelta(data, pw, seq, ids, key):
    blob = c3.encrypt_bytes(data, pw, seq, ids, key)
    assert c3.decrypt_bytes(blob, pw, seq, key) == data


def test_cifrado_no_determinista(pw, seq, ids, key):
    a = c3.encrypt_bytes(b"igual", pw, seq, ids, key)
    b = c3.encrypt_bytes(b"igual", pw, seq, ids, key)
    assert a != b


def test_texto_claro_no_aparece(pw, seq, ids, key):
    data = b"MARCADOR-MUY-RECONOCIBLE" * 10
    assert b"MARCADOR" not in c3.encrypt_bytes(data, pw, seq, ids, key)


def test_cabecera_guarda_ids(blob, ids):
    header = c3.struct.unpack(c3.HEADER_FMT, blob[:c3.HEADER_LEN])
    assert header[0] == c3.MAGIC
    assert header[1] == c3.VERSION
    assert list(header[2:2 + c3.NUM_POINTS]) == ids


# ---------- Cada capa rechaza su secreto incorrecto ----------

def test_contrasena_incorrecta(blob, seq, key):
    with pytest.raises(c3.CryptoError, match="Capa 1"):
        c3.decrypt_bytes(blob, "otra", seq, key)


@pytest.mark.parametrize("bad_seq", [
    [5, 0, 10, 15, 14],      # mismos puntos, otro orden
    [0, 5, 10, 15, 13],      # un punto distinto
    [0, 5, 10, 15],          # le falta un punto
    [0, 5, 10, 15, 14, 13],  # le sobra un punto
])
def test_patron_incorrecto(blob, pw, key, bad_seq):
    with pytest.raises(c3.CryptoError, match="Capa 2"):
        c3.decrypt_bytes(blob, pw, bad_seq, key)


def test_llave_incorrecta(blob, pw, seq):
    with pytest.raises(c3.CryptoError, match="Capa 3"):
        c3.decrypt_bytes(blob, pw, seq, secrets.token_bytes(64))


# ---------- Integridad ----------

@pytest.mark.parametrize("offset", [
    10,                      # un ID de la cabecera
    c3.HEADER_LEN - 1,       # ultimo byte de la cabecera (nonce3)
    c3.HEADER_LEN,           # primer byte cifrado
    -1,                      # ultimo byte (etiqueta GCM)
])
def test_manipulacion_detectada(blob, pw, seq, key, offset):
    tampered = bytearray(blob)
    tampered[offset] ^= 1
    with pytest.raises(c3.CryptoError):
        c3.decrypt_bytes(bytes(tampered), pw, seq, key)


def test_truncado_detectado(blob, pw, seq, key):
    with pytest.raises(c3.CryptoError):
        c3.decrypt_bytes(blob[:-1], pw, seq, key)


def test_no_es_c3(pw, seq, key):
    with pytest.raises(c3.CryptoError, match="No es un archivo"):
        c3.decrypt_bytes(b"cualquier cosa" * 20, pw, seq, key)


def test_version_no_soportada(blob, pw, seq, key):
    tampered = bytearray(blob)
    tampered[4] = c3.VERSION + 1
    with pytest.raises(c3.CryptoError, match="Version"):
        c3.decrypt_bytes(bytes(tampered), pw, seq, key)


# ---------- Validacion de entradas al cifrar ----------

def test_contrasena_vacia(seq, ids, key):
    with pytest.raises(c3.CryptoError, match="vacia"):
        c3.encrypt_bytes(b"x", "", seq, ids, key)


def test_ids_repetidos(pw, seq, ids, key):
    ids[1] = ids[0]
    with pytest.raises(c3.CryptoError, match="IDs"):
        c3.encrypt_bytes(b"x", pw, seq, ids, key)


def test_ids_cantidad_incorrecta(pw, seq, ids, key):
    with pytest.raises(c3.CryptoError, match="IDs"):
        c3.encrypt_bytes(b"x", pw, seq, ids[:-1], key)
