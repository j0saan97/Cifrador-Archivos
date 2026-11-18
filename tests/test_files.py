"""Pruebas de cifrado/descifrado de archivos en disco."""

import os

import pytest

import cifrador_3capas as c3


@pytest.fixture
def original(tmp_path):
    path = tmp_path / "documento.txt"
    path.write_bytes(b"contenido del documento\n" * 50)
    return path


def test_ciclo_completo(original, pw, seq, ids, keyfile):
    contenido = original.read_bytes()
    cifrado = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    assert cifrado == str(original) + ".c3"
    assert original.read_bytes() == contenido  # el original no se toca

    os.remove(original)
    descifrado = c3.decrypt_file(cifrado, pw, seq, keyfile)
    assert descifrado == str(original)
    assert original.read_bytes() == contenido


def test_descifrar_no_sobrescribe_original(original, pw, seq, ids, keyfile):
    cifrado = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    descifrado = c3.decrypt_file(cifrado, pw, seq, keyfile)
    base, ext = os.path.splitext(str(original))
    assert descifrado == f"{base} (1){ext}"


def test_cifrar_dos_veces_no_sobrescribe(original, pw, seq, ids, keyfile):
    a = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    b = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    assert a != b
    assert os.path.exists(a) and os.path.exists(b)


def test_descifrar_sin_extension_c3(original, tmp_path, pw, seq, ids, keyfile):
    cifrado = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    renombrado = tmp_path / "sin_extension.bin"
    os.rename(cifrado, renombrado)
    descifrado = c3.decrypt_file(str(renombrado), pw, seq, keyfile)
    assert descifrado == str(renombrado) + ".descifrado"


def test_fallo_no_crea_archivo(original, tmp_path, pw, seq, ids, keyfile):
    cifrado = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    os.remove(original)
    antes = set(os.listdir(tmp_path))
    with pytest.raises(c3.CryptoError):
        c3.decrypt_file(cifrado, "mala", seq, keyfile)
    assert set(os.listdir(tmp_path)) == antes


def test_read_header_ids(original, pw, seq, ids, keyfile):
    cifrado = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    assert c3.read_header_ids(cifrado) == ids


def test_read_header_ids_archivo_normal(original):
    assert c3.read_header_ids(str(original)) is None


def test_read_header_ids_no_existe(tmp_path):
    assert c3.read_header_ids(str(tmp_path / "no_existe.c3")) is None


def test_read_header_ids_version_distinta(original, pw, seq, ids, keyfile):
    cifrado = c3.encrypt_file(str(original), pw, seq, ids, keyfile)
    data = bytearray(open(cifrado, "rb").read())
    data[4] = c3.VERSION + 1
    with open(cifrado, "wb") as f:
        f.write(data)
    assert c3.read_header_ids(cifrado) is None
