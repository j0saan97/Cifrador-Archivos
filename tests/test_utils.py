"""Pruebas de utilidades: IDs, patron, suma de control, archivo llave, rutas."""

import pytest

import cifrador_3capas as c3


# ---------- IDs ----------

def test_new_ids_formato():
    ids = c3.new_ids()
    assert len(ids) == c3.NUM_POINTS
    assert len(set(ids)) == c3.NUM_POINTS
    assert all(100000 <= i <= 999999 for i in ids)


def test_new_ids_aleatorios():
    assert c3.new_ids() != c3.new_ids()


# ---------- Patron ----------

@pytest.mark.parametrize("seq", [[0, 1, 2, 3], list(range(16)), [15, 0, 7, 8]])
def test_patron_valido(seq):
    c3.validate_pattern(seq)


@pytest.mark.parametrize("seq, msg", [
    ([], "al menos"),
    ([0, 1, 2], "al menos"),
    ([0, 1, 2, 1], "repetir"),
    ([0, 1, 2, 16], "fuera"),
    ([-1, 0, 1, 2], "fuera"),
])
def test_patron_invalido(seq, msg):
    with pytest.raises(c3.CryptoError, match=msg):
        c3.validate_pattern(seq)


def test_pattern_secret_depende_del_orden(ids):
    assert c3.pattern_secret([0, 1, 2, 3], ids) != c3.pattern_secret([3, 2, 1, 0], ids)


def test_pattern_secret_depende_de_ids(ids):
    otros = c3.new_ids()
    assert c3.pattern_secret([0, 1, 2, 3], ids) != c3.pattern_secret([0, 1, 2, 3], otros)


def test_control_sum():
    ids = list(range(100000, 100016))
    assert c3.control_sum([0, 2, 15], ids) == 100000 + 100002 + 100015
    assert c3.control_sum([], ids) == 0


# ---------- Archivo llave ----------

def test_generate_keyfile(keyfile):
    assert len(c3.read_keyfile(keyfile)) == c3.KEYFILE_LEN


def test_generate_keyfile_no_sobrescribe(keyfile):
    with open(keyfile, "rb") as f:
        original = f.read()
    with pytest.raises(c3.CryptoError, match="Ya existe"):
        c3.generate_keyfile(keyfile)
    with open(keyfile, "rb") as f:
        assert f.read() == original


def test_keyfile_demasiado_pequeno(tmp_path):
    path = tmp_path / "corta.key"
    path.write_bytes(b"x" * 31)
    with pytest.raises(c3.CryptoError, match="pequeno"):
        c3.read_keyfile(str(path))


def test_keyfile_32_bytes_vale(tmp_path):
    path = tmp_path / "justa.key"
    path.write_bytes(b"x" * 32)
    assert len(c3.read_keyfile(str(path))) == 32


# ---------- Rutas ----------

def test_unique_path_libre(tmp_path):
    p = str(tmp_path / "a.txt")
    assert c3.unique_path(p) == p


def test_unique_path_ocupada(tmp_path):
    (tmp_path / "a.txt").write_text("1")
    (tmp_path / "a (1).txt").write_text("2")
    assert c3.unique_path(str(tmp_path / "a.txt")) == str(tmp_path / "a (2).txt")
