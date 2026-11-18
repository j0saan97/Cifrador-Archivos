import os
import secrets
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cifrador_3capas as c3  # noqa: E402


@pytest.fixture
def ids():
    return c3.new_ids()


@pytest.fixture
def seq():
    return [0, 5, 10, 15, 14]


@pytest.fixture
def key():
    return secrets.token_bytes(c3.KEYFILE_LEN)


@pytest.fixture
def pw():
    return "Contrasena-Segura-123"


@pytest.fixture
def keyfile(tmp_path):
    path = tmp_path / "llave.key"
    c3.generate_keyfile(str(path))
    return str(path)
