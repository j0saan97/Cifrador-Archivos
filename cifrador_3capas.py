"""
Cifrador de archivos en 3 capas.

  Capa 1 (exterior): contrasena     -> Argon2id  -> AES-256-GCM
  Capa 2 (media):    patron 4x4     -> Argon2id  -> ChaCha20-Poly1305
  Capa 3 (interior): archivo llave  -> HKDF-SHA256 -> AES-256-GCM

Patron 4x4: cada uno de los 16 puntos recibe un ID aleatorio de 6 cifras al
cifrar. La clave de la capa 2 se deriva de la SECUENCIA ORDENADA de los IDs que
pulsas. La suma de esos IDs solo se muestra como "numero de control" para que
compruebes que has marcado el patron correcto; no se guarda en ningun sitio.

Los IDs se guardan en la cabecera del archivo cifrado (no son secretos: el
secreto es que puntos pulsas y en que orden). Toda la cabecera esta autenticada,
asi que no se puede manipular sin que el descifrado falle.

Uso:
    python cifrador_3capas.py          -> abre la ventana
    python cifrador_3capas.py --test   -> autoprueba sin ventana
"""

import os
import secrets
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------
# Formato del archivo .c3
#   MAGIC(4) | VERSION(1) | 16 IDs uint32 (64) | sal_pw(16) | sal_pat(16)
#   | sal_kf(16) | nonce1(12) | nonce2(12) | nonce3(12) | datos cifrados
# --------------------------------------------------------------------------
MAGIC = b"C3LY"
VERSION = 1
EXTENSION = ".c3"
GRID = 4
NUM_POINTS = GRID * GRID
MIN_PATTERN = 4
SALT_LEN = 16
NONCE_LEN = 12
HEADER_FMT = f">4sB{NUM_POINTS}I{SALT_LEN}s{SALT_LEN}s{SALT_LEN}s{NONCE_LEN}s{NONCE_LEN}s{NONCE_LEN}s"
HEADER_LEN = struct.calcsize(HEADER_FMT)
KEYFILE_LEN = 64

# Parametros Argon2id: 64 MiB de memoria, 3 pasadas.
ARGON_MEMORY_KIB = 64 * 1024
ARGON_ITERATIONS = 3
ARGON_LANES = 4


class CryptoError(Exception):
    """Error con mensaje apto para mostrar al usuario."""


# ----------------------------- Derivacion de claves -----------------------

def _argon2(secret: bytes, salt: bytes, context: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON_ITERATIONS,
        lanes=ARGON_LANES,
        memory_cost=ARGON_MEMORY_KIB,
        ad=context,
    )
    return kdf.derive(secret)


def key_from_password(password: str, salt: bytes) -> bytes:
    return _argon2(password.encode("utf-8"), salt, b"c3-capa1-password")


def pattern_secret(sequence: list[int], ids: list[int]) -> bytes:
    """Convierte el patron (posiciones 0-15 en orden) en bytes secretos.
    Incluye posicion e ID de cada punto, en el orden en que se pulsaron."""
    return b"".join(struct.pack(">BI", pos, ids[pos]) for pos in sequence)


def key_from_pattern(sequence: list[int], ids: list[int], salt: bytes) -> bytes:
    return _argon2(pattern_secret(sequence, ids), salt, b"c3-capa2-patron")


def key_from_keyfile(keyfile_bytes: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"c3-capa3-llave")
    return hkdf.derive(keyfile_bytes)


# ----------------------------- Utilidades ---------------------------------

def new_ids() -> list[int]:
    """16 IDs aleatorios de 6 cifras, sin repetir."""
    ids: set[int] = set()
    while len(ids) < NUM_POINTS:
        ids.add(100000 + secrets.randbelow(900000))
    result = list(ids)
    secrets.SystemRandom().shuffle(result)
    return result


def control_sum(sequence: list[int], ids: list[int]) -> int:
    return sum(ids[p] for p in sequence)


def validate_pattern(sequence: list[int]) -> None:
    if len(sequence) < MIN_PATTERN:
        raise CryptoError(f"El patron debe tener al menos {MIN_PATTERN} puntos.")
    if len(set(sequence)) != len(sequence):
        raise CryptoError("El patron no puede repetir puntos.")
    if any(not 0 <= p < NUM_POINTS for p in sequence):
        raise CryptoError("Punto del patron fuera de la cuadricula.")


def generate_keyfile(path: str) -> None:
    if os.path.exists(path):
        raise CryptoError(f"Ya existe un archivo en:\n{path}\nNo se sobrescribe.")
    with open(path, "xb") as f:
        f.write(secrets.token_bytes(KEYFILE_LEN))


def read_keyfile(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 32:
        raise CryptoError("El archivo llave es demasiado pequeno (minimo 32 bytes).")
    return data


def read_header_ids(path: str) -> list[int] | None:
    """Devuelve los IDs guardados si el archivo es un .c3 valido, si no None."""
    try:
        with open(path, "rb") as f:
            raw = f.read(HEADER_LEN)
    except OSError:
        return None
    if len(raw) != HEADER_LEN or not raw.startswith(MAGIC):
        return None
    fields = struct.unpack(HEADER_FMT, raw)
    if fields[1] != VERSION:
        return None
    return list(fields[2:2 + NUM_POINTS])


def unique_path(path: str) -> str:
    """Devuelve una ruta que no existe, para no sobrescribir nunca nada."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    n = 1
    while os.path.exists(f"{base} ({n}){ext}"):
        n += 1
    return f"{base} ({n}){ext}"


# ----------------------------- Cifrar / descifrar -------------------------

def encrypt_bytes(plaintext: bytes, password: str, sequence: list[int],
                  ids: list[int], keyfile_bytes: bytes) -> bytes:
    if not password:
        raise CryptoError("La contrasena no puede estar vacia.")
    validate_pattern(sequence)
    if len(ids) != NUM_POINTS or len(set(ids)) != NUM_POINTS:
        raise CryptoError("IDs de la cuadricula no validos.")

    salt_pw, salt_pat, salt_kf = (secrets.token_bytes(SALT_LEN) for _ in range(3))
    n1, n2, n3 = (secrets.token_bytes(NONCE_LEN) for _ in range(3))
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, *ids,
                         salt_pw, salt_pat, salt_kf, n1, n2, n3)

    k_pw = key_from_password(password, salt_pw)
    k_pat = key_from_pattern(sequence, ids, salt_pat)
    k_kf = key_from_keyfile(keyfile_bytes, salt_kf)

    # De dentro hacia fuera: llave -> patron -> contrasena.
    c = AESGCM(k_kf).encrypt(n3, plaintext, header)
    c = ChaCha20Poly1305(k_pat).encrypt(n2, c, header)
    c = AESGCM(k_pw).encrypt(n1, c, header)
    return header + c


def decrypt_bytes(blob: bytes, password: str, sequence: list[int],
                  keyfile_bytes: bytes) -> bytes:
    if len(blob) < HEADER_LEN or not blob.startswith(MAGIC):
        raise CryptoError("No es un archivo cifrado con este programa (.c3).")
    header = blob[:HEADER_LEN]
    fields = struct.unpack(HEADER_FMT, header)
    if fields[1] != VERSION:
        raise CryptoError(f"Version de archivo no soportada: {fields[1]}")
    ids = list(fields[2:2 + NUM_POINTS])
    salt_pw, salt_pat, salt_kf, n1, n2, n3 = fields[2 + NUM_POINTS:]
    validate_pattern(sequence)
    c = blob[HEADER_LEN:]

    try:
        c = AESGCM(key_from_password(password, salt_pw)).decrypt(n1, c, header)
    except InvalidTag:
        raise CryptoError("Capa 1: contrasena incorrecta (o archivo danado).") from None
    try:
        c = ChaCha20Poly1305(key_from_pattern(sequence, ids, salt_pat)).decrypt(n2, c, header)
    except InvalidTag:
        raise CryptoError("Capa 2: patron incorrecto.") from None
    try:
        return AESGCM(key_from_keyfile(keyfile_bytes, salt_kf)).decrypt(n3, c, header)
    except InvalidTag:
        raise CryptoError("Capa 3: archivo llave incorrecto.") from None


def encrypt_file(src: str, password: str, sequence: list[int], ids: list[int],
                 keyfile_path: str) -> str:
    with open(src, "rb") as f:
        data = f.read()
    blob = encrypt_bytes(data, password, sequence, ids, read_keyfile(keyfile_path))
    dst = unique_path(src + EXTENSION)
    with open(dst, "xb") as f:
        f.write(blob)
    return dst


def decrypt_file(src: str, password: str, sequence: list[int], keyfile_path: str) -> str:
    with open(src, "rb") as f:
        blob = f.read()
    data = decrypt_bytes(blob, password, sequence, read_keyfile(keyfile_path))
    base = src[:-len(EXTENSION)] if src.lower().endswith(EXTENSION) else src + ".descifrado"
    dst = unique_path(base)
    with open(dst, "xb") as f:
        f.write(data)
    return dst


# ----------------------------- Interfaz grafica ---------------------------

def run_gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("Cifrador 3 capas")
    root.resizable(False, False)

    state = {"ids": new_ids(), "sequence": [], "from_header": False}
    pad = {"padx": 8, "pady": 4}

    # --- Archivo ---
    frm_file = tk.LabelFrame(root, text="Archivo")
    frm_file.grid(row=0, column=0, columnspan=2, sticky="ew", **pad)
    var_file = tk.StringVar()
    tk.Entry(frm_file, textvariable=var_file, width=52).grid(row=0, column=0, **pad)

    def choose_file():
        path = filedialog.askopenfilename(title="Elige un archivo")
        if not path:
            return
        var_file.set(path)
        ids = read_header_ids(path)
        if ids:
            state["ids"], state["from_header"] = ids, True
            lbl_mode.config(text="Archivo cifrado: IDs cargados del archivo. Pulsa DESCIFRAR.", fg="#1a6")
        else:
            if state["from_header"]:
                state["ids"] = new_ids()
            state["from_header"] = False
            lbl_mode.config(text="Archivo normal: marca tu patron y pulsa CIFRAR.", fg="#36c")
        clear_pattern()

    tk.Button(frm_file, text="Elegir...", command=choose_file).grid(row=0, column=1, **pad)
    lbl_mode = tk.Label(frm_file, text="Elige un archivo para empezar.", fg="#555")
    lbl_mode.grid(row=1, column=0, columnspan=2, sticky="w", **pad)

    # --- Capa 1: contrasena ---
    frm_pw = tk.LabelFrame(root, text="Capa 1 - Contrasena")
    frm_pw.grid(row=1, column=0, columnspan=2, sticky="ew", **pad)
    var_pw, var_pw2 = tk.StringVar(), tk.StringVar()
    tk.Label(frm_pw, text="Contrasena:").grid(row=0, column=0, sticky="e", **pad)
    tk.Entry(frm_pw, textvariable=var_pw, show="•", width=36).grid(row=0, column=1, **pad)
    tk.Label(frm_pw, text="Repetir (al cifrar):").grid(row=1, column=0, sticky="e", **pad)
    tk.Entry(frm_pw, textvariable=var_pw2, show="•", width=36).grid(row=1, column=1, **pad)

    # --- Capa 2: patron ---
    frm_pat = tk.LabelFrame(root, text="Capa 2 - Patron 4x4 (pulsa los puntos en orden)")
    frm_pat.grid(row=2, column=0, columnspan=2, sticky="ew", **pad)
    grid_frame = tk.Frame(frm_pat)
    grid_frame.grid(row=0, column=0, rowspan=3, **pad)
    buttons: list[tk.Button] = []
    default_bg = root.cget("bg")

    def refresh_grid():
        seq = state["sequence"]
        for pos, btn in enumerate(buttons):
            if pos in seq:
                btn.config(text=f"#{seq.index(pos) + 1}\n{state['ids'][pos]}", bg="#4a8", fg="white")
            else:
                btn.config(text=f"\n{state['ids'][pos]}", bg=default_bg, fg="black")
        if seq:
            puntos = "-".join(str(p + 1) for p in seq)
            lbl_info.config(text=f"Puntos: {puntos}\nSuma de control: {control_sum(seq, state['ids'])}")
        else:
            lbl_info.config(text="Puntos: (ninguno)\nSuma de control: -")

    def press(pos):
        if pos not in state["sequence"]:
            state["sequence"].append(pos)
            refresh_grid()

    def clear_pattern():
        state["sequence"] = []
        refresh_grid()

    def regenerate_ids():
        if state["from_header"]:
            messagebox.showinfo("IDs", "Este archivo ya esta cifrado: sus IDs no se pueden cambiar.")
            return
        state["ids"] = new_ids()
        clear_pattern()

    for pos in range(NUM_POINTS):
        b = tk.Button(grid_frame, width=8, height=2, command=lambda p=pos: press(p))
        b.grid(row=pos // GRID, column=pos % GRID, padx=2, pady=2)
        buttons.append(b)

    lbl_info = tk.Label(frm_pat, justify="left", font=("Consolas", 10))
    lbl_info.grid(row=0, column=1, sticky="nw", **pad)
    tk.Button(frm_pat, text="Borrar patron", command=clear_pattern).grid(row=1, column=1, sticky="ew", **pad)
    tk.Button(frm_pat, text="Nuevos IDs", command=regenerate_ids).grid(row=2, column=1, sticky="ew", **pad)

    # --- Capa 3: archivo llave ---
    frm_kf = tk.LabelFrame(root, text="Capa 3 - Archivo llave (guardalo en un USB)")
    frm_kf.grid(row=3, column=0, columnspan=2, sticky="ew", **pad)
    var_kf = tk.StringVar()
    tk.Entry(frm_kf, textvariable=var_kf, width=40).grid(row=0, column=0, **pad)

    def choose_keyfile():
        path = filedialog.askopenfilename(title="Elige tu archivo llave")
        if path:
            var_kf.set(path)

    def create_keyfile():
        path = filedialog.asksaveasfilename(title="Guardar nueva llave", defaultextension=".key",
                                            initialfile="mi_llave.key",
                                            filetypes=[("Archivo llave", "*.key"), ("Todos", "*.*")])
        if not path:
            return
        try:
            generate_keyfile(path)
        except CryptoError as e:
            messagebox.showerror("Llave", str(e))
            return
        var_kf.set(path)
        messagebox.showinfo("Llave creada",
                            f"Llave creada en:\n{path}\n\nHaz una COPIA DE SEGURIDAD. "
                            "Si la pierdes, no podras descifrar tus archivos.")

    tk.Button(frm_kf, text="Elegir...", command=choose_keyfile).grid(row=0, column=1, **pad)
    tk.Button(frm_kf, text="Generar nueva...", command=create_keyfile).grid(row=0, column=2, **pad)

    # --- Acciones ---
    def common_checks():
        if not var_file.get() or not os.path.isfile(var_file.get()):
            raise CryptoError("Elige un archivo valido.")
        if not var_kf.get() or not os.path.isfile(var_kf.get()):
            raise CryptoError("Elige o genera un archivo llave.")
        if os.path.abspath(var_kf.get()) == os.path.abspath(var_file.get()):
            raise CryptoError("El archivo llave no puede ser el mismo archivo que cifras.")

    def run_action(fn):
        root.config(cursor="watch")
        root.update()
        try:
            return fn()
        finally:
            root.config(cursor="")

    def do_encrypt():
        try:
            common_checks()
            if state["from_header"]:
                raise CryptoError("Este archivo ya esta cifrado. Usa DESCIFRAR.")
            if var_pw.get() != var_pw2.get():
                raise CryptoError("Las contrasenas no coinciden.")
            seq = list(state["sequence"])
            dst = run_action(lambda: encrypt_file(var_file.get(), var_pw.get(), seq,
                                                  state["ids"], var_kf.get()))
        except (CryptoError, OSError) as e:
            messagebox.showerror("Error al cifrar", str(e))
            return
        puntos = "-".join(str(p + 1) for p in seq)
        messagebox.showinfo("Cifrado",
                            f"Archivo cifrado:\n{dst}\n\nPatron: puntos {puntos}\n"
                            f"Suma de control: {control_sum(seq, state['ids'])}\n\n"
                            "El archivo original NO se ha borrado. Comprueba que puedes "
                            "descifrar la copia antes de borrarlo.")
        var_pw.set(""); var_pw2.set("")
        state["ids"] = new_ids()
        clear_pattern()

    def do_decrypt():
        try:
            common_checks()
            if not state["from_header"]:
                raise CryptoError("Este archivo no esta cifrado con este programa (.c3).")
            seq = list(state["sequence"])
            dst = run_action(lambda: decrypt_file(var_file.get(), var_pw.get(), seq, var_kf.get()))
        except (CryptoError, OSError) as e:
            messagebox.showerror("Error al descifrar", str(e))
            return
        messagebox.showinfo("Descifrado", f"Archivo descifrado:\n{dst}")
        var_pw.set(""); var_pw2.set("")
        clear_pattern()

    frm_act = tk.Frame(root)
    frm_act.grid(row=4, column=0, columnspan=2, **pad)
    tk.Button(frm_act, text="CIFRAR", width=18, bg="#36c", fg="white", command=do_encrypt).grid(row=0, column=0, padx=10, pady=8)
    tk.Button(frm_act, text="DESCIFRAR", width=18, bg="#1a6", fg="white", command=do_decrypt).grid(row=0, column=1, padx=10, pady=8)

    refresh_grid()
    root.mainloop()


# ----------------------------- Autoprueba ---------------------------------

def self_test() -> None:
    data = os.urandom(10_000) + "texto con tildes: canon, nino".encode()
    ids = new_ids()
    seq = [0, 5, 10, 15, 14]
    key = secrets.token_bytes(KEYFILE_LEN)
    pw = "Contrasena-Segura-123"

    blob = encrypt_bytes(data, pw, seq, ids, key)
    assert decrypt_bytes(blob, pw, seq, key) == data, "ida y vuelta"
    print("[OK] cifrar y descifrar devuelve el original")

    cases = [
        ("contrasena incorrecta", lambda: decrypt_bytes(blob, "otra", seq, key), "Capa 1"),
        ("patron en otro orden", lambda: decrypt_bytes(blob, pw, [5, 0, 10, 15, 14], key), "Capa 2"),
        ("patron distinto", lambda: decrypt_bytes(blob, pw, [0, 5, 10, 15, 13], key), "Capa 2"),
        ("llave incorrecta", lambda: decrypt_bytes(blob, pw, seq, secrets.token_bytes(64)), "Capa 3"),
    ]
    for name, fn, expected in cases:
        try:
            fn()
            raise AssertionError(f"{name}: deberia fallar")
        except CryptoError as e:
            assert expected in str(e), f"{name}: mensaje inesperado {e}"
            print(f"[OK] {name} -> rechazado ({expected})")

    tampered = bytearray(blob); tampered[10] ^= 1  # cambiar un ID de la cabecera
    try:
        decrypt_bytes(bytes(tampered), pw, seq, key)
        raise AssertionError("cabecera manipulada: deberia fallar")
    except CryptoError:
        print("[OK] cabecera manipulada -> rechazada")

    try:
        encrypt_bytes(data, pw, [1, 2, 3], ids, key)
        raise AssertionError("patron corto: deberia fallar")
    except CryptoError:
        print("[OK] patron de menos de 4 puntos -> rechazado")

    print("Autoprueba completada.")


if __name__ == "__main__":
    if "--test" in sys.argv:
        self_test()
    else:
        run_gui()
