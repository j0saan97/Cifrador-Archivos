# Cifrador 3 capas

Cifrador de archivos en Python con interfaz Tkinter. Un solo archivo: `cifrador_3capas.py`.

## Flujo de trabajo
- Se trabaja en la rama `dev`. No hacer commit ni merge a `main` salvo que se pida.
- Remoto: https://github.com/j0saan97/Cifrador-Archivos
- Este repo es independiente. El repo git del Escritorio tiene archivos personales y no se usa para este proyecto.

## Ejecutar
- `python cifrador_3capas.py`: abre la ventana.
- `python cifrador_3capas.py --test`: autoprueba sin ventana. Pasarla después de cualquier cambio en la parte criptográfica.
- Dependencia: `cryptography` (necesita una versión con `Argon2id`, es decir 44 o superior).

## Diseño criptográfico
Se cifra de dentro hacia fuera; al descifrar se recorre en orden inverso:
1. Capa 1 (exterior): contraseña → Argon2id → AES-256-GCM
2. Capa 2 (media): patrón 4x4 → Argon2id → ChaCha20-Poly1305
3. Capa 3 (interior): archivo llave (`.key`, 64 bytes) → HKDF-SHA256 → AES-256-GCM

- La cabecera entera (MAGIC `C3LY`, VERSION, los 16 IDs, las sales y los nonces) se pasa como AAD en las tres capas. Cualquier cambio en ella hace fallar el descifrado.
- Los IDs de la cuadrícula no son secretos. El secreto es qué puntos se pulsan y en qué orden. La "suma de control" solo se muestra en pantalla y no se guarda.
- Si se cambia el formato de la cabecera o los parámetros de Argon2, hay que subir `VERSION`. Si no, los archivos `.c3` ya existentes dejan de descifrarse.

## Reglas
- Nunca sobrescribir archivos: para escribir se usa `unique_path` con modo `"xb"`, y el archivo original no se borra.
- Los mensajes de error para el usuario se lanzan como `CryptoError`, en español y sin tildes (estilo actual del código).
- No subir archivos `.key` ni `.c3` (ya están en `.gitignore`).
