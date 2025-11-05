import os
import json
import shutil
import time
import platform
from tkinter import Tk, Label, Button, filedialog, Entry, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib
import stat
import subprocess

# ---------- Configuración ----------
SECURE_FOLDER_NAME = "Archivos_Seguros"  # nombre base (se hará oculto según SO)
METADATA_FILENAME = ".metadata.json"     # archivo para mapear cifrado -> ruta original

# ---------- Funciones auxiliares ----------

def generar_clave(password: str) -> bytes:
    """Genera una clave segura de 32 bytes a partir de la contraseña."""
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def obtener_ruta_carpeta_segura() -> str:
    """Devuelve la ruta absoluta de la carpeta segura (crea si no existe)."""
    base = os.getcwd()
    carpeta = os.path.join(base, SECURE_FOLDER_NAME)
    if not os.path.exists(carpeta):
        os.mkdir(carpeta)
        # hacerla oculta y restringir permisos
        configurar_oculto_y_permisos(carpeta)
        # crear metadata vacío
        guardar_metadata({}, carpeta)
    return carpeta

def ruta_metadata(carpeta_segura: str) -> str:
    return os.path.join(carpeta_segura, METADATA_FILENAME)

def cargar_metadata(carpeta_segura: str) -> dict:
    ruta = ruta_metadata(carpeta_segura)
    if not os.path.exists(ruta):
        return {}
    with open(ruta, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def guardar_metadata(data: dict, carpeta_segura: str):
    ruta = ruta_metadata(carpeta_segura)
    with open(ruta, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def generar_nombre_unico(carpeta, nombre_base):
    nombre = nombre_base
    contador = 1
    while os.path.exists(os.path.join(carpeta, nombre)):
        nombre = f"{nombre_base}_{int(time.time())}_{contador}"
        contador += 1
    return nombre

def configurar_oculto_y_permisos(carpeta):
    """Intenta ocultar la carpeta y restringir permisos (mejor esfuerzo)."""
    try:
        sistema = platform.system()
        if sistema == "Windows":
            # Atributo oculto
            subprocess.call(["attrib", "+h", carpeta])
            # Nota: cambiar ACLs en Windows es complejo; esto solo oculta la carpeta
        else:
            # En Unix, renombrar con punto la carpeta para ocultarla en la vista por defecto
            parent = os.path.dirname(carpeta)
            hidden = os.path.join(parent, "." + os.path.basename(carpeta))
            if not os.path.exists(hidden):
                os.rename(carpeta, hidden)
                carpeta = hidden
            # Establecer permisos owner-only (rwx------)
            os.chmod(carpeta, 0o700)
    except Exception:
        pass  # si falla no detendremos el programa

# ---------- Operaciones principales ----------

def cifrar_archivo():
    ruta = filedialog.askopenfilename(title="Selecciona el archivo a cifrar")
    if not ruta:
        return

    password = entrada_password.get()
    if not password:
        messagebox.showwarning("Advertencia", "Ingresa una contraseña para cifrar.")
        return

    clave = generar_clave(password)
    fernet = Fernet(clave)

    # leer archivo
    with open(ruta, 'rb') as f:
        datos = f.read()

    datos_cifrados = fernet.encrypt(datos)

    carpeta_segura = obtener_ruta_carpeta_segura()
    # asegurar la ruta actual de carpeta_segura si fue renombrada en Unix
    carpeta_segura = os.path.join(os.getcwd(), os.path.basename(carpeta_segura))
    # nombre del archivo cifrado
    nombre_archivo = os.path.basename(ruta) + ".cifrado"
    nombre_archivo = generar_nombre_unico(carpeta_segura, nombre_archivo)
    ruta_cifrado = os.path.join(carpeta_segura, nombre_archivo)

    # guardar cifrado en carpeta segura
    with open(ruta_cifrado, 'wb') as f:
        f.write(datos_cifrados)

    # actualizar metadata con la ruta original absoluta
    metadata = cargar_metadata(carpeta_segura)
    metadata[nombre_archivo] = os.path.abspath(ruta)
    guardar_metadata(metadata, carpeta_segura)

    # eliminar archivo original (para que no quede expuesto)
    try:
        os.remove(ruta)
    except Exception:
        # si no se puede eliminar, intentamos moverlo (último recurso)
        try:
            shutil.move(ruta, carpeta_segura)
        except Exception:
            pass

    messagebox.showinfo("Éxito", f"Archivo cifrado y guardado en carpeta segura:\n{ruta_cifrado}")
    entrada_password.delete(0, 'end')

def descifrar_archivo():
    carpeta_segura = obtener_ruta_carpeta_segura()
    # abrir diálogo en la carpeta segura
    ruta = filedialog.askopenfilename(title="Selecciona el archivo a descifrar", initialdir=carpeta_segura)
    if not ruta:
        return

    password = entrada_password.get()
    if not password:
        messagebox.showwarning("Advertencia", "Ingresa la contraseña para descifrar.")
        return

    clave = generar_clave(password)
    fernet = Fernet(clave)

    nombre_cifrado = os.path.basename(ruta)
    metadata = cargar_metadata(carpeta_segura)

    try:
        with open(ruta, 'rb') as f:
            datos_cifrados = f.read()

        datos_descifrados = fernet.decrypt(datos_cifrados)

        # determinar ruta original desde metadata; si no existe, colocar en carpeta actual
        ruta_original = metadata.get(nombre_cifrado, None)
        if ruta_original:
            ruta_destino = ruta_original
            # asegurar que la carpeta destino existe
            carpeta_destino = os.path.dirname(ruta_destino)
            if not os.path.exists(carpeta_destino):
                os.makedirs(carpeta_destino, exist_ok=True)
        else:
            # si no se encuentra metadata, dejar en la carpeta actual de usuario
            ruta_destino = os.path.join(os.path.expanduser("~"), nombre_cifrado.replace(".cifrado", "_descifrado"))

        # si existe un archivo en destino, renombrar para evitar sobreescritura
        if os.path.exists(ruta_destino):
            ruta_destino = generar_nombre_unico(os.path.dirname(ruta_destino), os.path.basename(ruta_destino))

        with open(ruta_destino, 'wb') as f:
            f.write(datos_descifrados)

        # actualizar metadata: eliminar entrada y borrar archivo cifrado
        if nombre_cifrado in metadata:
            del metadata[nombre_cifrado]
            guardar_metadata(metadata, carpeta_segura)

        # eliminar archivo cifrado
        try:
            os.remove(ruta)
        except Exception:
            pass

        messagebox.showinfo("Éxito", f"Archivo descifrado y restaurado en:\n{ruta_destino}")
        entrada_password.delete(0, 'end')
    except Exception:
        messagebox.showerror("Error", "Contraseña incorrecta o archivo dañado.")
        entrada_password.delete(0, 'end')

# ---------- Interfaz gráfica ----------

ventana = Tk()
ventana.title("SecureFile - Protección de Archivos (v3)")
ventana.geometry("460x280")
ventana.config(bg="#e6f2ff")

Label(ventana, text="🔐 SecureFile - Protección de Archivos", font=("Arial", 14, "bold"), bg="#e6f2ff", fg="#003366").pack(pady=10)
Label(ventana, text="Contraseña:", bg="#e6f2ff", fg="#003366", font=("Arial", 12)).pack(pady=5)

entrada_password = Entry(ventana, show="*", width=38)
entrada_password.pack()

Button(ventana, text="Cifrar archivo", command=cifrar_archivo, bg="#0066cc", fg="white", width=22).pack(pady=10)
Button(ventana, text="Descifrar archivo", command=descifrar_archivo, bg="#009933", fg="white", width=22).pack(pady=5)

Label(ventana, text="Los archivos cifrados se guardan en la carpeta segura", bg="#e6f2ff", fg="#666666", font=("Arial", 9)).pack(pady=10)
Label(ventana, text="Desarrollado por Oscar Cuervo, Andres Nova, David Castiblanco", bg="#e6f2ff", fg="#666666", font=("Arial", 8)).pack(side="bottom", pady=6)

ventana.mainloop()
