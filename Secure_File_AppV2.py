import os
import shutil
from tkinter import Tk, Label, Button, filedialog, Entry, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# ---------- Funciones de seguridad ----------

def generar_clave(password: str) -> bytes:
    """Genera una clave de 32 bytes a partir de la contraseña del usuario."""
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

# ---------- Cifrar y descifrar archivos ----------

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

    with open(ruta, 'rb') as archivo:
        datos = archivo.read()

    datos_cifrados = fernet.encrypt(datos)

    # Crear carpeta segura si no existe
    carpeta_segura = "Archivos_Seguros"
    if not os.path.exists(carpeta_segura):
        os.mkdir(carpeta_segura)

    # Guardar archivo cifrado dentro de la carpeta segura
    nombre_archivo = os.path.basename(ruta)
    nuevo_nombre = os.path.join(carpeta_segura, nombre_archivo + ".cifrado")

    with open(nuevo_nombre, 'wb') as archivo_cifrado:
        archivo_cifrado.write(datos_cifrados)

    # Mover archivo original a la carpeta segura (y eliminar copia visible)
    try:
        shutil.move(ruta, carpeta_segura)
    except Exception:
        pass  # Si no puede mover, no detiene el programa

    messagebox.showinfo("Éxito", f"Archivo cifrado y movido a:\n{carpeta_segura}")
    entrada_password.delete(0, 'end')  # limpiar contraseña


def descifrar_archivo():
    carpeta_segura = "Archivos_Seguros"
    ruta = filedialog.askopenfilename(title="Selecciona el archivo a descifrar", initialdir=carpeta_segura)
    if not ruta:
        return

    password = entrada_password.get()
    if not password:
        messagebox.showwarning("Advertencia", "Ingresa la contraseña correcta.")
        return

    clave = generar_clave(password)
    fernet = Fernet(clave)

    try:
        with open(ruta, 'rb') as archivo:
            datos_cifrados = archivo.read()

        datos_descifrados = fernet.decrypt(datos_cifrados)

        nuevo_nombre = ruta.replace(".cifrado", "")
        with open(nuevo_nombre, 'wb') as archivo_descifrado:
            archivo_descifrado.write(datos_descifrados)

        messagebox.showinfo("Éxito", f"Archivo descifrado correctamente:\n{nuevo_nombre}")
        entrada_password.delete(0, 'end')  # limpiar contraseña
    except Exception:
        messagebox.showerror("Error", "Contraseña incorrecta o archivo dañado.")
        entrada_password.delete(0, 'end')

# ---------- Interfaz gráfica ----------

ventana = Tk()
ventana.title("SecureFile - Protección de Archivos")
ventana.geometry("420x260")
ventana.config(bg="#e6f2ff")

Label(ventana, text="🔐 SecureFile - Protección de Archivos", font=("Arial", 14, "bold"), bg="#e6f2ff", fg="#003366").pack(pady=10)
Label(ventana, text="Contraseña:", bg="#e6f2ff", fg="#003366", font=("Arial", 12)).pack(pady=5)

entrada_password = Entry(ventana, show="*", width=35)
entrada_password.pack()

Button(ventana, text="Cifrar archivo", command=cifrar_archivo, bg="#0066cc", fg="white", width=20).pack(pady=10)
Button(ventana, text="Descifrar archivo", command=descifrar_archivo, bg="#009933", fg="white", width=20).pack(pady=5)

Label(ventana, text="Archivos protegidos en carpeta: Archivos_Seguros", bg="#e6f2ff", fg="#666666", font=("Arial", 9)).pack(pady=10)

ventana.mainloop()
