import os
from tkinter import Tk, Label, Button, filedialog, Entry, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# ---------- Funciones principales ----------

def generar_clave(password: str) -> bytes:
    """Genera una clave de 32 bytes a partir de la contraseña del usuario."""
    key = hashlib.sha256(password.encode()).digest()  # crea hash SHA256
    return base64.urlsafe_b64encode(key)  # convierte a formato válido para Fernet

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

    nuevo_nombre = ruta + ".cifrado"
    with open(nuevo_nombre, 'wb') as archivo_cifrado:
        archivo_cifrado.write(datos_cifrados)

    messagebox.showinfo("Éxito", f"Archivo cifrado correctamente:\n{nuevo_nombre}")

def descifrar_archivo():
    ruta = filedialog.askopenfilename(title="Selecciona el archivo a descifrar")
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

        nuevo_nombre = ruta.replace(".cifrado", "_descifrado")
        with open(nuevo_nombre, 'wb') as archivo_descifrado:
            archivo_descifrado.write(datos_descifrados)

        messagebox.showinfo("Éxito", f"Archivo descifrado correctamente:\n{nuevo_nombre}")
    except Exception:
        messagebox.showerror("Error", "Contraseña incorrecta o archivo dañado.")

# ---------- Interfaz gráfica ----------

ventana = Tk()
ventana.title("SecureFile - Cifrado de Archivos")
ventana.geometry("400x250")
ventana.config(bg="#e6f2ff")

Label(ventana, text="🔒 SecureFile", font=("Arial", 16, "bold"), bg="#e6f2ff", fg="#003366").pack(pady=10)
Label(ventana, text="Contraseña:", bg="#e6f2ff", fg="#003366", font=("Arial", 12)).pack(pady=5)

entrada_password = Entry(ventana, show="*", width=30)
entrada_password.pack()

Button(ventana, text="Cifrar archivo", command=cifrar_archivo, bg="#0066cc", fg="white", width=20).pack(pady=10)
Button(ventana, text="Descifrar archivo", command=descifrar_archivo, bg="#009933", fg="white", width=20).pack(pady=5)

ventana.mainloop()
