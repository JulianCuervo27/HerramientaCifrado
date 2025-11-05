import os
from tkinter import Tk, Label, Button, filedialog, Entry, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# ---------- Funciones principales ----------

def generar_clave(password: str) -> bytes:
    """Genera una clave segura (32 bytes) a partir de la contraseña del usuario."""
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

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

    # Leer el archivo original
    with open(ruta, 'rb') as archivo:
        datos = archivo.read()

    # Cifrar contenido
    datos_cifrados = fernet.encrypt(datos)

    # Guardar archivo cifrado en la misma carpeta
    nuevo_nombre = ruta + ".cifrado"
    with open(nuevo_nombre, 'wb') as archivo_cifrado:
        archivo_cifrado.write(datos_cifrados)

    # Eliminar archivo original para protegerlo
    try:
        os.remove(ruta)
    except Exception:
        pass

    messagebox.showinfo("Éxito", f"Archivo cifrado en la misma carpeta:\n{nuevo_nombre}")
    entrada_password.delete(0, 'end')  # limpiar contraseña

def descifrar_archivo():
    ruta = filedialog.askopenfilename(title="Selecciona el archivo a descifrar")
    if not ruta:
        return

    password = entrada_password.get()
    if not password:
        messagebox.showwarning("Advertencia", "Ingresa la contraseña para descifrar.")
        return

    clave = generar_clave(password)
    fernet = Fernet(clave)

    try:
        # Leer archivo cifrado
        with open(ruta, 'rb') as archivo:
            datos_cifrados = archivo.read()

        # Descifrar datos
        datos_descifrados = fernet.decrypt(datos_cifrados)

        # Generar nombre original (sin .cifrado)
        ruta_descifrada = ruta.replace(".cifrado", "")
        with open(ruta_descifrada, 'wb') as archivo_descifrado:
            archivo_descifrado.write(datos_descifrados)

        # Eliminar archivo cifrado (para mantener solo el descifrado)
        os.remove(ruta)

        messagebox.showinfo("Éxito", f"Archivo descifrado correctamente:\n{ruta_descifrada}")
        entrada_password.delete(0, 'end')
    except Exception:
        messagebox.showerror("Error", "Contraseña incorrecta o archivo dañado.")
        entrada_password.delete(0, 'end')

# ---------- Interfaz gráfica ----------

ventana = Tk()
ventana.title("SecureFile - Cifrado de Archivos (v4)")
ventana.geometry("420x260")
ventana.config(bg="#e6f2ff")

Label(ventana, text="🔐 SecureFile - Protección de Archivos", font=("Arial", 14, "bold"), bg="#e6f2ff", fg="#003366").pack(pady=10)
Label(ventana, text="Contraseña:", bg="#e6f2ff", fg="#003366", font=("Arial", 12)).pack(pady=5)

entrada_password = Entry(ventana, show="*", width=35)
entrada_password.pack()

Button(ventana, text="Cifrar archivo", command=cifrar_archivo, bg="#0066cc", fg="white", width=20).pack(pady=10)
Button(ventana, text="Descifrar archivo", command=descifrar_archivo, bg="#009933", fg="white", width=20).pack(pady=5)

Label(ventana, text="Guarda el archivo cifrado en la misma carpeta de origen", bg="#e6f2ff", fg="#666666", font=("Arial", 9)).pack(pady=10)
Label(ventana, text="Desarrollado por Oscar Cuervo, Andres Nova, David Castiblanco", bg="#e6f2ff", fg="#666666", font=("Arial", 8)).pack(side="bottom", pady=5)

ventana.mainloop()
