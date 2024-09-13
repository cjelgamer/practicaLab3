import hashlib
import os
import customtkinter as ctk
from tkinter import messagebox

# Funcion para generar hash de una contrasena con una sal
def generar_hash_contrasena(contrasena):
    sal = os.urandom(16)
    hash_contrasena = hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), sal, 100000)
    return sal + hash_contrasena

# Funcion para verificar si la contrasena ingresada coincide con el hash almacenado
def verificar_contrasena(contrasena, hash_almacenado):
    sal = hash_almacenado[:16]
    hash_original = hash_almacenado[16:]
    hash_contrasena = hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), sal, 100000)
    return hash_contrasena == hash_original

# Clase para implementar una tabla hash en memoria
class TablaHashContrasenas:
    def __init__(self, tamano=100):
        self.tamano = tamano
        self.tabla = [[] for _ in range(tamano)]

    def _hash(self, clave):
        return hash(clave) % self.tamano

    # Inserta un nuevo usuario y el hash de su contrasena en la tabla hash
    def insertar(self, usuario, contrasena):
        hash_contrasena = generar_hash_contrasena(contrasena)
        indice = self._hash(usuario)
        for item in self.tabla[indice]:
            if item[0] == usuario:
                # Si el usuario ya existe, actualiza el hash
                item[1] = hash_contrasena
                return
        # Si el usuario no existe, anade una nueva entrada
        self.tabla[indice].append((usuario, hash_contrasena))

    # Busca y verifica el hash de la contrasena para un usuario especifico
    def buscar(self, usuario, contrasena):
        indice = self._hash(usuario)
        for item in self.tabla[indice]:
            if item[0] == usuario:
                hash_almacenado = item[1]
                return verificar_contrasena(contrasena, hash_almacenado)
        return False

# Interfaz grafica con customtkinter
class InterfazApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Almacenamiento Seguro de Contrasenas")
        self.root.geometry("500x400")  # Ampliado para mostrar los datos

        # Configuracion del tema y apariencia
        ctk.set_appearance_mode("dark")  # Modo oscuro
        ctk.set_default_color_theme("blue")  # Color de tema

        self.tabla_hash = TablaHashContrasenas()
        self.mostrar_contrasena = False  # Estado para alternar la visibilidad de la contrasena

        # Etiqueta para el titulo
        self.label_titulo = ctk.CTkLabel(root, text="Gestion de Contrasenas", font=("Arial", 18))
        self.label_titulo.pack(pady=10)

        # Etiqueta y campo de entrada para el nombre de usuario
        self.label_usuario = ctk.CTkLabel(root, text="Usuario:")
        self.label_usuario.pack(pady=5)
        self.entrada_usuario = ctk.CTkEntry(root, placeholder_text="Ingrese su usuario", width=250)
        self.entrada_usuario.pack(pady=5)

        # Etiqueta y campo de entrada para la contrasena
        self.label_contrasena = ctk.CTkLabel(root, text="Contrasena:")
        self.label_contrasena.pack(pady=5)
        self.entrada_contrasena = ctk.CTkEntry(root, show="*", placeholder_text="Ingrese su contrasena", width=250)
        self.entrada_contrasena.pack(pady=5)

        # Boton para mostrar u ocultar la contrasena
        self.boton_mostrar_contrasena = ctk.CTkButton(root, text="Mostrar", command=self.alternar_contrasena, width=120)
        self.boton_mostrar_contrasena.pack(pady=5)

        # Boton para registrar
        self.boton_registrar = ctk.CTkButton(root, text="Registrar", command=self.registrar_usuario, width=120)
        self.boton_registrar.pack(pady=10)

        # Boton para verificar
        self.boton_verificar = ctk.CTkButton(root, text="Verificar", command=self.verificar_usuario, width=120)
        self.boton_verificar.pack(pady=10)

        # Etiqueta para mostrar los datos ingresados
        self.label_datos = ctk.CTkLabel(root, text="Datos Ingresados:", font=("Arial", 14))
        self.label_datos.pack(pady=10)

        # Area de texto para mostrar los datos ingresados
        self.texto_datos = ctk.CTkTextbox(root, width=450, height=150, wrap='word', state='disabled')
        self.texto_datos.pack(pady=10)

    # Funcion para alternar la visibilidad de la contrasena
    def alternar_contrasena(self):
        if self.mostrar_contrasena:
            self.entrada_contrasena.configure(show="*")
            self.boton_mostrar_contrasena.configure(text="Mostrar")
        else:
            self.entrada_contrasena.configure(show="")
            self.boton_mostrar_contrasena.configure(text="Ocultar")
        self.mostrar_contrasena = not self.mostrar_contrasena

    # Funcion para registrar el usuario y la contrasena
    def registrar_usuario(self):
        usuario = self.entrada_usuario.get()
        contrasena = self.entrada_contrasena.get()

        if usuario and contrasena:
            self.tabla_hash.insertar(usuario, contrasena)
            messagebox.showinfo("Registro Exitoso", f"Usuario '{usuario}' registrado correctamente.")
            self.mostrar_datos(usuario, "Contrasena almacenada de forma segura (hash encriptado)", "Registrado")
        else:
            messagebox.showwarning("Campos Vacios", "Por favor, ingrese ambos campos.")

    # Funcion para verificar si la contrasena ingresada es correcta
    def verificar_usuario(self):
        usuario = self.entrada_usuario.get()
        contrasena = self.entrada_contrasena.get()

        if usuario and contrasena:
            if self.tabla_hash.buscar(usuario, contrasena):
                messagebox.showinfo("Verificacion Exitosa", "Contrasena correcta.")
                self.mostrar_datos(usuario, "Contrasena correcta", "Verificado")
            else:
                messagebox.showerror("Error", "Contrasena incorrecta o usuario no registrado.")
        else:
            messagebox.showwarning("Campos Vacios", "Por favor, ingrese ambos campos.")

    # Funcion para mostrar los datos ingresados en el area de texto
    def mostrar_datos(self, usuario, contrasena_mensaje, estado):
        self.texto_datos.configure(state='normal')  # Habilitar el area de texto
        self.texto_datos.delete(1.0, 'end')  # Limpiar el area de texto
        datos = f"Usuario: {usuario}\n{contrasena_mensaje}\nEstado: {estado}\n"
        self.texto_datos.insert('end', datos)  # Insertar los datos
        self.texto_datos.configure(state='disabled')  # Deshabilitar el area de texto

# Inicializar la interfaz grafica
if __name__ == "__main__":
    root = ctk.CTk()
    app = InterfazApp(root)
    root.mainloop()
