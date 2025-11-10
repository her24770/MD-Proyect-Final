"""
Sistema RSA - Encriptación con Teoría de Números
Implementa conceptos de los capítulos 4.1 y 4.3
"""

import random
import os

# Lista de números primos (suficientemente grandes para que n > 255)
# Para garantizar n > 255, necesitamos p*q > 255, por lo tanto usamos primos >= 17
PRIMOS = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
          101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179]


# Algoritmo de Euclides para calcular MCD
def mcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Algoritmo Extendido de Euclides para encontrar el inverso modular
def mcd_extendido(a, b):
    if b == 0:
        return a, 1, 0
    mcd_val, x1, y1 = mcd_extendido(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return mcd_val, x, y


# Calcula d tal que: e * d ≡ 1 (mod phi_n)
def inverso_modular(e, phi_n):
    mcd_val, x, y = mcd_extendido(e, phi_n)
    if mcd_val != 1:
        return None
    return x % phi_n


# Test de primalidad por división
def es_primo(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


# Exponenciación modular: (base^exp) mod m
# Usa la propiedad: (a * b) mod m = [(a mod m) * (b mod m)] mod m
def exp_modular(base, exp, mod):
    resultado = 1
    base = base % mod
    
    while exp > 0:
        if exp % 2 == 1:
            resultado = (resultado * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    
    return resultado


# Genera las claves RSA a partir de dos primos p y q
def generar_claves(p, q):
    # Verificar que ambos sean primos
    if not es_primo(p):
        print(f"Error: {p} no es un numero primo")
        return None
    
    if not es_primo(q):
        print(f"Error: {q} no es un numero primo")
        return None
    
    if p == q:
        print("Error: p y q deben ser diferentes")
        return None
    
    # Calculo de n (modulo)
    n = p * q
    
    # n debe ser mayor a 255 para poder encriptar caracteres extendidos ASCII/UTF-8
    if n < 256:
        print(f"Error: n = {n} es muy pequeno (necesita ser > 255)")
        return None
    
    # Calculo de la funcion de Euler: φ(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Seleccionar e tal que 1 < e < φ(n) y MCD(e, φ(n)) = 1
    # Valores comunes: 3, 17, 65537
    e = 65537
    if e >= phi_n:
        e = 17
    if e >= phi_n:
        e = 3
    
    # Verificar que MCD(e, φ(n)) = 1
    while mcd(e, phi_n) != 1:
        e += 2
        if e >= phi_n:
            print("Error: No se pudo encontrar un exponente valido")
            return None
    
    # Calcular d usando el Algoritmo Extendido de Euclides
    # d es el inverso modular de e: e * d ≡ 1 (mod φ(n))
    d = inverso_modular(e, phi_n)
    
    if d is None:
        print("Error: No se pudo calcular la clave privada")
        return None
    
    print("\n" + "="*50)
    print("CLAVES GENERADAS")
    print("="*50)
    print(f"n = {p} x {q} = {n}")
    print(f"φ(n) = ({p}-1) x ({q}-1) = {phi_n}")
    print(f"e = {e}")
    print(f"{e} x {d} ≡ 1 (mod {phi_n})")
    print(f"d = {d}")
    print()
    print(f"Clave PUBLICA:  (e={e}, n={n})")
    print(f"Clave PRIVADA:  (d={d}, n={n})")
    print("="*50)
    print("\nNOTA: Anote estas claves, el programa NO las guardara")


# Encripta un mensaje usando la clave publica ingresada por el usuario
def encriptar(mensaje, archivo):
    try:
        entrada = input("\nIngrese la clave publica (e n): ").strip().split()
        if len(entrada) != 2:
            print("Error: Debe ingresar exactamente dos valores (e y n)")
            return None
        e = int(entrada[0])
        n = int(entrada[1])
        
        # Validaciones de clave
        if e <= 1 or n <= 1:
            print("Error: Los valores e y n deben ser mayores a 1")
            return None
        if n < 256:
            print(f"Error: n = {n} es muy pequeno (necesita ser > 255 para caracteres)")
            return None
            
    except (ValueError, IndexError):
        print("Error: Formato invalido. Use: e n (ejemplo: 17 3233)")
        return None
    
    # Convertir cada caracter a su codigo (0-255)
    # Usamos encode para convertir a bytes y manejar cualquier caracter UTF-8
    try:
        codigos = [b for b in mensaje.encode('latin-1')]
    except UnicodeEncodeError:
        # Si hay caracteres que no se pueden codificar en latin-1, usar UTF-8
        print("Advertencia: El texto contiene caracteres especiales que pueden requerir n mas grande")
        codigos = [ord(c) for c in mensaje]
    
    # Verificar que todos los caracteres puedan ser cifrados
    max_codigo = max(codigos) if codigos else 0
    if max_codigo >= n:
        print(f"Error: Caracter con codigo {max_codigo} no puede cifrarse con n={n}")
        print(f"Necesita un valor de n mayor a {max_codigo}")
        return None
    
    # Aplicar la formula: c = m^e mod n
    cifrados = []
    for m in codigos:
        c = exp_modular(m, e, n)
        cifrados.append(c)
    
    # Crear carpeta encriptado si no existe
    os.makedirs("encriptado", exist_ok=True)
    
    nuevoArchivo = f"encriptado/{archivo}.enc"
    try:
        with open(nuevoArchivo, "w", encoding="utf-8") as output:
            output.write(",".join(map(str, cifrados)))
    except Exception as e:
        print(f"Error al escribir el archivo: {e}")
        return None

    print("\n" + "="*50)
    print("MENSAJE ENCRIPTADO")
    print("="*50)
    print(f"Usando clave publica: (e={e}, n={n})")
    print(f"Mensaje: {mensaje[:50]}{'...' if len(mensaje) > 50 else ''}")
    print(f"Mensaje cifrado en el archivo: {nuevoArchivo}")
    print("="*50)
    print(f"\n*** IMPORTANTE: Para descifrar use (d=?, n={n}) ***")
    print(f"*** El valor de n DEBE ser exactamente {n} ***\n")
    
    return cifrados


# Desencripta un mensaje cifrado usando la clave privada ingresada por el usuario
def desencriptar(cifrados_texto, archivo):
    try:
        entrada = input("\nIngrese la clave privada (d n): ").strip().split()
        if len(entrada) != 2:
            print("Error: Debe ingresar exactamente dos valores (d y n)")
            return None
        d = int(entrada[0])
        n = int(entrada[1])
        
        # Validaciones de clave
        if d <= 1 or n <= 1:
            print("Error: Los valores d y n deben ser mayores a 1")
            return None
            
    except (ValueError, IndexError):
        print("Error: Formato invalido. Use: d n (ejemplo: 2753 3233)")
        return None
    
    try:
        cifrados = [int(x) for x in cifrados_texto.strip().split(",") if x]
        if not cifrados:
            print("Error: El archivo no contiene datos cifrados validos")
            return None
    except ValueError:
        print("Error: Archivo .enc con formato invalido")
        return None
    
    # Aplicar la formula: m = c^d mod n
    descifrados = []
    try:
        for c in cifrados:
            m = exp_modular(c, d, n)
            descifrados.append(m)
    except Exception as e:
        print(f"Error durante el descifrado: {e}")
        return None
    
    # Convertir codigos a caracteres usando bytes
    try:
        # Intentar decodificar como latin-1 primero (más común para 0-255)
        mensaje = bytes(descifrados).decode('latin-1')
    except (ValueError, UnicodeDecodeError):
        # Si falla, intentar como caracteres Unicode directos
        try:
            mensaje = ''.join([chr(m) for m in descifrados])
        except ValueError as e:
            print(f"Error: No se pudo convertir los valores a caracteres: {e}")
            return None
    
    # Crear carpeta desencriptado si no existe
    os.makedirs("desencriptado", exist_ok=True)
    
    nuevoArchivo = f"desencriptado/{archivo}.txt"
    try:
        with open(nuevoArchivo, "w", encoding="utf-8") as output:
            output.write(mensaje)
    except Exception as e:
        print(f"Error al escribir el archivo: {e}")
        return None
    
    print("\n" + "="*50)
    print("MENSAJE DESENCRIPTADO")
    print("="*50)
    print(f"Usando clave privada: (d={d}, n={n})")
    print(f"Mensaje desencriptado en: {nuevoArchivo}")
    print(f"Primeros caracteres: {mensaje[:50]}{'...' if len(mensaje) > 50 else ''}")
    print("="*50)
    
    return mensaje


def menu():
    while True:
        print("\n" + "="*50)
        print("SISTEMA RSA - ENCRIPTACION")
        print("="*50)
        print("\n1. Generar claves (ingresar p, q)")
        print("2. Encriptar archivo")
        print("3. Desencriptar archivo")
        print("4. Salir")
        print("="*50)
        
        opcion = input("\nSeleccione una opcion: ").strip()
        
        if opcion == "1":
            print("\n" + "-"*50)
            print("1. Ingresar dos numeros primos manualmente")
            print("2. Elegir de la lista de primos disponibles")
            print("-"*50)
            
            sub_opcion = input("Seleccione metodo: ").strip()
            
            if sub_opcion == "1":
                try:
                    entrada = input("\nIngrese dos numeros primos (p q): ").strip().split()
                    p = int(entrada[0])
                    q = int(entrada[1])
                    
                    generar_claves(p, q)
                    
                except (ValueError, IndexError):
                    print("Error: Formato invalido. Use: p q (ejemplo: 61 53)")
            
            elif sub_opcion == "2":
                # Elegir dos primos diferentes al azar
                # Intentar varias veces hasta obtener un n suficientemente grande
                max_intentos = 10
                for intento in range(max_intentos):
                    primos_seleccionados = random.sample(PRIMOS, 2)
                    p = primos_seleccionados[0]
                    q = primos_seleccionados[1]
                    n = p * q
                    
                    # Verificar que n sea suficientemente grande
                    if n > 255:
                        print(f"\nPrimos elegidos al azar: p={p}, q={q}")
                        print(f"Calculando n = {p} x {q} = {n}")
                        generar_claves(p, q)
                        break
                else:
                    print("Error: No se pudo generar claves con n > 255. Intente con primos mas grandes.")
            
            else:
                print("Opcion no valida")
        
        elif opcion == "2":
            ruta = input("\nIngrese el nombre del archivo a encriptar sin .txt (Ej. texto): ").strip()
            
            if not ruta:
                print("Error: El nombre del archivo no puede estar vacio")
                continue
            
            # Leer desde la carpeta desencriptado
            path_entrada = f"desencriptado/{ruta}.txt"
            
            # Verificar que el archivo exista
            if not os.path.exists(path_entrada):
                print(f"Error: Archivo no encontrado: {path_entrada}")
                print(f"Asegurese de que el archivo este en la carpeta 'desencriptado/'")
                continue
            
            # Leer el archivo
            try:
                with open(path_entrada, "r", encoding="utf-8") as archivo:
                    data = archivo.read()
                
                # Eliminar BOM (Byte Order Mark) si existe
                # El BOM UTF-8 es el caracter U+FEFF (código 65279)
                if data and data[0] == '\ufeff':
                    data = data[1:]
                    print("Nota: Se eliminó el BOM del archivo")
                    
            except Exception as e:
                print(f"Error al leer el archivo: {e}")
                continue
            
            # Validar que el archivo no este vacio
            if not data:
                print("Error: El archivo esta vacio")
                continue
            
            encriptar(data, ruta)
        
        elif opcion == "3":
            entrada = input("\nIngrese el nombre del archivo con el texto cifrado sin .enc (Ej. texto): ").strip()
            
            if not entrada:
                print("Error: El nombre del archivo no puede estar vacio")
                continue
            
            path_enc = f"encriptado/{entrada}.enc"
            
            # Verificar que el archivo exista
            if not os.path.exists(path_enc):
                print(f"Error: Archivo no encontrado: {path_enc}")
                print(f"Asegurese de que el archivo este en la carpeta 'encriptado/'")
                continue
            
            # Leer el archivo
            try:
                with open(path_enc, "r", encoding="utf-8") as archivo:
                    data = archivo.read()
            except Exception as e:
                print(f"Error al leer el archivo: {e}")
                continue
            
            # Validar que el archivo no este vacio
            if not data:
                print("Error: El archivo esta vacio")
                continue
            
            desencriptar(data, entrada)
        
        elif opcion == "4":
            print("\nPrograma finalizado")
            break
        
        else:
            print("Opcion no valida")


if __name__ == "__main__":
    menu()