"""
Calcular las claves correctas para n=17363
"""
from main import inverso_modular, es_primo

# n = 17363, necesitamos encontrar p y q
n = 17363

print("="*60)
print("ENCONTRAR FACTORES PRIMOS DE n=17363")
print("="*60)

# Factorizar n (probando divisores primos)
def factorizar(n):
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            p = i
            q = n // i
            if es_primo(p) and es_primo(q):
                return p, q
    return None, None

p, q = factorizar(n)

if p and q:
    print(f"\n✓ Factorización encontrada:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = {p} × {q} = {p*q}")
    
    phi_n = (p - 1) * (q - 1)
    print(f"  φ(n) = ({p}-1) × ({q}-1) = {phi_n}")
    
    # Calcular d para e=17
    e = 17
    d = inverso_modular(e, phi_n)
    
    print(f"\n✓ Claves RSA:")
    print(f"  Clave PÚBLICA:  (e={e}, n={n})")
    print(f"  Clave PRIVADA:  (d={d}, n={n})")
    
    # Verificar
    verificacion = (e * d) % phi_n
    print(f"\n✓ Verificación: ({e} × {d}) mod {phi_n} = {verificacion}")
    
    if verificacion == 1:
        print("  ✓ Las claves son correctas")
        
        print("\n" + "="*60)
        print("PARA DESCIFRAR EL ARCHIVO, USA:")
        print("="*60)
        print(f"  Clave privada: {d} {n}")
        print("="*60)
    else:
        print("  ✗ ERROR: Las claves no son válidas")
else:
    print(f"\n✗ No se pudo factorizar n={n}")
