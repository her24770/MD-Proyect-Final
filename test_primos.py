from main import PRIMOS
import random

print("="*60)
print("PRUEBA DE SELECCIÓN ALEATORIA DE PRIMOS")
print("="*60)
print(f"\nLista de primos disponibles ({len(PRIMOS)} primos):")
print(f"Rango: {min(PRIMOS)} - {max(PRIMOS)}")
print(f"Primos: {PRIMOS[:10]}...")

print("\n\nPrueba de 15 selecciones aleatorias:")
print("-"*60)
print(f"{'p':>4} {'q':>4} {'n = p*q':>8} {'Estado':>15}")
print("-"*60)

for i in range(15):
    p, q = random.sample(PRIMOS, 2)
    n = p * q
    estado = "✓ OK (n > 255)" if n > 255 else "✗ FALLO (n <= 255)"
    print(f"{p:4d} {q:4d} {n:8d} {estado:>15}")

print("-"*60)

# Calcular el peor caso (dos primos más pequeños)
primos_ordenados = sorted(PRIMOS)
peor_n = primos_ordenados[0] * primos_ordenados[1]
print(f"\nPeor caso posible: {primos_ordenados[0]} x {primos_ordenados[1]} = {peor_n}")
print(f"¿Peor caso válido? {'✓ SÍ' if peor_n > 255 else '✗ NO'}")
print("="*60)
