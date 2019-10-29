#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

PRIMARY_DOMAIN = "http://earnestnessbiophysicalohax.com"
# Número de iteraciones a realizar
ITERATIONS = 39

def plus97_modulus26_minus97(number):
    """
    Replica algunas operaciones realizadas por el DGA a cada caracter.
    Suma 97, realiza el modulo 26 y vuelve a sumar 97
    :param number: entero que representa el carácter en base a la tabla ASCII
    :return: el carácter resultante
    """
    return chr(((number - 97) % 26 ) + 97)

def calc_next_domain(current_domain):
    """
    Calcula el siguiente dominio en la iteración del DGA
    :param current_domain: dominio actual
    :return:
    """
    domain_chars = list(current_domain)
    domain_chars[0] = plus97_modulus26_minus97(ord(domain_chars[0]) + ord(domain_chars[3]))
    domain_chars[1] = plus97_modulus26_minus97(ord(domain_chars[1]) + ord(domain_chars[0]) + ord(domain_chars[1]))
    domain_chars[2] = plus97_modulus26_minus97(ord(domain_chars[2]) + ord(domain_chars[0]) - 1)
    domain_chars[3] = plus97_modulus26_minus97(ord(domain_chars[3]) + ord(domain_chars[1]) + ord(domain_chars[2]))
    return ''.join(domain_chars)

print("Initial Domain: %s" % PRIMARY_DOMAIN)
if PRIMARY_DOMAIN.startswith("http://"):
    domain = PRIMARY_DOMAIN[7:]
else:
    domain = PRIMARY_DOMAIN

for i in range(ITERATIONS):
    domain = calc_next_domain(domain)
    print("Next domain: http://%s" % domain)
    if domain in PRIMARY_DOMAIN:
        print("Iteration %i" % i)
        sys.exit(0)
