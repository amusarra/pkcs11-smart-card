#!/usr/bin/env python3

"""
Script per firmare un messaggio usando una Smart Card.

Questo script utilizza una libreria PKCS#11 per accedere alla Smart Card e firmare un messaggio.
Può essere eseguito come eseguibile e accetta parametri in input, come il PIN e il messaggio da firmare.
È previsto un parametro --debug per visualizzare i messaggi utili per eventuali debug e un parametro --help per visualizzare la modalità di uso dello script.

Autore: Antonio Musarra <antonio.musarra[at]gmail.com>

Parametri:
    --pin: PIN della Smart Card (obbligatorio)
    --message: Messaggio da firmare (obbligatorio)
    --debug: Abilita i messaggi di debug (opzionale)
    --signature-file: File in cui salvare la firma (opzionale)
    --message-file: File in cui salvare il messaggio (opzionale)
    --pkcs11-lib: Percorso della libreria PKCS#11 (opzionale)
    --help: Visualizza la modalità di uso dello script (opzionale)

Eccezioni:
    PKCS11LibraryNotFound: Sollevata quando la libreria PKCS#11 non viene trovata.
    NoSmartCardInserted: Sollevata quando nessuna Smart Card è inserita.

Esempio di utilizzo:
    ./sign-via-ts-cns.py --pin 12345 --message "Messaggio da firmare e verificare" --signature-file firma.bin --message-file messaggio.txt --pkcs11-lib /path/to/lib --debug
"""

import os
import argparse
import PyKCS11
import binascii
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from colorama import Fore, Style, init

# Inizializza colorama per la colorazione del testo nel terminale
init(autoreset=True)

# Definizione delle eccezioni personalizzate
class PKCS11LibraryNotFound(Exception):
    pass

class NoSmartCardInserted(Exception):
    pass

def main():
    # Configura l'argparse per gestire i parametri di input
    parser = argparse.ArgumentParser(description='Script per firmare un messaggio usando una Smart Card')
    parser.add_argument('--pin', required=True, help='PIN della Smart Card')
    parser.add_argument('--message', required=True, help='Messaggio da firmare')
    parser.add_argument('--debug', action='store_true', help='Abilita i messaggi di debug')
    parser.add_argument('--signature-file', help='File in cui salvare la firma')
    parser.add_argument('--message-file', help='File in cui salvare il messaggio')
    parser.add_argument('--pkcs11-lib', help='Percorso della libreria PKCS#11')
    args = parser.parse_args()

    # Percorso della libreria PKCS#11
    pkcs11_lib_path = args.pkcs11_lib if args.pkcs11_lib else '/opt/homebrew/Cellar/opensc/0.25.1/lib/opensc-pkcs11.so'
    if not os.path.exists(pkcs11_lib_path):
        raise PKCS11LibraryNotFound(
            f"Libreria PKCS#11 non trovata. Specifica il percorso manualmente. Percorso attuale: {pkcs11_lib_path}")

    # Carica la libreria PKCS#11
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)

    # Ottieni la lista degli slot con token presenti
    slots = pkcs11.getSlotList(tokenPresent=True)
    if args.debug:
        print(f"{Fore.YELLOW}🔍 Slot disponibili: {slots}")

    if len(slots) == 0:
        raise NoSmartCardInserted("Nessuna Smart Card inserita")

    # Usa il primo slot disponibile
    slot = slots[0]
    if args.debug:
        print(f"{Fore.YELLOW}🔍 Usando lo slot: {slot}")

    # Apri una sessione con la Smart Card
    session = pkcs11.openSession(slot)
    session.login(args.pin)
    if args.debug:
        print(f"{Fore.GREEN}✅ Login effettuato con successo")

    # Trova la chiave privata sulla Smart Card
    private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0]
    if args.debug:
        private_key_info = session.getAttributeValue(private_key, [PyKCS11.CKA_KEY_TYPE, PyKCS11.CKA_MODULUS_BITS])
        print(f"{Fore.YELLOW}🔍 Chiave privata trovata: {private_key}")
        print(f"{Fore.YELLOW}🔍 Lunghezza chiave privata: {private_key_info[1]} bit")

    # Trova il certificato pubblico sulla Smart Card
    public_cert = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])[0]
    if args.debug:
        print(f"{Fore.YELLOW}🔍 Certificato pubblico trovato: {public_cert}")

    # Ottieni il certificato pubblico in formato DER
    public_cert_der = session.getAttributeValue(public_cert, [PyKCS11.CKA_VALUE], False)[0]
    public_cert_der = bytes(public_cert_der)
    if args.debug:
        print(f"{Fore.YELLOW}🔍 Certificato pubblico (DER): {binascii.hexlify(public_cert_der)}")

    # Carica il certificato pubblico
    cert = x509.load_der_x509_certificate(public_cert_der, backend=default_backend())
    if args.debug:
        print(f"{Fore.YELLOW}🔍 Subject: {cert.subject}")
        print(f"{Fore.YELLOW}🔍 Issuer: {cert.issuer}")

    # Salva il certificato pubblico in formato PEM
    with open("public_cert.pem", "wb") as pem_file:
        pem_file.write(cert.public_bytes(Encoding.PEM))
    if args.debug:
        print(f"{Fore.GREEN}✅ Certificato pubblico salvato in formato PEM su 'public_cert.pem'")

    # Ottieni la chiave pubblica dal certificato
    public_key = cert.public_key()
    if args.debug:
        print(f"{Fore.YELLOW}🔍 Chiave pubblica caricata correttamente (DER)")
        print(f"{Fore.YELLOW}🔍 Lunghezza chiave pubblica: {public_key.key_size} bit")
        print(f"{Fore.YELLOW}🔍 Tipo chiave pubblica: {public_key.__class__.__name__}")

    # Codifica il messaggio da firmare
    data = args.message.encode()
    print(f"{Fore.YELLOW}🔍 Dati da firmare: {data}")

    # Firma il messaggio usando la chiave privata
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
    signature = session.sign(private_key, data, mechanism)
    signature = bytes(signature)
    print(f"{Fore.GREEN}✅ Firma generata (in esadecimale): {binascii.hexlify(signature)}")

    # Salva la firma su file, generando un nome casuale se non specificato
    if args.signature_file:
        signature_file = args.signature_file
    else:
        signature_file = f"signature_{uuid.uuid4().hex}.bin"
    with open(signature_file, "wb") as sig_file:
        sig_file.write(signature)
    if args.debug:
        print(f"{Fore.GREEN}✅ Firma salvata su file: {signature_file}")

    # Salva il messaggio su file, generando un nome casuale se non specificato
    if args.message_file:
        message_file = args.message_file
    else:
        message_file = f"message_{uuid.uuid4().hex}.txt"
    with open(message_file, "wb") as msg_file:
        msg_file.write(data)
    if args.debug:
        print(f"{Fore.GREEN}✅ Messaggio salvato su file: {message_file}")

    # Verifica la firma usando la chiave pubblica
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"{Fore.GREEN}✅ Firma verificata correttamente!")
    except Exception as e:
        print(f"{Fore.RED}❌ Verifica della firma fallita: {e}")

    # Logout dalla sessione
    session.logout()
    if args.debug:
        print(f"{Fore.GREEN}✅ Logout effettuato")

if __name__ == "__main__":
    main()