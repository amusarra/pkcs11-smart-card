# Signature con Smart Card via PKCS#11

Questo progetto è uno script Python che permette di firmare messaggi utilizzando una Smart Card, attraverso l'uso di una
libreria PKCS#11.

## Funzionalità

- Firma di messaggi tramite Smart Card.
- Utilizzo di una libreria PKCS#11 per l'accesso sicuro alla Smart Card.
- Supporto per input parametri, tra cui:
    - PIN della Smart Card.
    - Messaggio da firmare.
    - Opzione `--debug` per abilitare il debug.
    - Opzione `--help` per mostrare l'uso dello script.
    - Opzione `--signature-file` per specificare il file in cui salvare la firma.
    - Opzione `--message-file` per specificare il file in cui salvare il messaggio.
    - Opzione `--pkcs11-lib` per specificare la libreria PKCS#11 da utilizzare.

## Prerequisiti

- Python 3.x
- Libreria PKCS#11 compatibile con il proprio hardware (es. libreria OpenSC).
- Una Smart Card abilitata alla firma.
- Lettore di Smart Card compatibile.

## Installazione

1. Clona il repository:
```bash
git clone https://github.com/amusarra/pkcs11-smart-card.git
```

2. Installa le dipendenze richieste:
```bash
pip install -r requirements.txt
```

## Utilizzo

Esegui lo script passando i parametri richiesti:

```bash
./sign-via-ts-cns.py --pin <PIN> --message "<messaggio>"
```

Opzioni disponibili:

- `--pin`: PIN della Smart Card.
- `--message`: Messaggio da firmare.
- `--debug`: Abilita la modalità di debug.
- `--help`: Mostra l'uso dello script.
- `--signature-file` Specifica il file in cui salvare la firma.
- `--message-file` Specifica il file in cui salvare il messaggio.
- `--pkcs11-lib` Specifica il path completo della libreria PKCS#11 da utilizzare.

## Esempio

```bash
./sign-via-ts-cns.py --pin 123456 --message "Questo è un messaggio da firmare"
```

## Licenza

Questo progetto è distribuito sotto licenza MIT.
