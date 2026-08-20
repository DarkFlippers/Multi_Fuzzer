# Chameleon Ultra Fuzzer — port z Flipper "Multi Fuzzer"

Port kluczowej logiki fuzzingu UID z aplikacji Flipper Zero (to repozytorium)
na **Chameleon Ultra** w Pythonie.

## Pliki

| Plik | Opis |
|------|------|
| `chameleon_ultra_fuzzer.py` | Skrypt fuzzera dla Chameleon Ultra. |
| `flipper_fuzzer_wordlist.txt` | Wordlista UID wyciagnieta z `lib/worker/protocol.c`. |

## Skad wyciagnieto logike

| Zrodlo w repo | Co wyciagnieto |
|---------------|----------------|
| `lib/worker/protocol.c` | Wbudowane slowniki UID (EM4100, 3/4/6/8-bajtowe, iButton). |
| `lib/worker/fake_worker.c` | Strategie: DefaultDict (index++), LoadFile (bajt +1), CustomUids (plik). |
| `lib/worker/protocol_i.h` | Stale timingu (jednostki 10 ms; idle/emu). |

## Strategie (odwzorowane 1:1)

1. **Lista znanych UID** — sekwencyjne przejscie slownika (`FuzzerWorkerAttackTypeDefaultDict`).
2. **Sekwencyjny z maska** — inkrementacja jednego wybranego bajtu `+1`
   (`FuzzerWorkerAttackTypeLoadFile` / `BFCustomerID`).
3. **Wordlista z pliku** — czytanie UID HEX, `#` = komentarz
   (`FuzzerWorkerAttackTypeLoadFileCustomUids`).

## Uzycie

```bash
# menu interaktywne
python3 chameleon_ultra_fuzzer.py

# tryb 1: znane UID, LF EM410x, slot 1
python3 chameleon_ultra_fuzzer.py --mode 1 --tech lf

# tryb 2: sekwencyjny +1 na bajcie 0, HF MIFARE 4B
python3 chameleon_ultra_fuzzer.py --mode 2 --tech hf --base 12345678 --byte 0

# podglad bez sprzetu (tylko logi HEX)
python3 chameleon_ultra_fuzzer.py --mode 1 --tech lf --dry-run
```

Domyslny timing: `--emu-time 0.2` + `--idle-time 0.1` = ~0.3 s na UID
(konfigurowalne), zgodnie z cyklem emu+idle z `fake_worker.c`.

## Ograniczenia / uwagi

- Chameleon Ultra emuluje z protokolow Flippera realnie **EM4100 (LF EM410x)**.
- **ATQA/SAK nie wystepuja** w kodzie Flippera (to protokoly LF/iButton). Dla HF
  MIFARE Classic skrypt dokleja domyslne wartosci 1K (ATQA=`0004`, SAK=`08`).
- iButton (DS1990/Cyfral/Metakom) nie jest obslugiwany przez Chameleon — dane
  zalaczono w wordliscie tylko dla kompletnosci.
- Adapter `ChameleonFuzzer` izoluje wywolania SDK — jesli nazwy metod w Twojej
  wersji SDK sie roznia, popraw wylacznie ten fragment.

> Uzywaj wylacznie na wlasnym sprzecie / w autoryzowanych testach bezpieczenstwa.
