#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chameleon_ultra_fuzzer.py
=========================================================================
Port strategii fuzzingu UID z aplikacji "Multi Fuzzer" dla Flipper Zero
na Chameleon Ultra (Python).

Logika i bazy danych wyciagniete z repozytorium Flippera:
    - lib/worker/protocol.c        -> wbudowane slowniki UID (dict)
    - lib/worker/fake_worker.c     -> strategie fuzzingu (petla, timing)
    - lib/worker/protocol_i.h      -> stale timingu (jednostki 10 ms)

Odwzorowane 1:1 strategie z Flippera:
    * DefaultDict  (FuzzerWorkerAttackTypeDefaultDict)
         -> sekwencyjne przejscie wbudowanej listy UID (index++)
    * BF / LoadFile (FuzzerWorkerAttackTypeLoadFile)
         -> modyfikacja JEDNEGO wybranego bajtu, sekwencyjnie +1 (0x00..0xFF)
    * LoadFileCustomUids
         -> wczytanie UID-ow z pliku wordlisty (linie '#' = komentarz)

Timing z Flippera (fake_worker.c / on_tick_callback):
    cykl na jeden UID = faza emulacji (pole ON) + faza idle (pole OFF).
    Domyslnie w tym skrypcie ~0.3 s na UID (zgodnie z prosba).

WAZNE - roznice sprzetowe:
    - Aplikacja Flippera obsluguje iButton (Dallas) + RFID 125 kHz (LF).
    - Chameleon Ultra realnie emuluje z tych: EM4100 (LF EM410x).
    - Dla HF MIFARE Classic UID (4 bajty) w kodzie Flippera NIE MA ATQA/SAK,
      wiec tutaj doklejane sa domyslne wartosci MIFARE 1K (ATQA=0004, SAK=08).
    - iButton (DS1990/Cyfral/Metakom) nie jest emulowany przez Chameleon.

Uzycie:
    python3 chameleon_ultra_fuzzer.py                 # tryb interaktywny (menu)
    python3 chameleon_ultra_fuzzer.py --mode 1 --tech lf
    python3 chameleon_ultra_fuzzer.py --mode 2 --tech hf --base 12345678 --byte 0
    python3 chameleon_ultra_fuzzer.py --dry-run       # bez sprzetu, tylko logi
=========================================================================
"""

import argparse
import os
import sys
import time

# Oficjalne Python SDK Chameleon Ultra.
# Import zgodnie z zyczeniem uzytkownika; jesli w zainstalowanej wersji SDK
# klasa nazywa sie inaczej, patrz adapter ChameleonFuzzer ponizej.
try:
    from chameleonultra import ChameleonUltra
except Exception:  # pragma: no cover - pozwala uruchomic --dry-run bez SDK
    ChameleonUltra = None


# =========================================================================
# 1. BAZY DANYCH WYCIAGNIETE Z FLIPPERA (lib/worker/protocol.c)
# =========================================================================
# Kazda lista to zestaw UID jako bytes. Nazwy odpowiadaja tablicom w protocol.c.

# uid_list_5byte -> EM4100 (LF EM410x na Chameleon)
UID_LIST_EM4100 = [
    bytes.fromhex(h) for h in [
        "0000000000", "FFFFFFFFFF",
        "1111111111", "2222222222", "3333333333", "4444444444",
        "5555555555", "6666666666", "7777777777", "8888888888",
        "9999999999",
        "123456789A",  # Incremental UID
        "9A78563412",  # Decremental UID
        "04D09B0D6A", "3400293D9E", "04DF000001", "CACACACACA",
    ]
]

# uid_list_4byte -> UID 4-bajtowy (HF MIFARE Classic 4B)
UID_LIST_4BYTE = [
    bytes.fromhex(h) for h in [
        "00000000", "FFFFFFFF",
        "11111111", "22222222", "33333333", "44444444",
        "55555555", "66666666", "77777777", "88888888",
        "99999999",
        "12345678",  # Incremental UID
        "9A785634",  # Decremental UID
        "04D09B0D", "3400293D", "04DF0000", "CACACACA",
    ]
]

# Domyslne wartosci HF MIFARE Classic 1K (NIE pochodza z Flippera - patrz naglowek)
DEFAULT_ATQA = bytes.fromhex("0004")  # little-endian tak jak zwykle w SDK
DEFAULT_SAK = 0x08


# =========================================================================
# 2. STRATEGIE GENEROWANIA UID (port z fake_worker.c)
# =========================================================================

def strat_known_uids(uid_list):
    """DefaultDict: sekwencyjnie po wbudowanym slowniku (Flipper: index++)."""
    for uid in uid_list:
        yield uid


def strat_sequential_mask(base_uid, byte_index):
    """
    LoadFile / BFCustomerID (FuzzerWorkerAttackTypeLoadFile):
    modyfikuj TYLKO jeden bajt, inkrementujac go +1 od jego wartosci do 0xFF.

    Odwzorowanie fake_worker.c:
        if(payload[index] != 0xFF) { payload[index]++; }
    Tutaj przechodzimy pelny zakres wybranego bajtu (0x00..0xFF) na maske UID.
    """
    base = bytearray(base_uid)
    if not (0 <= byte_index < len(base)):
        raise ValueError("byte_index poza zakresem UID")
    start = base[byte_index]
    for val in range(start, 0x100):
        base[byte_index] = val
        yield bytes(base)


def strat_from_wordlist(path, data_size=None):
    """
    LoadFileCustomUids: czytaj UID-y z pliku HEX.
    Zasady jak w fuzzer_worker.c:
        - linia zaczynajaca sie od '#' -> komentarz (pomijana),
        - dlugosc musi pasowac do rozmiaru danych (jesli data_size podany),
        - parsowanie HEX.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                uid = bytes.fromhex(line)
            except ValueError:
                continue
            if data_size is not None and len(uid) != data_size:
                continue
            yield uid


# =========================================================================
# 3. ADAPTER SPRZETOWY CHAMELEON ULTRA
# =========================================================================
# Warstwa oddzielajaca strategie od konkretnego API SDK. Nazwy metod SDK
# roznia sie miedzy wersjami - jesli import/metoda sie nie zgadza, popraw
# wylacznie ten adapter, reszta skryptu pozostaje bez zmian.

class ChameleonFuzzer:
    ACTIVE_SLOT = 1  # modyfikacja wartosci w slocie 1 (zgodnie z prosba)

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.dev = None
        if self.dry_run:
            print("[i] Tryb DRY-RUN: brak komunikacji ze sprzetem, tylko logi.")
            return
        if ChameleonUltra is None:
            print("[!] Nie znaleziono SDK 'chameleonultra'. Uruchom z --dry-run "
                  "albo zainstaluj/popraw import.")
            sys.exit(1)
        self.dev = ChameleonUltra()
        self.dev.connect()
        # Ustaw aktywny slot 1
        self._set_active_slot(self.ACTIVE_SLOT)
        print(f"[i] Polaczono z Chameleon Ultra. Aktywny slot: {self.ACTIVE_SLOT}")

    # --- niskopoziomowe operacje (dostosuj do zainstalowanego SDK) ----------
    def _set_active_slot(self, slot):
        if self.dry_run:
            return
        # Slot numerowany od 1 w UI, wiele wersji SDK liczy od 0.
        try:
            self.dev.set_active_slot(slot - 1)
        except AttributeError:
            # alternatywne nazwy spotykane w roznych buildach SDK
            self.dev.set_slot(slot - 1)

    def program_lf_em410x(self, uid5):
        """Wgraj 5-bajtowy UID EM410x do aktywnego slotu (LF)."""
        if self.dry_run:
            return
        # Typowe API: ustawienie ID EM410x w aktywnym slocie.
        self.dev.set_em410x_emulator_id(uid5)

    def program_hf_mifare(self, uid, atqa=DEFAULT_ATQA, sak=DEFAULT_SAK):
        """Wgraj UID MIFARE Classic (4/7 B) + ATQA/SAK do aktywnego slotu (HF)."""
        if self.dry_run:
            return
        # Ustawienie danych antykolizji (UID/ATQA/SAK) dla emulacji MIFARE.
        self.dev.mf1_set_anti_coll_data(uid=uid, atqa=atqa, sak=bytes([sak]))

    def emulate_pulse(self, emu_time_s, idle_time_s):
        """
        Odwzorowanie cyklu z fake_worker.c: pole ON przez emu_time,
        potem OFF przez idle_time. Chameleon emuluje ciagle po zaprogramowaniu
        slotu, wiec 'pole ON' realizujemy jako odczekanie emu_time, a 'idle'
        jako krotka pauza przed nastepnym UID.
        """
        time.sleep(emu_time_s)
        # (opcjonalnie: mozna tu wywolac stop/start emulacji jesli SDK wspiera)
        time.sleep(idle_time_s)

    def close(self):
        if self.dry_run or self.dev is None:
            return
        try:
            self.dev.disconnect()
        except Exception:
            pass


# =========================================================================
# 4. GLOWNA PETLA FUZZINGU
# =========================================================================

def run_fuzz(fuzzer, tech, uid_iter, emu_time_s, idle_time_s):
    """
    tech: 'lf' (EM410x) lub 'hf' (MIFARE Classic).
    uid_iter: generator UID-ow (jedna ze strategii).
    Odwzorowuje petle Flippera z czytelnymi logami HEX.
    """
    count = 0
    try:
        for uid in uid_iter:
            hex_uid = uid.hex().upper()
            count += 1
            if tech == "lf":
                fuzzer.program_lf_em410x(uid)
                print(f"[{count:04d}] LF EM410x  UID = {hex_uid}")
            else:
                fuzzer.program_hf_mifare(uid)
                print(f"[{count:04d}] HF MIFARE  UID = {hex_uid}  "
                      f"ATQA={DEFAULT_ATQA.hex().upper()} SAK={DEFAULT_SAK:02X}")
            fuzzer.emulate_pulse(emu_time_s, idle_time_s)
    except KeyboardInterrupt:
        print("\n[i] Przerwano przez uzytkownika (Ctrl+C).")
    print(f"[i] Zakonczono. Przetestowano {count} UID-ow.")


# =========================================================================
# 5. MENU / CLI
# =========================================================================

def choose_uid_iter(mode, tech, args):
    """Zbuduj generator UID w zaleznosci od trybu."""
    data_size = 5 if tech == "lf" else 4
    base_list = UID_LIST_EM4100 if tech == "lf" else UID_LIST_4BYTE

    if mode == 1:
        # Tryb 1: znane UID z listy (wbudowanej lub z pliku wordlisty)
        if args.wordlist:
            print(f"[i] Tryb 1: wordlista z pliku {args.wordlist}")
            return strat_from_wordlist(args.wordlist, data_size)
        print("[i] Tryb 1: wbudowana lista znanych UID (z Flippera).")
        return strat_known_uids(base_list)

    # Tryb 2: fuzzing sekwencyjny z maska (jeden bajt +1)
    base_hex = args.base or ("123456789A" if tech == "lf" else "12345678")
    base_uid = bytes.fromhex(base_hex)
    if len(base_uid) != data_size:
        print(f"[!] Bazowy UID musi miec {data_size} bajtow dla tech={tech}.")
        sys.exit(1)
    print(f"[i] Tryb 2: sekwencyjny +1 na bajcie #{args.byte}, baza {base_hex.upper()}")
    return strat_sequential_mask(base_uid, args.byte)


def interactive_menu(args):
    print("=" * 60)
    print(" Chameleon Ultra Fuzzer - port strategii z Flipper Multi Fuzzer")
    print("=" * 60)
    if not args.tech:
        t = input("Technologia [1=LF EM410x, 2=HF MIFARE] (domyslnie 1): ").strip()
        args.tech = "hf" if t == "2" else "lf"
    if not args.mode:
        print("Tryb pracy:")
        print("  1: Wykorzystanie wyciagnietej listy znanych UID")
        print("  2: Fuzzing sekwencyjny z maska (jeden bajt +1)")
        m = input("Wybierz tryb [1/2] (domyslnie 1): ").strip()
        args.mode = 2 if m == "2" else 1
    if args.mode == 2 and args.byte is None:
        b = input("Ktory bajt modyfikowac (index od 0, domyslnie 0): ").strip()
        args.byte = int(b) if b else 0
    return args


def main():
    parser = argparse.ArgumentParser(
        description="Fuzzer UID dla Chameleon Ultra (port z Flipper Multi Fuzzer).")
    parser.add_argument("--mode", type=int, choices=[1, 2],
                        help="1=lista znanych UID, 2=sekwencyjny z maska")
    parser.add_argument("--tech", choices=["lf", "hf"],
                        help="lf=EM410x (5B), hf=MIFARE Classic (4B)")
    parser.add_argument("--base", help="Bazowy UID w HEX dla trybu 2")
    parser.add_argument("--byte", type=int, default=None,
                        help="Index bajtu do inkrementacji (tryb 2)")
    parser.add_argument("--wordlist",
                        help="Sciezka do pliku wordlisty (tryb 1). "
                             "Domyslnie dolaczony flipper_fuzzer_wordlist.txt")
    parser.add_argument("--emu-time", type=float, default=0.2,
                        help="Czas emulacji (pole ON) na UID w sek. (domyslnie 0.2)")
    parser.add_argument("--idle-time", type=float, default=0.1,
                        help="Czas idle (pole OFF) na UID w sek. (domyslnie 0.1)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Bez sprzetu - tylko wypisuj logi UID.")
    args = parser.parse_args()

    # Tryb interaktywny gdy brak kluczowych argumentow
    if args.mode is None or args.tech is None:
        args = interactive_menu(args)
    if args.byte is None:
        args.byte = 0

    # Cykl ~0.3 s na UID (emu 0.2 + idle 0.1), zgodnie z prosba - konfigurowalny.
    print(f"[i] Timing: emu={args.emu_time}s + idle={args.idle_time}s "
          f"(cykl ~{args.emu_time + args.idle_time:.2f}s / UID)")

    uid_iter = choose_uid_iter(args.mode, args.tech, args)

    fuzzer = ChameleonFuzzer(dry_run=args.dry_run)
    try:
        run_fuzz(fuzzer, args.tech, uid_iter, args.emu_time, args.idle_time)
    finally:
        fuzzer.close()


if __name__ == "__main__":
    main()
