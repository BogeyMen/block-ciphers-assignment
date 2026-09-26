import bcrypt
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock
from time import perf_counter

from nltk.corpus import words


@dataclass
class PasswordRecord:
    username: str
    bcrypt_salt: bytes
    bcrypt_hash: bytes
    password: str | None = None
    crack_time: float | None = None


def parse_shadow_file(path: str | Path) -> list[PasswordRecord]:
    records = []

    with Path(path).open(encoding="utf-8") as shadow_file:
        for line in shadow_file:
            line = line.strip()
            if not line:
                continue

            username, bcrypt_value = line.split(":", 1)
            bcrypt_hash = bcrypt_value.encode("ascii")

            records.append(
                PasswordRecord(
                    username=username,
                    bcrypt_salt=bcrypt_hash[:29],
                    bcrypt_hash=bcrypt_hash,
                )
            )

    return records


def crack_passwords(
    records: list[PasswordRecord], work_factor: int
) -> list[PasswordRecord]:
    records_to_crack = [
        record
        for record in records
        if int(record.bcrypt_salt[4:6]) == work_factor
    ]
    if not records_to_crack:
        return records

    bcrypt_salt = records_to_crack[0].bcrypt_salt
    cracked_count = sum(
        record.password is not None for record in records_to_crack
    )
    if cracked_count == len(records_to_crack):
        return records

    valid_guesses = [
        guess
        for guess in words.words()
        if 6 <= len(guess) <= 10 and guess.isalpha()
    ]
    guess_chunks = [valid_guesses[index::16] for index in range(16)]

    guesses_tested = 0
    start_time = perf_counter()
    state_lock = Lock()
    all_cracked = Event()

    def search_chunk(guesses: list[str]) -> None:
        nonlocal cracked_count, guesses_tested

        for guess in guesses:
            if all_cracked.is_set():
                return

            calculated_hash = bcrypt.hashpw(guess.encode(), bcrypt_salt)

            with state_lock:
                guesses_tested += 1

                for record in records_to_crack:
                    if (
                        record.password is None
                        and calculated_hash == record.bcrypt_hash
                    ):
                        record.password = guess
                        record.crack_time = perf_counter() - start_time
                        cracked_count += 1
                        print(f"{record.username}: {guess}")

                if guesses_tested % 1000 == 0:
                    print(
                        f"Tested {guesses_tested:,} words for work factor "
                        f"{work_factor} "
                        f"({cracked_count}/{len(records_to_crack)} cracked)"
                    )

                if cracked_count == len(records_to_crack):
                    all_cracked.set()

    with ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(search_chunk, guess_chunks))

    return records


if __name__ == "__main__":
    shadow_path = Path(__file__).with_name("shadow.txt")
    password_records = parse_shadow_file(shadow_path)
    work_factor = 8
    crack_passwords(password_records, work_factor)

    selected_records = [
        record
        for record in password_records
        if int(record.bcrypt_salt[4:6]) == work_factor
    ]

    for record in selected_records:
        if record.password is None:
            result = "not found"
        else:
            result = f"{record.password} ({record.crack_time:.2f} seconds)"
        print(f"{record.username}: {result}")
