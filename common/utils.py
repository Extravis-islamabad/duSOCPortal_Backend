import hashlib
import os


class PasswordCreation:
    @staticmethod
    def make_password(raw_password: str, salt: str = None) -> str:
        if salt is None:
            salt = os.urandom(16).hex()  # generate a random 16-byte salt
        salted_password = salt + raw_password
        hashed = hashlib.sha256(salted_password.encode("utf-8")).hexdigest()
        return f"{salt}${hashed}"

    @staticmethod
    def check_password(raw_password: str, hashed_password: str) -> bool:
        try:
            salt, hashed = hashed_password.split("$")
        except ValueError:
            return False  # Incorrect format

        check_hashed = hashlib.sha256((salt + raw_password).encode("utf-8")).hexdigest()
        return check_hashed == hashed
