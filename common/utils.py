import hashlib
import os


class PasswordCreation:
    @staticmethod
    def _make_password(raw_password: str, salt: str = None) -> str:
        """
        Generates a hashed password using SHA-256 with an optional salt.

        Args:
            raw_password (str): The plain text password to be hashed.
            salt (str, optional): A hexadecimal string used to salt the password.
                                If not provided, a random 16-byte salt is generated.

        Returns:
            str: The hashed password in the format 'salt$hashed',
                where 'salt' is the hexadecimal representation of the salt
                and 'hashed' is the SHA-256 hash of the salted password.
        """

        if salt is None:
            salt = os.urandom(16).hex()
        salted_password = salt + raw_password
        hashed = hashlib.sha256(salted_password.encode("utf-8")).hexdigest()
        return f"{salt}${hashed}"

    @staticmethod
    def _check_password(raw_password: str, hashed_password: str) -> bool:
        """
        Verifies if a provided raw password matches the hashed password.

        Args:
            raw_password (str): The plain text password to verify.
            hashed_password (str): The hashed password in the format 'salt$hashed'.

        Returns:
            bool: True if the raw password, when hashed, matches the provided hashed password;
                False otherwise or if the hashed password format is incorrect.
        """

        try:
            salt, hashed = hashed_password.split("$")
        except ValueError:
            return False
        check_hashed = hashlib.sha256((salt + raw_password).encode("utf-8")).hexdigest()
        return check_hashed == hashed


class DBMappings:
    @staticmethod
    def get_db_id_to_id_mapping(model_class):
        """
        Returns a dictionary mapping db_id to id for the given model class.
        The model must have 'db_id' and 'id' fields.

        :param model_class: A Django model class
        :return: Dictionary {db_id: id}
        """
        return dict(model_class.objects.values_list("db_id", "id"))
