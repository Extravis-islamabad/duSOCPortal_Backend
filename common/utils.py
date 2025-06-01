import hashlib
import os
import time

import ldap
from loguru import logger

from common.constants import LDAPConstants


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


class LDAP:
    @staticmethod
    def _check_ldap(username: str, password: str):
        try:
            connect = ldap.initialize(
                f"ldap://{LDAPConstants.LDAP_SERVERS[0]}:{LDAPConstants.LDAP_PORT}"
            )
            connect.set_option(ldap.OPT_REFERRALS, 0)
            connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

            # Bind as the user
            bind_dn = f"{username}@{LDAPConstants.BIND_DOMAIN}"
            connect.simple_bind_s(bind_dn, password)

            # Search for the user DN
            search_filter = f"(sAMAccountName={username})"
            result = connect.search_s(
                LDAPConstants.BASE_DN,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ["memberOf", "distinguishedName"],
            )

            if not result:
                logger.error(f"User {username} not found in LDAP directory.")
                return False
            else:
                dn, attributes = result[0]
                logger.info(f"Successfully authenticated: {username}")
                return True
                print(f"Distinguished Name: {dn}")

                groups = attributes.get("memberOf", [])
                if groups:
                    print(f"Groups for {username}:")
                    for group in groups:
                        print(f"  - {group.decode()}")
                else:
                    print(f"No group memberships found for {username}")

            connect.unbind()

        except Exception as e:
            logger.error(f"The exception LDAP occurred: {str(e)}")
            return False

    @staticmethod
    def fetch_all_ldap_users():
        start = time.time()
        logger.info(f"LDAP.fetch_all_ldap_users() started : {start}")
        try:
            connect = ldap.initialize(
                f"ldap://{LDAPConstants.LDAP_SERVERS[0]}:{LDAPConstants.LDAP_PORT}"
            )
            connect.set_option(ldap.OPT_REFERRALS, 0)
            connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

            bind_dn = f"{LDAPConstants.LDAP_BIND_USER}@{LDAPConstants.BIND_DOMAIN}"
            connect.simple_bind_s(bind_dn, LDAPConstants.LDAP_BIND_PASSWORD)

            # Search filter to get all user accounts
            search_filter = "(&(objectClass=user)(sAMAccountName=*))"
            attributes = ["sAMAccountName", "distinguishedName", "mail", "displayName"]

            result = connect.search_s(
                LDAPConstants.BASE_DN, ldap.SCOPE_SUBTREE, search_filter, attributes
            )
            result_list = []
            for dn, attrs in result:
                username = attrs.get("sAMAccountName", [b"N/A"])[0].decode()
                display_name = attrs.get("displayName", [b"N/A"])[0].decode()
                email = attrs.get("mail", [b"N/A"])[0].decode()
                result_list.append(
                    {"user": username, "name": display_name, "email": email, "dn": dn}
                )
            connect.unbind()
            logger.info(
                f"LDAP.fetch_all_ldap_users() took: {time.time() - start} seconds"
            )
            return result_list
        except Exception as e:
            logger.exception(
                f"An error occurred in LDAP.fetch_all_ldap_users(): {str(e)}"
            )
            return []
