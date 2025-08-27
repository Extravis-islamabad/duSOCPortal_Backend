import hashlib
import os
import re
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

    @staticmethod
    def get_name_to_id_mapping(model_class):
        """
        Returns a dictionary mapping 'name' to 'id' for the given model class.
        The model must have 'name' and 'id' fields.

        :param model_class: A Django model class
        :return: Dictionary {name: id}
        """
        return dict(
            model_class.objects.filter(name__isnull=False)
            .exclude(name__exact="")
            .values_list("name", "id")
        )


class LDAP:
    @staticmethod
    def get_connection():
        """
        Establishes and returns a connection to the LDAP server.

        This method initializes an LDAP connection using the first server
        from the list of LDAP servers and binds it using the configured
        bind user credentials. The connection is set to not follow referrals
        and to use protocol version 3.

        Returns:
            LDAPObject: An LDAP connection object for interacting with the server.
        """

        connect = ldap.initialize(
            f"ldap://{LDAPConstants.LDAP_SERVERS[0]}:{LDAPConstants.LDAP_PORT}"
        )
        connect.set_option(ldap.OPT_REFERRALS, 0)
        connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        bind_dn = f"{LDAPConstants.LDAP_BIND_USER}@{LDAPConstants.BIND_DOMAIN}"
        connect.simple_bind_s(bind_dn, LDAPConstants.LDAP_BIND_PASSWORD)
        return connect

    @staticmethod
    def fetch_all_groups():
        """
        Fetches all groups from LDAP server.

        Connects to the LDAP server, searches for all groups (objectClass=group),
        and returns a list of group names (cn attribute).

        :return: List of group names
        """
        connect = LDAP.get_connection()
        search_filter = "(objectClass=group)"
        attributes = ["cn"]
        result = connect.search_s(
            LDAPConstants.BASE_DN, ldap.SCOPE_SUBTREE, search_filter, attributes
        )
        groups = [attrs["cn"][0].decode() for dn, attrs in result if "cn" in attrs]
        connect.unbind()
        return groups

    @staticmethod
    def fetch_users_in_group(group_name):
        """
        Fetches all users in a given LDAP group.

        Connects to the LDAP server and searches for the specified group by its
        common name (cn). Once the group is found, retrieves all members of the
        group, and for each member, fetches their user details such as username,
        email, and display name.

        Args:
            group_name (str): The common name of the group to search for users.

        Returns:
            list: A list of dictionaries containing user details (username, email,
            and name) for each member of the group. Returns an empty list if the
            group is not found or if an error occurs.
        """

        connect = LDAP.get_connection()
        # Find group DN first
        group_filter = f"(&(objectClass=group)(cn={group_name}))"
        group_result = connect.search_s(
            LDAPConstants.BASE_DN, ldap.SCOPE_SUBTREE, group_filter, ["member"]
        )
        if not group_result:
            return []

        _, group_attrs = group_result[0]
        members = group_attrs.get("member", [])
        users = []

        for member_dn in members:
            try:
                user_result = connect.search_s(
                    member_dn.decode(),
                    ldap.SCOPE_BASE,
                    "(objectClass=person)",
                    ["sAMAccountName", "mail", "displayName"],
                )
                if user_result:
                    _, user_attrs = user_result[0]
                    users.append(
                        {
                            "username": user_attrs.get("sAMAccountName", [b""])[
                                0
                            ].decode(),
                            "email": user_attrs.get("mail", [b""])[0].decode(),
                            "name": user_attrs.get("displayName", [b""])[0].decode(),
                        }
                    )
            except Exception as e:
                logger.error(
                    f"LDAP.fetch_users_in_group(): Error fetching user details: {e}"
                )
                return []
        connect.unbind()
        return users

    @staticmethod
    def _check_ldap(username: str, password: str):
        """
        Authenticates a user against the LDAP server.

        This method attempts to connect to the LDAP server using the provided
        username and password. If the user is successfully authenticated, the
        distinguished name (DN) is retrieved, and group memberships are logged.

        Args:
            username (str): The username of the user to authenticate.
            password (str): The password corresponding to the username.

        Returns:
            bool: True if the user is successfully authenticated; False otherwise.
        """

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
        """
        Fetches all user accounts from the LDAP server.

        :return: A list of dictionaries with the following keys:
            - username: string
            - name: string
            - email: string
            - dn: string (distinguished name)
        """
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
                    {
                        "username": username,
                        "name": display_name,
                        "email": email,
                        "dn": dn,
                    }
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


class DateTimeStorage:
    """
    Utility class for storing and managing datetime values.
    Provides static methods to store, retrieve, and manipulate datetime values
    using the DateTimeStorage model.
    """

    @staticmethod
    def store_current_time():
        """
        Store or update the current datetime.

        Returns:
            DateTimeStorage: The created or updated instance

        Example:
            >>> DateTimeStorage.store_current_time()
            <DateTimeStorage: DateTime: 2024-01-15 14:30:25+00:00>
        """
        from tenant.models import DateTimeStorage as DTStorage

        return DTStorage.store_datetime()

    @staticmethod
    def store_specific_time(datetime_value):
        """
        Store or update a specific datetime.

        Args:
            datetime_value (datetime): The datetime to store

        Returns:
            DateTimeStorage: The created or updated instance

        Example:
            >>> from datetime import datetime
            >>> from django.utils import timezone
            >>> dt = timezone.make_aware(datetime(2024, 1, 15, 14, 30, 0))
            >>> DateTimeStorage.store_specific_time(dt)
            <DateTimeStorage: DateTime: 2024-01-15 14:30:00+00:00>
        """
        from tenant.models import DateTimeStorage as DTStorage

        return DTStorage.store_datetime(datetime_value)

    @staticmethod
    def get_stored_time():
        """
        Get the currently stored datetime.

        Returns:
            datetime or None: The stored datetime or None if nothing is stored

        Example:
            >>> DateTimeStorage.get_stored_time()
            datetime.datetime(2024, 1, 15, 14, 30, 25, tzinfo=<UTC>)
        """
        from tenant.models import DateTimeStorage as DTStorage

        return DTStorage.get_stored_datetime()

    @staticmethod
    def update_time():
        """
        Update the stored datetime to the current time.
        This is an alias for store_current_time() for better readability.

        Returns:
            DateTimeStorage: The updated instance

        Example:
            >>> DateTimeStorage.update_time()
            <DateTimeStorage: DateTime: 2024-01-15 14:35:45+00:00>
        """
        return DateTimeStorage.store_current_time()

    @staticmethod
    def has_stored_time():
        """
        Check if any datetime is currently stored.

        Returns:
            bool: True if a datetime is stored, False otherwise

        Example:
            >>> DateTimeStorage.has_stored_time()
            True
        """
        from tenant.models import DateTimeStorage as DTStorage

        return DTStorage.has_stored_datetime()

    @staticmethod
    def get_time_since_stored():
        """
        Get the time difference between now and the stored datetime.

        Returns:
            timedelta or None: The time difference or None if no datetime is stored

        Example:
            >>> DateTimeStorage.get_time_since_stored()
            datetime.timedelta(seconds=125)
        """
        from django.utils import timezone

        stored_time = DateTimeStorage.get_stored_time()
        if stored_time:
            return timezone.now() - stored_time
        return None


def extract_use_case(name):
    # Remove leading numbers and optional org code like "ADGM-"
    cleaned = re.sub(r"^\d+\s+", "", name)  # remove leading numeric ID and spaces
    cleaned = re.sub(r"^[A-Z]+-", "", cleaned)  # remove leading org code and dash
    return cleaned.strip()
