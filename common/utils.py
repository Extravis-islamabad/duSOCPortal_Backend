import hashlib
import os
import re
import time

import ldap
from loguru import logger


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
    def get_connection(ldap_server, ldap_port, bind_user, bind_domain, bind_password):
        """
        Establishes and returns a connection to the LDAP server.

        This method initializes an LDAP connection using the provided server
        and binds it using the provided credentials. The connection is set to
        not follow referrals and to use protocol version 3.

        Args:
            ldap_server (str): LDAP server address.
            ldap_port (str/int): LDAP port.
            bind_user (str): LDAP bind user.
            bind_domain (str): LDAP bind domain.
            bind_password (str): LDAP bind password.

        Returns:
            LDAPObject: An LDAP connection object for interacting with the server.
        """
        connect = ldap.initialize(f"ldap://{ldap_server}:{ldap_port}")
        connect.set_option(ldap.OPT_REFERRALS, 0)
        connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        bind_dn = f"{bind_user}@{bind_domain}"
        connect.simple_bind_s(bind_dn, bind_password)
        return connect

    @staticmethod
    def fetch_all_groups(
        base_dn, ldap_server, ldap_port, bind_user, bind_domain, bind_password
    ):
        """
        Fetches all groups from LDAP server.

        Connects to the LDAP server, searches for all groups (objectClass=group),
        and returns a list of group names (cn attribute).

        Args:
            base_dn (str): LDAP base DN for search.
            ldap_server (str): LDAP server address.
            ldap_port (str/int): LDAP port.
            bind_user (str): LDAP bind user.
            bind_domain (str): LDAP bind domain.
            bind_password (str): LDAP bind password.

        :return: List of group names
        """
        connect = LDAP.get_connection(
            ldap_server, ldap_port, bind_user, bind_domain, bind_password
        )
        search_filter = "(objectClass=group)"
        attributes = ["cn"]

        result = connect.search_s(
            base_dn, ldap.SCOPE_SUBTREE, search_filter, attributes
        )
        groups = [attrs["cn"][0].decode() for dn, attrs in result if "cn" in attrs]
        connect.unbind()
        return groups

    @staticmethod
    def fetch_users_in_group(
        group_name,
        base_dn,
        ldap_server,
        ldap_port,
        bind_user,
        bind_domain,
        bind_password,
    ):
        """
        Fetches all users in a given LDAP group.

        Connects to the LDAP server and searches for the specified group by its
        common name (cn). Once the group is found, retrieves all members of the
        group, and for each member, fetches their user details such as username,
        email, and display name.

        Args:
            group_name (str): The common name of the group to search for users.
            base_dn (str): LDAP base DN for search.
            ldap_server (str): LDAP server address.
            ldap_port (str/int): LDAP port.
            bind_user (str): LDAP bind user.
            bind_domain (str): LDAP bind domain.
            bind_password (str): LDAP bind password.

        Returns:
            list: A list of dictionaries containing user details (username, email,
            and name) for each member of the group. Returns an empty list if the
            group is not found or if an error occurs.
        """

        connect = LDAP.get_connection(
            ldap_server, ldap_port, bind_user, bind_domain, bind_password
        )

        # Find group DN first
        group_filter = f"(&(objectClass=group)(cn={group_name}))"
        group_result = connect.search_s(
            base_dn, ldap.SCOPE_SUBTREE, group_filter, ["member"]
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
    def _check_ldap(
        username: str, password: str, base_dn, ldap_server, ldap_port, bind_domain
    ):
        """
        Authenticates a user against the LDAP server.

        This method attempts to connect to the LDAP server using the provided
        username and password. If the user is successfully authenticated, the
        distinguished name (DN) is retrieved, and group memberships are logged.

        Args:
            username (str): The username of the user to authenticate.
            password (str): The password corresponding to the username.
            base_dn (str): LDAP base DN for search.
            ldap_server (str): LDAP server address.
            ldap_port (str/int): LDAP port.
            bind_domain (str): LDAP bind domain.

        Returns:
            bool: True if the user is successfully authenticated; False otherwise.
        """

        try:
            connect = ldap.initialize(f"ldap://{ldap_server}:{ldap_port}")
            connect.set_option(ldap.OPT_REFERRALS, 0)
            connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

            # Bind as the user
            bind_dn = f"{username}@{bind_domain}"
            connect.simple_bind_s(bind_dn, password)

            # Search for the user DN
            search_filter = f"(sAMAccountName={username})"
            result = connect.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ["memberOf", "distinguishedName"],
            )

            if not result:
                connect.unbind()
                logger.error(f"User {username} not found in LDAP directory.")
                return False
            else:
                dn, attributes = result[0]
                logger.info(f"Successfully authenticated: {username}")
                connect.unbind()
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
    def fetch_all_ldap_users(
        base_dn, ldap_server, ldap_port, bind_user, bind_domain, bind_password
    ):
        """
        Fetches all user accounts from the LDAP server.

        Args:
            base_dn (str): LDAP base DN for search.
            ldap_server (str): LDAP server address.
            ldap_port (str/int): LDAP port.
            bind_user (str): LDAP bind user.
            bind_domain (str): LDAP bind domain.
            bind_password (str): LDAP bind password.

        :return: A list of dictionaries with the following keys:
            - username: string
            - name: string
            - email: string
            - dn: string (distinguished name)
        """
        start = time.time()
        logger.info(f"LDAP.fetch_all_ldap_users() started : {start}")

        try:
            connect = ldap.initialize(f"ldap://{ldap_server}:{ldap_port}")
            connect.set_option(ldap.OPT_REFERRALS, 0)
            connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

            bind_dn = f"{bind_user}@{bind_domain}"
            connect.simple_bind_s(bind_dn, bind_password)

            # Search filter to get all user accounts
            search_filter = "(&(objectClass=user)(sAMAccountName=*))"
            attributes = ["sAMAccountName", "distinguishedName", "mail", "displayName"]

            result = connect.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                search_filter,
                attributes,
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

    @staticmethod
    def fetch_user_groups(
        username, base_dn, ldap_server, ldap_port, bind_user, bind_domain, bind_password
    ):
        """
        Fetches all groups that a user belongs to in LDAP.

        Args:
            username (str): The username (sAMAccountName) to get groups for.
            base_dn (str): LDAP base DN for search.
            ldap_server (str): LDAP server address.
            ldap_port (str/int): LDAP port.
            bind_user (str): LDAP bind user.
            bind_domain (str): LDAP bind domain.
            bind_password (str): LDAP bind password.

        Returns:
            list: A list of group names (cn) that the user belongs to.
        """
        try:
            connect = LDAP.get_connection(
                ldap_server, ldap_port, bind_user, bind_domain, bind_password
            )

            # Search for the user's distinguished name and group memberships
            search_filter = f"(sAMAccountName={username})"
            attributes = ["memberOf"]

            result = connect.search_s(
                base_dn, ldap.SCOPE_SUBTREE, search_filter, attributes
            )

            if not result:
                connect.unbind()
                logger.warning(f"User {username} not found in LDAP directory.")
                return []

            _, user_attrs = result[0]
            member_of = user_attrs.get("memberOf", [])

            # Extract group names from DN strings
            group_names = []
            for group_dn in member_of:
                group_dn_str = group_dn.decode()
                # Extract CN from DN (e.g., "CN=GroupName,OU=...") -> "GroupName"
                cn_match = re.search(r"CN=([^,]+)", group_dn_str)
                if cn_match:
                    group_names.append(cn_match.group(1))

            connect.unbind()
            return group_names

        except Exception as e:
            logger.error(f"Error fetching user groups: {str(e)}")
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


def normalize_incident_name(name):
    """
    Normalize incident names for better grouping and comparison.
    This function handles various formatting issues:
    - Removes newlines and excess whitespace
    - Removes leading numbers
    - Removes organization prefixes
    - Normalizes case for comparison

    Args:
        name (str): The incident name to normalize

    Returns:
        str: The normalized incident name
    """
    if not name:
        return ""

    # Remove newlines and normalize whitespace
    cleaned = " ".join(name.replace("\n", " ").split())

    # Remove leading numbers (like "31607 ")
    cleaned = re.sub(r"^\d+\s+", "", cleaned)

    # Remove organization prefixes (like "ADGM-", "AEP-", etc.)
    cleaned = re.sub(r"^[A-Z]{2,}-", "", cleaned)

    # Handle specific patterns for XDR Defender-Alerts
    # Normalize variations like "XDR Defender-Alerts containing X"
    if "XDR Defender-Alerts" in cleaned:
        # Extract the core alert type after "containing"
        match = re.search(r"containing\s+(.+)$", cleaned, re.IGNORECASE)
        if match:
            alert_type = match.group(1).strip()
            cleaned = f"XDR Defender-Alerts containing {alert_type}"
        else:
            cleaned = "XDR Defender-Alerts"

    return cleaned.strip()


def group_similar_incidents(incident_names, similarity_threshold=0.85):
    """
    Group similar incident names based on text similarity.
    Uses a simple approach based on normalized names and keyword matching.

    Args:
        incident_names (list): List of incident name strings
        similarity_threshold (float): Threshold for considering names similar (0-1)

    Returns:
        dict: Dictionary mapping normalized incident names to their occurrence counts
    """
    from collections import Counter
    from difflib import SequenceMatcher

    # First pass: normalize all names
    normalized_counts = Counter()
    name_mappings = {}  # Track original to normalized mappings

    for name in incident_names:
        if not name:
            continue

        normalized = normalize_incident_name(name)
        if not normalized:
            continue

        # Check if this normalized name is similar to any existing group
        best_match = None
        best_score = 0

        for existing_name in normalized_counts.keys():
            # Calculate similarity score
            score = SequenceMatcher(
                None, normalized.lower(), existing_name.lower()
            ).ratio()

            # Special handling for XDR Defender-Alerts patterns
            if (
                "XDR Defender-Alerts" in normalized
                and "XDR Defender-Alerts" in existing_name
            ):
                # If both are XDR Defender-Alerts, check the "containing" part
                normalized_containing = re.search(
                    r"containing\s+(.+)$", normalized, re.IGNORECASE
                )
                existing_containing = re.search(
                    r"containing\s+(.+)$", existing_name, re.IGNORECASE
                )

                if normalized_containing and existing_containing:
                    alert_type_1 = normalized_containing.group(1).lower().strip()
                    alert_type_2 = existing_containing.group(1).lower().strip()

                    # Check if the alert types are similar
                    alert_score = SequenceMatcher(
                        None, alert_type_1, alert_type_2
                    ).ratio()
                    if alert_score > 0.8:  # High similarity in alert type
                        score = 0.95  # Consider them very similar

            if score > best_score and score >= similarity_threshold:
                best_match = existing_name
                best_score = score

        if best_match:
            # Add to existing group
            normalized_counts[best_match] += 1
        else:
            # Create new group
            normalized_counts[normalized] += 1
            name_mappings[normalized] = name

    return normalized_counts
