# Create your views here.
import time

from django.db.models import Q
from django.db.models.functions import Lower
from django.utils import timezone
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from loguru import logger
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenViewBase

from authentication.permissions import IsAdminUser
from common.constants import LDAPConstants, RBACConstants
from common.utils import LDAP
from tenant.models import Company

from .models import User
from .serializers import (
    CustomTokenRefreshSerializer,
    UserCreateSerializer,
    UserDetailSerializer,
)


class UserCreateAPIView(APIView):
    @swagger_auto_schema(request_body=UserCreateSerializer)
    def post(self, request):
        """
        Creates a new user.

        Accepts POST requests with the following data:

        - username: string
        - email: string
        - name: string
        - password: string
        - is_admin: boolean
        - is_superuser: boolean

        Returns a JSON response with the following data:

        - message: string
        - user_id: integer
        - username: string

        Returns HTTP 201 status code on success, or HTTP 400 status code on failure.
        """
        start = time.time()
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            logger.info(f"UserCreateAPIView.post took {time.time() - start} seconds")
            return Response(
                {
                    "message": "User created successfully",
                    "user_id": user.id,
                    "username": user.username,
                },
                status=status.HTTP_201_CREATED,
            )
        logger.info(f"UserCreateAPIView.post took {time.time() - start} seconds")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginAPIView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "username": openapi.Schema(type=openapi.TYPE_STRING),
                "password": openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=["username", "password"],
        )
    )
    def post(self, request):
        # Extract credentials from request
        """
        Authenticates a user and returns JWT tokens.

        Accepts POST requests with the following data:
        - username: string (can be either username or email)
        - password: string

        Returns a JSON response with the following data on success:
        - refresh: string (refresh token)
        - access: string (access token)

        Returns HTTP 200 status code on successful authentication,
        HTTP 400 for missing credentials,
        HTTP 401 for invalid password,
        HTTP 404 if the user does not exist,
        or HTTP 500 for any other server error.
        """
        start = time.time()
        username = request.data.get("username")
        password = request.data.get("password")
        # /Validate input
        if not username or not password:
            logger.info(f"UserLoginAPIView.post took {time.time() - start} seconds")
            return Response(
                {"error": "Please provide both username and password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        flag = LDAP._check_ldap(
            username,
            password,
            base_dn=LDAPConstants.CUSTOMER_BASE_DN,
            ldap_server=LDAPConstants.CUSTOMER_LDAP_SERVERS[0],
            ldap_port=LDAPConstants.LDAP_PORT,
            bind_domain=LDAPConstants.CUSTOMER_BIND_DOMAIN,
        )
        if not flag:
            return Response(
                {"error": "Invalid password or username"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.filter(
                Q(username__iexact=username) | Q(email__iexact=username),
                is_active=True,
                is_deleted=False,
            ).first()
            if user is None:
                return Response(
                    {"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND
                )
            if user.is_admin:
                if not user.check_password(password):
                    logger.info(
                        f"UserLoginAPIView.post took {time.time() - start} seconds"
                    )
                    return Response(
                        {"error": "Invalid password or username"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])
            refresh = RefreshToken.for_user(user)
            logger.info(f"UserLoginAPIView.post took {time.time() - start} seconds")
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"An error occurred UserLoginAPIView.post: {str(e)}")
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class UserDetailsAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    # @swagger_auto_schema(
    #     request_body=UserDetailSerializer
    # )
    def get(self, request):
        """
        Retrieves the user details.

        Returns a JSON response with the following data on success:
        - message: string
        - user: object (User details)

        Returns HTTP 200 status code on success, or HTTP 500 for any other server error.
        """
        start = time.time()
        try:
            user = request.user
            serializer = UserDetailSerializer(user, context={"request": request})
            logger.info(f"UserDetailsAPIView.get took {time.time() - start} seconds")
            return Response(
                {
                    "user": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"An error occurred UserDetailsAPIView.get: {str(e)}")
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class UserLogoutAPIView(APIView):
    """
    Logs out a user by blacklisting the provided refresh token.

    Accepts POST requests with the following data:
    - refresh: string (refresh token)

    Returns a JSON response with the following data on success:
    - message: string ("Successfully logged out")

    Returns HTTP 200 status code on successful logout,
    HTTP 400 for missing or invalid refresh token,
    or HTTP 500 for any other server error.
    """

    def post(self, request):
        start = time.time()
        refresh_token = request.data.get("refresh")

        # Validate input
        if not refresh_token:
            logger.info(f"UserLogoutAPIView.post took {time.time() - start} seconds")
            return Response(
                {"error": "Please provide a refresh token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            logger.info(f"UserLogoutAPIView.post took {time.time() - start} seconds")
            return Response(
                {"message": "Successfully logged out"},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"An error occurred in UserLogoutAPIView.post: {str(e)}")
            return Response(
                {"message": "Successfully logged out"},
                status=status.HTTP_200_OK,
            )


class CompanyProfilePictureUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    parser_classes = (MultiPartParser, FormParser)
    
    def patch(self, request, company_id):
        try:
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response(
                {"error": "Company not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        
        company_name = request.data.get("company_name")
        profile_picture = request.FILES.get("profile_picture")
        
        has_profile_picture_null = 'profile_picture' in request.data and request.data['profile_picture'] in [None, '', 'null']
        
        if not company_name and not profile_picture and not has_profile_picture_null:
            return Response(
                {
                    "error": "At least one of 'company_name' or 'profile_picture' must be provided."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        if company_name:
            company.company_name = company_name
        
        if profile_picture:
            company.profile_picture = profile_picture
        elif has_profile_picture_null:
            company.profile_picture = None
        
        company.save()
        
        return Response(
            {
                "message": f"Company '{company.company_name}' updated successfully.",
                "profile_picture": request.build_absolute_uri(company.profile_picture.url) if company.profile_picture else None,
            },
            status=status.HTTP_200_OK,
        )

class LDAPUsersAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Get ad_flag query parameter and validate it's provided
        ad_flag = request.query_params.get("ad_flag", "CUSTOMER")

        if not ad_flag:
            return Response(
                {"error": "Required ad_flag parameter is missing"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Convert to uppercase for comparison
        ad_flag = ad_flag.upper()

        # Determine which LDAP configuration to use
        if ad_flag == "CUSTOMER":
            base_dn = LDAPConstants.CUSTOMER_BASE_DN
            ldap_servers = LDAPConstants.CUSTOMER_LDAP_SERVERS
            bind_domain = LDAPConstants.CUSTOMER_BIND_DOMAIN
        elif ad_flag == "ADMIN":
            base_dn = LDAPConstants.ADMIN_BASE_DN
            ldap_servers = LDAPConstants.ADMIN_LDAP_SERVERS
            bind_domain = LDAPConstants.ADMIN_BIND_DOMAIN
        else:
            return Response(
                {"error": "Invalid ad_flag value."}, status=status.HTTP_400_BAD_REQUEST
            )

        # base_dn = LDAPConstants.CUSTOMER_BASE_DN
        # ldap_servers = LDAPConstants.CUSTOMER_LDAP_SERVERS
        # bind_domain = LDAPConstants.CUSTOMER_BIND_DOMAIN

        data = LDAP.fetch_all_ldap_users(
            base_dn=base_dn,
            ldap_server=ldap_servers[0],
            ldap_port=LDAPConstants.LDAP_PORT,
            bind_user=LDAPConstants.LDAP_BIND_USER,
            bind_domain=bind_domain,
            bind_password=LDAPConstants.LDAP_BIND_PASSWORD,
        )

        if not data:
            return Response(
                {"message": "No users found"}, status=status.HTTP_404_NOT_FOUND
            )
        return Response({"data": data}, status=status.HTTP_200_OK)


class LDAPGroupListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            # Get ad_flag query parameter and validate it's provided
            ad_flag = request.query_params.get("ad_flag", "CUSTOMER")

            if not ad_flag:
                return Response(
                    {"error": "Required ad_flag parameter is missing"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Convert to uppercase for comparison
            ad_flag = ad_flag.upper()

            # Determine which LDAP configuration to use based on ad_flag
            if ad_flag == "CUSTOMER":
                base_dn = LDAPConstants.CUSTOMER_BASE_DN
                ldap_servers = LDAPConstants.CUSTOMER_LDAP_SERVERS
                bind_domain = LDAPConstants.CUSTOMER_BIND_DOMAIN
            elif ad_flag == "ADMIN":
                base_dn = LDAPConstants.ADMIN_BASE_DN
                ldap_servers = LDAPConstants.ADMIN_LDAP_SERVERS
                bind_domain = LDAPConstants.ADMIN_BIND_DOMAIN
            else:
                return Response(
                    {"error": "Invalid ad_flag value."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # base_dn = LDAPConstants.CUSTOMER_BASE_DN
            # ldap_servers = LDAPConstants.CUSTOMER_LDAP_SERVERS
            # bind_domain = LDAPConstants.CUSTOMER_BIND_DOMAIN
            groups = LDAP.fetch_all_groups(
                base_dn=base_dn,
                ldap_server=ldap_servers[0],
                ldap_port=LDAPConstants.LDAP_PORT,
                bind_user=LDAPConstants.LDAP_BIND_USER,
                bind_domain=bind_domain,
                bind_password=LDAPConstants.LDAP_BIND_PASSWORD,
            )

            return Response({"groups": groups}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LDAPGroupUsersView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, group_name):
        try:
            # Get ad_flag query parameter and validate it's provided
            ad_flag = request.query_params.get("ad_flag", "CUSTOMER")

            if not ad_flag:
                return Response(
                    {"error": "Required ad_flag parameter is missing"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Convert to uppercase for comparison
            ad_flag = ad_flag.upper()

            # Determine which LDAP configuration to use based on ad_flag
            if ad_flag == "CUSTOMER":
                base_dn = LDAPConstants.CUSTOMER_BASE_DN
                ldap_servers = LDAPConstants.CUSTOMER_LDAP_SERVERS
                bind_domain = LDAPConstants.CUSTOMER_BIND_DOMAIN
            elif ad_flag == "ADMIN":
                base_dn = LDAPConstants.ADMIN_BASE_DN
                ldap_servers = LDAPConstants.ADMIN_LDAP_SERVERS
                bind_domain = LDAPConstants.ADMIN_BIND_DOMAIN
            else:
                return Response(
                    {"error": "Invalid ad_flag value"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # base_dn = LDAPConstants.CUSTOMER_BASE_DN
            # ldap_servers = LDAPConstants.CUSTOMER_LDAP_SERVERS
            # bind_domain = LDAPConstants.CUSTOMER_BIND_DOMAIN
            ldap_users = LDAP.fetch_users_in_group(
                group_name=group_name,
                base_dn=base_dn,
                ldap_server=ldap_servers[0],
                ldap_port=LDAPConstants.LDAP_PORT,
                bind_user=LDAPConstants.LDAP_BIND_USER,
                bind_domain=bind_domain,
                bind_password=LDAPConstants.LDAP_BIND_PASSWORD,
            )

            ldap_usernames = {user["username"].lower() for user in ldap_users}
            existing_usernames = set(
                User.objects.annotate(lower_username=Lower("username"))
                .filter(lower_username__in=ldap_usernames)
                .values_list("lower_username", flat=True)
            )
            new_users = [
                user
                for user in ldap_users
                if user["username"].lower() not in existing_usernames
            ]
            if not new_users:
                return Response(
                    {
                        "error": "All users of this group are already assigned to some tenants."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return Response(
                {"group": group_name, "users": new_users}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminLoginAPIView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "username": openapi.Schema(type=openapi.TYPE_STRING),
                "password": openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=["username", "password"],
        )
    )
    def post(self, request):
        """
        Authenticates an admin user against ADMIN_AD and creates/updates admin user based on LDAP group membership.

        The Admin login will use the ADMIN_AD. Users who can access and login to the portal will come under these groups:
        - CSOC_SOAR_ADMIN (super_admin) - Highest privilege
        - CSOC_SOAR_SR_SECURITY_ANALYST (admin) - Medium privilege
        - CSOC_SOAR_ANALYST (read_only) - Lowest privilege

        If a user exists in more than one mentioned group, they will be assigned the highest privilege level.
        Group hierarchy: SUPER_ADMIN > ADMIN > READ_ONLY

        For first-time admin login, username and password will be taken, checked against LDAP,
        group membership evaluated, and user will be created with highest available privilege.

        Authentication is always done against LDAP - no passwords are stored in DB.

        Args:
            username (str): Admin username
            password (str): Admin password

        Returns:
            JSON response with JWT tokens on success or error message on failure.
        """
        start = time.time()
        username = request.data.get("username")
        password = request.data.get("password")

        # Validate input
        if not username or not password:
            logger.info(f"AdminLoginAPIView.post took {time.time() - start} seconds")
            return Response(
                {"error": "Please provide both username and password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Always authenticate against ADMIN_AD first
            ldap_auth_success = LDAP._check_ldap(
                username,
                password,
                base_dn=LDAPConstants.ADMIN_BASE_DN,
                ldap_server=LDAPConstants.ADMIN_LDAP_SERVERS[0],
                ldap_port=LDAPConstants.LDAP_PORT,
                bind_domain=LDAPConstants.ADMIN_BIND_DOMAIN,
            )

            if not ldap_auth_success:
                return Response(
                    {"error": "Invalid LDAP credentials"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Check if user exists in database
            existing_user = User.objects.filter(
                username__iexact=username, is_active=True, is_deleted=False
            ).first()

            # If user doesn't exist, this is first-time login - create user
            if not existing_user:
                # Get user's LDAP groups
                user_groups = LDAP.fetch_user_groups(
                    username=username,
                    base_dn=LDAPConstants.ADMIN_BASE_DN,
                    ldap_server=LDAPConstants.ADMIN_LDAP_SERVERS[0],
                    ldap_port=LDAPConstants.LDAP_PORT,
                    bind_user=LDAPConstants.LDAP_BIND_USER,
                    bind_domain=LDAPConstants.ADMIN_BIND_DOMAIN,
                    bind_password=LDAPConstants.LDAP_BIND_PASSWORD,
                )

                # Check for valid admin groups
                valid_groups = [
                    RBACConstants.SUPER_ADMIN_GROUP,
                    RBACConstants.ADMIN_GROUP,
                    RBACConstants.READ_ONLY_USER_GROUP,
                ]

                user_valid_groups = [
                    group for group in user_groups if group in valid_groups
                ]

                # Check if user is in at least one valid group
                if not user_valid_groups:
                    return Response(
                        {"error": "User is not a member of any valid admin groups"},
                        status=status.HTTP_403_FORBIDDEN,
                    )

                # If user belongs to multiple groups, assign highest privileges
                # Group hierarchy: SUPER_ADMIN > ADMIN > READ_ONLY
                is_super_admin = False
                is_admin = False
                is_read_only = False
                assigned_role = None

                # Check for highest privilege first (Super Admin)
                if RBACConstants.SUPER_ADMIN_GROUP in user_valid_groups:
                    is_super_admin = True
                    assigned_role = RBACConstants.SUPER_ADMIN_GROUP
                # Then check for Admin privilege
                elif RBACConstants.ADMIN_GROUP in user_valid_groups:
                    is_admin = True
                    assigned_role = RBACConstants.ADMIN_GROUP
                # Finally assign Read Only if that's the only role
                elif RBACConstants.READ_ONLY_USER_GROUP in user_valid_groups:
                    is_read_only = True
                    assigned_role = RBACConstants.READ_ONLY_USER_GROUP

                # Create new admin user without storing password
                user = User.objects.create(
                    username=username,
                    name=username,  # You might want to get display name from LDAP
                    is_super_admin=is_super_admin,
                    is_admin=is_admin,
                    is_read_only=is_read_only,
                    is_active=True,
                    is_deleted=False,
                    # No password stored - authentication is always done via LDAP
                )

                logger.info(
                    f"Created new admin user: {username} with role: {assigned_role}"
                )

            else:
                # User exists, LDAP authentication already succeeded above
                # No need to check stored password as we rely entirely on LDAP
                user = existing_user

            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            logger.info(f"AdminLoginAPIView.post took {time.time() - start} seconds")
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"An error occurred in AdminLoginAPIView.post: {str(e)}")
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CustomTokenRefreshView(TokenViewBase):
    serializer_class = CustomTokenRefreshSerializer
