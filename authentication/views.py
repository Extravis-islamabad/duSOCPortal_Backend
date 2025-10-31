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
    @swagger_auto_schema(
        operation_description="""Creates a new user in the system.

        This endpoint is typically used for creating admin users.
        The password will be hashed before storage.""",
        request_body=UserCreateSerializer,
        responses={
            201: openapi.Response(
                description="User created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "user_id": openapi.Schema(type=openapi.TYPE_INTEGER),
                        "username": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        "message": "User created successfully",
                        "user_id": 1,
                        "username": "john.doe",
                    },
                ),
            ),
            400: openapi.Response(
                description="Bad request - validation errors",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "username": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                        "password": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                    },
                    example={
                        "username": ["This field is required."],
                        "password": ["This field is required."],
                    },
                ),
            ),
        },
        tags=["Authentication"],
    )
    def post(self, request):
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
        operation_description="""Authenticates a user against LDAP (CUSTOMER_AD) and returns JWT tokens.

        The username field accepts either a username or email address.
        Authentication is performed against LDAP, and only active, non-deleted users can login.
        Username matching is case-insensitive.""",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "username": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Username or email address",
                    default="john.doe",
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User password",
                    default="password123",
                ),
            },
            required=["username", "password"],
            example={"username": "john.doe", "password": "password123"},
        ),
        responses={
            200: openapi.Response(
                description="Authentication successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "refresh": openapi.Schema(type=openapi.TYPE_STRING),
                        "access": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                    },
                ),
            ),
            400: openapi.Response(
                description="Bad request - missing credentials or invalid credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Please provide both username and password"},
                ),
            ),
            404: openapi.Response(
                description="User not found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "User does not exist"},
                ),
            ),
            503: openapi.Response(
                description="Service unavailable",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "An error occurred: <error_details>"},
                ),
            ),
        },
        tags=["Authentication"],
    )
    def post(self, request):
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

    @swagger_auto_schema(
        operation_description="""Retrieves the authenticated user's details including permissions and integrated tools.

        Returns user profile information, permissions (for tenant users), and integrated tools (for tenant users).
        For admin users, permissions and integrated_tools arrays will be empty.""",
        responses={
            200: openapi.Response(
                description="User details retrieved successfully",
                schema=UserDetailSerializer,
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided or invalid",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "detail": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={"detail": "Authentication credentials were not provided."},
                ),
            ),
            503: openapi.Response(
                description="Service unavailable",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={"error": "An error occurred: <error_details>"},
                ),
            ),
        },
        tags=["Authentication"],
    )
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
    @swagger_auto_schema(
        operation_description="""Logs out a user by blacklisting the provided refresh token.

        This prevents the refresh token from being used to generate new access tokens.
        Note: The current access token remains valid until it expires.""",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="JWT refresh token to blacklist",
                ),
            },
            required=["refresh"],
        ),
        responses={
            200: openapi.Response(
                description="Successfully logged out",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={"message": "Successfully logged out"},
                ),
            ),
            400: openapi.Response(
                description="Missing refresh token",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={"error": "Please provide a refresh token"},
                ),
            ),
        },
        tags=["Authentication"],
    )
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

    @swagger_auto_schema(
        operation_description="""Updates the company profile picture and/or company name.

        Only admin users can update company profiles.
        To remove the profile picture, send profile_picture as null or empty string.
        At least one of company_name or profile_picture must be provided.""",
        manual_parameters=[
            openapi.Parameter(
                "company_id",
                openapi.IN_PATH,
                description="ID of the company to update",
                type=openapi.TYPE_INTEGER,
                required=True,
            ),
            openapi.Parameter(
                "company_name",
                openapi.IN_FORM,
                description="New company name",
                type=openapi.TYPE_STRING,
                required=False,
            ),
            openapi.Parameter(
                "profile_picture",
                openapi.IN_FORM,
                description="Company profile picture image file (or null to remove)",
                type=openapi.TYPE_FILE,
                required=False,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Company updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "profile_picture": openapi.Schema(
                            type=openapi.TYPE_STRING, nullable=True
                        ),
                    },
                    example={
                        "message": "Company 'ACME Corp' updated successfully.",
                        "profile_picture": "http://example.com/media/companies/profile.jpg",
                    },
                ),
            ),
            400: openapi.Response(
                description="Bad request - missing required fields",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={
                        "error": "At least one of 'company_name' or 'profile_picture' must be provided."
                    },
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided",
            ),
            403: openapi.Response(
                description="User is not an admin",
            ),
            404: openapi.Response(
                description="Company not found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                    example={"error": "Company not found."},
                ),
            ),
        },
        tags=["Company Management"],
    )
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

        has_profile_picture_null = "profile_picture" in request.data and request.data[
            "profile_picture"
        ] in [None, "", "null"]

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
                "profile_picture": request.build_absolute_uri(
                    company.profile_picture.url
                )
                if company.profile_picture
                else None,
            },
            status=status.HTTP_200_OK,
        )


class LDAPUsersAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="""Fetches all users from LDAP directory (CUSTOMER_AD or ADMIN_AD).

        Only admin users can access this endpoint.
        The ad_flag parameter determines which Active Directory to query.""",
        manual_parameters=[
            openapi.Parameter(
                "ad_flag",
                openapi.IN_QUERY,
                description="Active Directory to query. Options: CUSTOMER (default) or ADMIN",
                type=openapi.TYPE_STRING,
                enum=["CUSTOMER", "ADMIN"],
                default="CUSTOMER",
                required=False,
            ),
        ],
        responses={
            200: openapi.Response(
                description="LDAP users retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "data": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "username": openapi.Schema(
                                        type=openapi.TYPE_STRING
                                    ),
                                    "name": openapi.Schema(type=openapi.TYPE_STRING),
                                    "email": openapi.Schema(type=openapi.TYPE_STRING),
                                    "department": openapi.Schema(
                                        type=openapi.TYPE_STRING
                                    ),
                                },
                            ),
                        ),
                    },
                    example={
                        "data": [
                            {
                                "username": "john.doe",
                                "name": "John Doe",
                                "email": "john.doe@example.com",
                                "department": "IT Security",
                            },
                            {
                                "username": "jane.smith",
                                "name": "Jane Smith",
                                "email": "jane.smith@example.com",
                                "department": "Operations",
                            },
                        ]
                    },
                ),
            ),
            400: openapi.Response(
                description="Invalid ad_flag value",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Invalid ad_flag value."},
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided",
            ),
            403: openapi.Response(
                description="User is not an admin",
            ),
            404: openapi.Response(
                description="No users found",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"message": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"message": "No users found"},
                ),
            ),
        },
        tags=["LDAP Management"],
    )
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

    @swagger_auto_schema(
        operation_description="""Fetches all groups from LDAP directory.

        Only admin users can access this endpoint.
        Returns a list of all LDAP group names from the specified Active Directory.""",
        manual_parameters=[
            openapi.Parameter(
                "ad_flag",
                openapi.IN_QUERY,
                description="Active Directory to query. Options: CUSTOMER (default) or ADMIN",
                type=openapi.TYPE_STRING,
                enum=["CUSTOMER", "ADMIN"],
                default="CUSTOMER",
                required=False,
            ),
        ],
        responses={
            200: openapi.Response(
                description="LDAP groups retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "groups": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_STRING),
                        ),
                    },
                    example={
                        "groups": [
                            "CSOC_SOAR_ADMIN",
                            "CSOC_SOAR_SR_SECURITY_ANALYST",
                            "CSOC_SOAR_ANALYST",
                            "Security_Team",
                            "Operations_Team",
                        ]
                    },
                ),
            ),
            400: openapi.Response(
                description="Invalid or missing ad_flag parameter",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Invalid ad_flag value."},
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided",
            ),
            403: openapi.Response(
                description="User is not an admin",
            ),
            500: openapi.Response(
                description="Internal server error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "<error_details>"},
                ),
            ),
        },
        tags=["LDAP Management"],
    )
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

    @swagger_auto_schema(
        operation_description="""Fetches users belonging to a specific LDAP group.

        Only admin users can access this endpoint.
        Returns only users who are NOT already assigned to any tenant.
        This is useful for bulk user assignment to tenants.""",
        manual_parameters=[
            openapi.Parameter(
                "group_name",
                openapi.IN_PATH,
                description="Name of the LDAP group",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                "ad_flag",
                openapi.IN_QUERY,
                description="Active Directory to query. Options: CUSTOMER (default) or ADMIN",
                type=openapi.TYPE_STRING,
                enum=["CUSTOMER", "ADMIN"],
                default="CUSTOMER",
                required=False,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Group users retrieved successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "group": openapi.Schema(type=openapi.TYPE_STRING),
                        "users": openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "username": openapi.Schema(
                                        type=openapi.TYPE_STRING
                                    ),
                                    "name": openapi.Schema(type=openapi.TYPE_STRING),
                                    "email": openapi.Schema(type=openapi.TYPE_STRING),
                                    "department": openapi.Schema(
                                        type=openapi.TYPE_STRING
                                    ),
                                },
                            ),
                        ),
                    },
                    example={
                        "group": "Security_Team",
                        "users": [
                            {
                                "username": "john.doe",
                                "name": "John Doe",
                                "email": "john.doe@example.com",
                                "department": "IT Security",
                            }
                        ],
                    },
                ),
            ),
            400: openapi.Response(
                description="Invalid ad_flag or all users already assigned",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={
                        "error": "All users of this group are already assigned to some tenants."
                    },
                ),
            ),
            401: openapi.Response(
                description="Authentication credentials were not provided",
            ),
            403: openapi.Response(
                description="User is not an admin",
            ),
            500: openapi.Response(
                description="Internal server error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "<error_details>"},
                ),
            ),
        },
        tags=["LDAP Management"],
    )
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
        operation_description="""Authenticates an admin user against ADMIN_AD and creates/updates admin user based on LDAP group membership.

        **Admin Groups & Privilege Levels:**
        - CSOC_SOAR_ADMIN (super_admin) - Highest privilege
        - CSOC_SOAR_SR_SECURITY_ANALYST (admin) - Medium privilege
        - CSOC_SOAR_ANALYST (read_only) - Lowest privilege

        **Group Hierarchy:** SUPER_ADMIN > ADMIN > READ_ONLY

        If a user belongs to multiple admin groups, the highest privilege level is assigned.

        **First-time Login:**
        For first-time admin login, the user is automatically created based on LDAP group membership.

        **Important:** Authentication is always done against LDAP - no passwords are stored in the database.""",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "username": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Admin username from ADMIN_AD",
                    default="admin.user",
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Admin password",
                    default="AdminPassword123",
                ),
            },
            required=["username", "password"],
            example={"username": "admin.user", "password": "AdminPassword123"},
        ),
        responses={
            200: openapi.Response(
                description="Admin authentication successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "refresh": openapi.Schema(
                            type=openapi.TYPE_STRING, description="JWT Refresh Token"
                        ),
                        "access": openapi.Schema(
                            type=openapi.TYPE_STRING, description="JWT Access Token"
                        ),
                    },
                    example={
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTc2MjA2NzYyNywiaWF0IjoxNzYxOTgxMjI3LCJqdGkiOiJhZjA5MTA1OTY1YmM0ZmUzYWIwZDUyNDU4YmY4MzVhNiIsInVzZXJfaWQiOjY5OX0.abc123...",
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzYxOTgxMjI3LCJpYXQiOjE3NjE4OTQ4MjcsImp0aSI6ImFmMDkxMDU5NjViYzRmZTNhYjBkNTI0NThiZjgzNWE2IiwidXNlcl9pZCI6Njk5fQ.def456...",
                    },
                ),
            ),
            400: openapi.Response(
                description="Missing credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Please provide both username and password"},
                ),
            ),
            401: openapi.Response(
                description="Invalid LDAP credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "Invalid LDAP credentials"},
                ),
            ),
            403: openapi.Response(
                description="User not in valid admin groups",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "User is not a member of any valid admin groups"},
                ),
            ),
            500: openapi.Response(
                description="Internal server error",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                    example={"error": "An error occurred: <error_details>"},
                ),
            ),
        },
        tags=["Authentication"],
    )
    def post(self, request):
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
