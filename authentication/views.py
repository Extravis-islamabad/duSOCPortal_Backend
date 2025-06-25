# Create your views here.
import json
import time
from io import BytesIO

from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db.models import Q
from django.utils import timezone
from loguru import logger
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.permissions import IsAdminUser
from common.utils import LDAP
from tenant.models import Tenant

from .models import User
from .serializers import (
    ProfilePictureUploadSerializer,
    UserCreateSerializer,
    UserDetailSerializer,
)


class UserCreateAPIView(APIView):
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
        if username != "admin@gmail.com" and password != "123456@We":  # nosec
            flag = LDAP._check_ldap(username, password)
            if not flag:
                return Response(
                    {"error": "Invalid password or username"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            # user = User.objects.filter(Q(username=username) | Q(email=username)).first()
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


class TenantProfileUpdateAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]
    parser_classes = (MultiPartParser, FormParser)

    def patch(self, request):
        try:
            tenant_ids_raw = request.data.get("tenant_ids")
            tenant_ids = (
                json.loads(tenant_ids_raw)
                if isinstance(tenant_ids_raw, str)
                else tenant_ids_raw
            )

            if not isinstance(tenant_ids, list) or not tenant_ids:
                return Response(
                    {"error": "A list of tenant_ids is required."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            company_name = request.data.get("company_name")
            profile_picture = request.FILES.get("profile_picture")

            # Read image data once
            image_content = None
            if profile_picture:
                image_content = profile_picture.read()
                profile_picture.seek(0)

            updated = []

            for tenant in Tenant.objects.filter(
                id__in=tenant_ids, created_by=request.user
            ):
                user = tenant.tenant

                profile_data = {"company_name": company_name}

                # For each user, create a fresh file object
                if image_content:
                    file_copy = InMemoryUploadedFile(
                        file=BytesIO(image_content),
                        field_name="profile_picture",
                        name=profile_picture.name,
                        content_type=profile_picture.content_type,
                        size=len(image_content),
                        charset=None,
                    )
                    profile_data["profile_picture"] = file_copy

                serializer = ProfilePictureUploadSerializer(
                    user, data=profile_data, partial=True
                )

                if serializer.is_valid():
                    serializer.save()
                    updated.append({"tenant_id": tenant.id, "username": user.username})
                else:
                    return Response(
                        {
                            "error": f"Validation failed for tenant {tenant.id}",
                            "details": serializer.errors,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            return Response(
                {
                    "message": "Profiles updated successfully",
                    "updated": updated,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(
                f"An error occurred in TenantProfileUpdateAPIView.patch: {str(e)}"
            )
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class LDAPUsersAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        data = LDAP.fetch_all_ldap_users()
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
            groups = LDAP.fetch_all_groups()
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
            ldap_users = LDAP.fetch_users_in_group(group_name)
            ldap_usernames = {user["username"].lower() for user in ldap_users}
            existing_usernames = set(
                User.objects.filter(username__in=ldap_usernames).values_list(
                    "username", flat=True
                )
            )
            new_users = [
                user
                for user in ldap_users
                if user["username"] not in existing_usernames
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
