# Create your views here.
from django.db.models import Q
from loguru import logger
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from .models import PermissionChoices, User
from .serializers import UserCreateSerializer, UserDetailSerializer


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
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {
                    "message": "User created successfully",
                    "user_id": user.id,
                    "username": user.username,
                },
                status=status.HTTP_201_CREATED,
            )
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

        username = request.data.get("username")
        password = request.data.get("password")

        # Validate input
        if not username or not password:
            return Response(
                {"error": "Please provide both username and password"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Get the user
            user = User.objects.filter(Q(username=username) | Q(email=username)).first()

            # Check password
            if user.check_password(password):
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)

                return Response(
                    {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Invalid password"}, status=status.HTTP_401_UNAUTHORIZED
                )

        except User.DoesNotExist:
            return Response(
                {"error": "User does not exist"}, status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            logger.error(f"An error occurred UserLoginAPIView.post: {str(e)}")
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        try:
            # The user is already authenticated via JWT
            user = request.user

            # Serialize the user data
            serializer = UserDetailSerializer(user)

            return Response(
                {
                    "message": "User details retrieved successfully",
                    "user": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PermissionChoicesAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Retrieves the permission choices.

        Returns a JSON response with the following data on success:
        - permissions: list of objects (Permission choice details)

        Returns HTTP 200 status code on success, or HTTP 500 for any other server error.
        """
        try:
            # Get all PermissionChoices as a list of dictionaries
            permissions = [
                {"id": choice.value, "text": choice.label}
                for choice in PermissionChoices
            ]

            return Response(
                {
                    "permissions": permissions,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
