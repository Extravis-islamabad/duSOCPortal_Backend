# Create your views here.
from django.db.models import Q
from loguru import logger
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .serializers import UserCreateSerializer


class UserCreateAPIView(APIView):
    def post(self, request):
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
        username = request.data.get("username")
        password = request.data.get("raw_password")

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
                        "message": "Login successful",
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_super_admin": user.is_super_admin,
                            "is_admin": user.is_admin,
                        },
                        "tokens": {
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                        },
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
