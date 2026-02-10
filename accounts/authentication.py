# auth/authentication.py
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class VersionedJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)

        token_version = validated_token.get("token_version")
        if token_version is None:
            raise InvalidToken("Missing token_version claim")

        if token_version != user.token_version:
            raise InvalidToken("Token has been revoked")

        return user
