import logging

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import ContactMessageSerializer
from core.tasks import send_contact_email
from commons.throttles import ContactRateThrottle

logger = logging.getLogger(__name__)


class ContactView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ContactRateThrottle]

    @extend_schema(
        request=ContactMessageSerializer,
        responses={
            202: OpenApiResponse(
                description="Message accepted and queued for delivery."
            ),
            400: OpenApiResponse(description="Invalid payload."),
            429: OpenApiResponse(description="Too many requests."),
        },
        tags=["Contact"],
        summary="Submit contact form",
        description=(
            "Accepts a contact-form submission from the portfolio frontend "
            "and delivers it to the site owner's inbox via an async Celery task. "
            "Nothing is persisted to the database."
        ),
    )
    def post(self, request):
        serializer = ContactMessageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        send_contact_email.delay(
            name=data["name"],
            email=data["email"],
            message=data["message"],
            sent_at=data["sentAt"].isoformat(),
        )

        logger.info("Contact message queued from %s", data["email"])

        return Response(
            {
                "success": True,
                "message": "Your message has been received. I'll get back to you soon!",
            },
            status=status.HTTP_202_ACCEPTED,
        )
