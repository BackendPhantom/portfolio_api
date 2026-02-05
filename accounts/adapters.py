from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom adapter for regular (non-social) account registration.
    Ensures username is set to email.
    """

    def save_user(self, request, user, form, commit=True):
        user = super().save_user(request, user, form, commit=False)
        # Set username to email for regular signups
        user.username = user.email
        if commit:
            user.save()
        return user


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter for social account registration.
    Pulls profile data from social providers and ensures username = email.
    """

    def populate_user(self, request, sociallogin, data):
        """
        Called when a new user is being created from a social login.
        Extracts profile info from the social provider.
        """
        user = super().populate_user(request, sociallogin, data)

        # Get email from the social account data
        email = data.get("email")
        if email:
            user.username = email
            user.email = email

        # Extract first_name and last_name
        user.first_name = data.get("first_name", "")
        user.last_name = data.get("last_name", "")

        # If name is provided as a single field, split it
        if not user.first_name and data.get("name"):
            name_parts = data.get("name", "").split(" ", 1)
            user.first_name = name_parts[0]
            user.last_name = name_parts[1] if len(name_parts) > 1 else ""

        return user

    def save_user(self, request, sociallogin, form=None):
        """
        Called when saving a new user from social login.
        Pulls additional profile data (avatar, etc.) from the provider.
        """
        user = super().save_user(request, sociallogin, form)

        # Ensure username equals email
        if user.email and user.username != user.email:
            user.username = user.email

        # Extract avatar and additional data from the social account
        extra_data = sociallogin.account.extra_data
        provider = sociallogin.account.provider

        if provider == "google":
            # Google provides 'picture' for avatar
            user.avatar = extra_data.get("picture", "")
            # Google might provide name separately
            if not user.first_name:
                user.first_name = extra_data.get("given_name", "")
            if not user.last_name:
                user.last_name = extra_data.get("family_name", "")
            # Mark email as verified (Google verifies emails)
            user.email_verified = True

        elif provider == "github":
            # GitHub provides 'avatar_url' for avatar
            user.avatar = extra_data.get("avatar_url", "")
            # GitHub might provide name as a single field
            if not user.first_name and extra_data.get("name"):
                name_parts = extra_data.get("name", "").split(" ", 1)
                user.first_name = name_parts[0]
                user.last_name = name_parts[1] if len(name_parts) > 1 else ""
            # GitHub provides bio
            if extra_data.get("bio"):
                user.bio = extra_data.get("bio", "")
            # GitHub provides location
            if extra_data.get("location"):
                user.location = extra_data.get("location", "")
            # GitHub provides html_url (profile URL)
            if extra_data.get("html_url"):
                user.github_url = extra_data.get("html_url", "")
            # GitHub provides blog (website)
            if extra_data.get("blog"):
                user.website = extra_data.get("blog", "")
            # GitHub provides twitter_username
            if extra_data.get("twitter_username"):
                user.twitter_url = (
                    f"https://twitter.com/{extra_data.get('twitter_username')}"
                )

        user.save()
        return user

    def authentication_error(
        self, request, provider_id, error=None, exception=None, extra_context=None
    ):
        """
        Handle authentication errors gracefully.
        """
        # Log the error for debugging
        import logging

        logger = logging.getLogger(__name__)
        logger.error(
            f"Social auth error for {provider_id}: {error}, exception: {exception}"
        )
        return super().authentication_error(
            request, provider_id, error, exception, extra_context
        )
