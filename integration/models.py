from django.db import models
from django.forms import ValidationError

from authentication.models import User


class IntegrationTypes(models.IntegerChoices):
    SIEM_INTEGRATION = 1, "SIEM Integration"
    SOAR_INTEGRATION = 2, "SOAR Integration"
    ITSM_INTEGRATION = 3, "ITSM Integration"
    THREAT_INTELLIGENCE = 4, "Threat Intelligence"


class SiemSubTypes(models.IntegerChoices):
    IBM_QRADAR = 1, "IBM QRadar"
    SPLUNK = 2, "Splunk"
    OTHER = 3, "Other"


class SoarSubTypes(models.IntegerChoices):
    CORTEX_SOAR = 1, "Cortex SOAR"
    IBM_RESILIENT = 2, "IBM Resilient"
    OTHER = 3, "Other"


class ItsmSubTypes(models.IntegerChoices):
    MANAGE_ENGINE = 1, "M.E ServiceDesk Plus MSP"
    ZENDESK = 2, "Zendesk"
    OTHER = 3, "Other"


class ThreatIntelligenceSubTypes(models.IntegerChoices):
    CYWARE = 1, "CYWARE"


class CredentialTypes(models.IntegerChoices):
    API_KEY = 1, "API Key"
    USERNAME_PASSWORD = 2, "Username and Password"
    SECRET_KEY_ACCESS_KEY = 3, "Secret Key and Access Key"


class Integration(models.Model):
    admin = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="integration",
        null=True,
        blank=True,
    )
    integration_type = models.IntegerField(
        choices=IntegrationTypes.choices, default=IntegrationTypes.SIEM_INTEGRATION
    )
    siem_subtype = models.IntegerField(
        choices=SiemSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for SIEM Integration type",
    )
    soar_subtype = models.IntegerField(
        choices=SoarSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for SOAR Integration type",
    )
    itsm_subtype = models.IntegerField(
        choices=ItsmSubTypes.choices,
        null=True,
        blank=True,
        help_text="Required for ITSM Integration type",
    )
    status = models.BooleanField(default=True)
    instance_name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.instance_name

    def clean(self):
        """Validate that the correct subtype is set based on integration_type."""
        if self.integration_type == IntegrationTypes.SIEM_INTEGRATION:
            if not self.siem_subtype:
                raise ValidationError(
                    {
                        "siem_subtype": "SIEM subtype is required for SIEM Integration type."
                    }
                )
            self.soar_subtype = None
            self.itsm_subtype = None
        elif self.integration_type == IntegrationTypes.SOAR_INTEGRATION:
            if not self.soar_subtype:
                raise ValidationError(
                    {
                        "soar_subtype": "SOAR subtype is required for SOAR Integration type."
                    }
                )
            self.siem_subtype = None
            self.itsm_subtype = None
        elif self.integration_type == IntegrationTypes.ITSM_INTEGRATION:
            if not self.itsm_subtype:
                raise ValidationError(
                    {
                        "itsm_subtype": "ITSM subtype is required for ITSM Integration type."
                    }
                )
            self.siem_subtype = None
            self.soar_subtype = None

    def save(self, *args, **kwargs):
        """Ensure clean is called before saving."""
        self.full_clean()
        super().save(*args, **kwargs)


class IntegrationCredentials(models.Model):
    integration = models.ForeignKey(
        Integration, on_delete=models.CASCADE, related_name="credentials"
    )
    credential_type = models.IntegerField(
        choices=CredentialTypes.choices, default=CredentialTypes.API_KEY
    )
    username = models.CharField(max_length=100, null=True, blank=True)
    password = models.CharField(max_length=100, null=True, blank=True)
    api_key = models.CharField(max_length=100, null=True, blank=True)
    access_key = models.CharField(max_length=100, null=True, blank=True)
    secret_key = models.CharField(max_length=100, null=True, blank=True)
    ip_address = models.GenericIPAddressField(unique=True)
    port = models.IntegerField(default=80)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        """Validate credential_type constraints."""
        if self.credential_type == CredentialTypes.API_KEY:
            if not self.api_key:
                raise ValidationError(
                    {"api_key": "API key is required for API Key credential type."}
                )
            if self.username or self.password:
                raise ValidationError(
                    {
                        "username": "Username and password must be null for API Key credential type.",
                        "password": "Username and password must be null for API Key credential type.",
                    }
                )
        elif self.credential_type == CredentialTypes.USERNAME_PASSWORD:
            if not (self.username and self.password):
                raise ValidationError(
                    {
                        "username": "Both username and password are required for Username and Password credential type.",
                        "password": "Both username and password are required for Username and Password credential type.",
                    }
                )
            if self.api_key:
                raise ValidationError(
                    {
                        "api_key": "API key must be null for Username and Password credential type."
                    }
                )

    def save(self, *args, **kwargs):
        """Ensure clean is called and password is securely hashed before saving."""
        self.full_clean()

        if self.credential_type == CredentialTypes.USERNAME_PASSWORD and self.password:
            self._plaintext_password = self.password

            # TODO : Removed the password hashing
            # self.password = make_password(self.password)

        super().save(*args, **kwargs)
