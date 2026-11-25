"""Forms for managing assets and filtering the local interface."""

from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.http import QueryDict

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.findings.models import Finding, FindingDecision
from ciclosec.scanners.adapters import validate_local_image_reference
from ciclosec.scanners.github import _validate_repository
from ciclosec.scanners.process import ScannerExecutionError

PROVIDER_LABELS = {
    "cisa_kev": "CISA KEV",
    "osv": "OSV",
    "github_advisories": "GitHub Advisories",
    "nvd": "NVD",
    "epss": "EPSS",
}

SETTINGS_OPTIONS = {
    "scanning.execution.allow_on_demand": ("Escaneos manuales", "bool"),
    "scanning.execution.allow_repository_scanners_with_network": (
        "Autorizar escáneres de repositorios con acceso a red",
        "bool",
    ),
    "scanning.execution.repository_scanner_use_local_databases": (
        "Usar bases locales para escáneres de repositorios",
        "bool",
    ),
    "scanning.execution.timeout_seconds": ("Tiempo máximo de escaneo en segundos", "int"),
    "scanning.execution.max_concurrent_scans": ("Máximo de escaneos simultáneos", "int"),
    "scanning.execution.max_queued_scans": ("Máximo de escaneos en cola", "int"),
    "scanning.schedules.repositories": ("Intervalo de repositorios", "duration"),
    "scanning.schedules.container_images": ("Intervalo de imágenes", "duration"),
    "docker.enabled": ("Habilitar escaneo de imágenes locales", "bool"),
    "docker.allow_local_daemon": ("Autorizar acceso al daemon Docker local", "bool"),
    "intelligence.stale_after": ("Límite de antigüedad de inteligencia", "duration"),
    "notifications.enabled": ("Habilitar notificaciones configuradas", "bool"),
    "mcp.enabled": ("Habilitar servidor MCP al arrancar", "bool"),
    "mcp.allow_intelligence_sync": ("Autorizar sincronización de inteligencia desde MCP", "bool"),
    "mcp.allow_finding_decisions": ("Autorizar decisiones de hallazgos desde MCP", "bool"),
}

PROVIDER_SCHEDULE_OPTIONS = {
    key: option
    for provider, label in PROVIDER_LABELS.items()
    for key, option in (
        (f"intelligence.providers.{provider}.enabled", (f"Programar {label}", "bool")),
        (
            f"intelligence.providers.{provider}.refresh_interval",
            (f"Intervalo programado de {label}", "duration"),
        ),
    )
}
SETTINGS_OPTIONS.update(PROVIDER_SCHEDULE_OPTIONS)


class ConfigurationOptionForm(forms.Form):
    revision = forms.IntegerField(min_value=0, widget=forms.HiddenInput)
    confirm = forms.BooleanField(label="Confirmo este cambio", required=True)

    def __init__(
        self, data: QueryDict | None = None, *, key: str, revision: int, value: object, prefix: str
    ) -> None:
        super().__init__(data=data, prefix=prefix)
        label, kind = SETTINGS_OPTIONS[key]
        field: forms.Field
        if kind == "bool":
            field = forms.TypedChoiceField(
                label=label,
                choices=[("false", "Deshabilitado"), ("true", "Habilitado")],
                coerce=lambda item: item == "true",
            )
            value = "true" if value is True else "false"
        elif kind == "int":
            field = forms.IntegerField(label=label, min_value=1)
        else:
            field = forms.RegexField(
                label=label,
                regex=r"^[1-9][0-9]*(s|m|h|d)$",
                max_length=20,
                help_text="Duración positiva, por ejemplo 6h o 7d.",
            )
        self.fields["value"] = field
        self.fields["revision"].initial = revision
        self.fields["value"].initial = value
        self.order_fields(["value", "revision", "confirm"])


class AssetForm(forms.ModelForm):  # type: ignore[type-arg]
    class Meta:
        model = Asset
        fields = ["name", "environment", "exposure", "enabled"]
        labels = {
            "name": "Nombre",
            "environment": "Entorno",
            "exposure": "Exposición",
            "enabled": "Activo habilitado",
        }


class RepositoryForm(forms.ModelForm):  # type: ignore[type-arg]
    class Meta:
        model = Repository
        fields = ["owner", "repository_name", "ref", "credential_env"]
        labels = {
            "owner": "Propietario u organización",
            "repository_name": "Repositorio",
            "ref": "Rama o referencia",
            "credential_env": "Nombre de la variable del token",
        }
        help_texts = {
            "credential_env": (
                "Solo el nombre de la variable de entorno, nunca el valor del token. "
                "Déjalo vacío para usar la configuración predeterminada."
            ),
        }

    def clean(self) -> dict[str, object]:
        super().clean()
        cleaned = self.cleaned_data
        owner = cleaned.get("owner")
        name = cleaned.get("repository_name")
        ref = cleaned.get("ref")
        if isinstance(owner, str) and isinstance(name, str) and isinstance(ref, str):
            try:
                _validate_repository(owner, name, ref)
            except ScannerExecutionError as error:
                raise ValidationError(
                    "Comprueba el propietario, el repositorio y la referencia."
                ) from error
            duplicates = Repository.objects.filter(
                provider=Repository.Provider.GITHUB, owner=owner, repository_name=name, ref=ref
            )
            if self.instance.pk:
                duplicates = duplicates.exclude(pk=self.instance.pk)
            if duplicates.exists():
                raise ValidationError("Esta referencia de repositorio ya está registrada.")
        return cleaned


class ContainerImageForm(forms.ModelForm):  # type: ignore[type-arg]
    class Meta:
        model = ContainerImage
        fields = ["image_reference"]
        labels = {"image_reference": "Referencia de la imagen"}
        help_texts = {
            "image_reference": (
                "El escaneo requiere habilitar Docker local y autorizar esta referencia "
                "en la configuración."
            ),
        }

    def clean_image_reference(self) -> str:
        value: str = self.cleaned_data["image_reference"]
        try:
            validate_local_image_reference(value)
        except ScannerExecutionError:
            raise ValidationError("La referencia de imagen local no es válida.") from None
        return value


class AssetSearchForm(forms.Form):
    q = forms.CharField(label="Buscar por nombre", required=False, max_length=200)


class FindingFilterForm(forms.Form):
    q = forms.CharField(label="Buscar", required=False, max_length=200)
    status = forms.ChoiceField(
        label="Afectación",
        required=False,
        choices=[
            ("", "Todas"),
            (Finding.AffectedStatus.CONFIRMED, "Confirmada"),
            (Finding.AffectedStatus.POTENTIAL, "Potencial"),
            (Finding.AffectedStatus.NOT_AFFECTED, "No afectada"),
            (Finding.AffectedStatus.NOT_APPLICABLE, "No aplicable"),
            (Finding.AffectedStatus.PENDING_VERIFICATION, "Pendiente de verificar"),
        ],
    )
    asset_id = forms.IntegerField(label="ID del activo", required=False, min_value=1)
    scan_id = forms.IntegerField(label="ID del escaneo", required=False, min_value=1)
    sort = forms.ChoiceField(
        label="Orden",
        required=False,
        choices=[("risk", "Mayor prioridad"), ("recent", "Más recientes")],
        initial="risk",
    )


class FindingDecisionForm(forms.Form):
    status = forms.ChoiceField(
        label="Decisión humana",
        choices=FindingDecision.Status.choices,
    )
    assignee = forms.ModelChoiceField(
        label="Responsable",
        queryset=get_user_model().objects.filter(is_active=True).order_by("username"),
        required=False,
    )
    reason = forms.CharField(
        label="Motivo",
        widget=forms.Textarea(attrs={"rows": 4}),
        max_length=4000,
    )


class HistoryFilterForm(forms.Form):
    asset_id = forms.IntegerField(label="ID del activo", required=False, min_value=1)


class SBOMFilterForm(forms.Form):
    asset = forms.ModelChoiceField(label="Activo", queryset=Asset.objects.order_by("name"))
    scan_id = forms.IntegerField(label="ID del escaneo", required=False, min_value=1)
