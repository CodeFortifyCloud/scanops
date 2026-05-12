from __future__ import annotations

import json

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views import View
from django.views.generic import CreateView

from apps.core.services.scan_policy import build_scan_summary, validate_scan_options
from apps.ops.services import data_visibility_service
from apps.scans.forms import ScanRequestForm
from apps.scans.models import ScanRequest
from apps.targets.models import Target


class ScanRequestCreateView(CreateView):
    model = ScanRequest
    form_class = ScanRequestForm
    template_name = "scans/new_scan.html"

    def dispatch(self, request, *args, **kwargs):
        if request.method.lower() == "post" and not request.user.is_authenticated:
            messages.info(request, "Please login or register to submit a scan request.")
            login_url = reverse("accounts:login")
            return HttpResponseRedirect(f"{login_url}?next={reverse('scans:new')}")
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        initial = super().get_initial()
        initial.update(
            {
                "scan_type": ScanRequest._meta.get_field("scan_type").default,
                "timing_profile": ScanRequest._meta.get_field("timing_profile").default,
                "enable_host_discovery": True,
                "enable_service_detection": True,
                "enable_version_detection": False,
                "enable_os_detection": False,
                "enable_traceroute": False,
                "enable_dns_resolution": True,
            }
        )
        return initial

    def form_valid(self, form):
        if not self.request.user.is_authenticated:
            raise PermissionDenied("Anonymous users cannot submit scan requests.")
        self.object: ScanRequest = form.save(commit=False)
        self.object.requested_by = self.request.user
        self.object.status = ScanRequest.Status.PENDING
        summary = form.summary or build_scan_summary(form.cleaned_data, form.policy_result)
        self.object.validation_summary = json.dumps(summary)
        self.object.save()

        messages.success(self.request, "Scan request created and queued for validation.")
        if form.policy_result:
            for warning in form.policy_result.warnings:
                messages.warning(self.request, warning)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return reverse("scans:new")

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user if self.request.user.is_authenticated else None
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        initial_payload = self.get_initial()
        initial_payload["target"] = None
        initial_policy = validate_scan_options(initial_payload)
        form = context.get("form")
        profile_presets = []
        if form is not None and "profile" in form.fields:
            for profile in form.fields["profile"].queryset:
                profile_presets.append(
                    {
                        "id": profile.pk,
                        "scan_type": profile.scan_type,
                        "timing_profile": profile.timing_profile,
                        "port_scope": profile.port_scope or "",
                        "enable_host_discovery": profile.enable_host_discovery,
                        "enable_service_detection": profile.enable_service_detection,
                        "enable_version_detection": profile.enable_version_detection,
                        "enable_os_detection": profile.enable_os_detection,
                        "enable_traceroute": profile.enable_traceroute,
                        "enable_dns_resolution": profile.enable_dns_resolution,
                    }
                )
        context["scan_preview"] = build_scan_summary(initial_payload, initial_policy)
        context["profile_presets"] = profile_presets
        context["breadcrumbs"] = [
            {"label": "Scans", "url": ""},
            {"label": "New Request", "url": ""},
        ]
        context["public_mode"] = not self.request.user.is_authenticated
        return context


class ScanPreviewView(View):
    template_name = "partials/scan_preview.html"

    @staticmethod
    def _coerce_checkbox(raw_value: str | None) -> bool:
        return (raw_value or "").lower() in {"1", "true", "on", "yes"}

    def post(self, request, *args, **kwargs) -> HttpResponse:
        if request.user.is_authenticated:
            target = None
            target_id = request.POST.get("target")
            if target_id and target_id.isdigit():
                target_queryset = data_visibility_service.get_user_visible_targets(request.user, queryset=Target.objects.all())
                target = target_queryset.filter(pk=int(target_id)).first()

            payload = {
                "target": target,
                "scan_type": request.POST.get("scan_type", ""),
                "port_input": request.POST.get("port_input", ""),
                "enable_host_discovery": self._coerce_checkbox(request.POST.get("enable_host_discovery")),
                "enable_service_detection": self._coerce_checkbox(request.POST.get("enable_service_detection")),
                "enable_version_detection": self._coerce_checkbox(request.POST.get("enable_version_detection")),
                "enable_os_detection": self._coerce_checkbox(request.POST.get("enable_os_detection")),
                "enable_traceroute": self._coerce_checkbox(request.POST.get("enable_traceroute")),
                "enable_dns_resolution": self._coerce_checkbox(request.POST.get("enable_dns_resolution")),
                "timing_profile": request.POST.get("timing_profile", ""),
            }
        else:
            payload = {
                "target": None,
                "scan_type": "safe_basic",
                "port_input": "",
                "enable_host_discovery": True,
                "enable_service_detection": True,
                "enable_version_detection": False,
                "enable_os_detection": False,
                "enable_traceroute": False,
                "enable_dns_resolution": True,
                "timing_profile": "normal",
            }
        policy = validate_scan_options(payload)
        summary = build_scan_summary(payload, policy)
        return render(
            request,
            self.template_name,
            {
                "summary": summary,
            },
        )
