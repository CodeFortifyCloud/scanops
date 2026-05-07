from __future__ import annotations

from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView

from apps.ops.models import PermissionRule
from apps.ops.rbac import CapabilityRequiredMixin
from apps.ops.services import data_visibility_service
from apps.scans.forms import CompareResultsForm, ResultFilterForm
from apps.scans.models import ScanResult
from apps.scans.services.comparison_service import build_comparison_from_current, compare_results
from apps.scans.services.result_service import (
    build_host_detail_context,
    build_result_detail_context,
)
from apps.targets.models import Target


def _has_multi_host_rows(result: ScanResult) -> bool:
    host_markers: set[str] = set()
    for row in result.port_results.all():
        if isinstance(row.extra_data_json, dict):
            host = (row.extra_data_json.get("host") or "").strip()
            if host:
                host_markers.add(host)
                if len(host_markers) > 1:
                    return True
    return False


class ScanResultListView(CapabilityRequiredMixin, ListView):
    capability_key = PermissionRule.PermissionKey.VIEW_RESULTS
    model = ScanResult
    template_name = "scans/results_list.html"
    context_object_name = "results"
    paginate_by = 15

    def get_template_names(self):
        if self.request.headers.get("HX-Request"):
            return ["partials/results_table.html"]
        return [self.template_name]

    def get_queryset(self):
        queryset = (
            ScanResult.objects.select_related(
                "execution",
                "execution__scan_request",
                "execution__scan_request__target",
                "execution__scan_request__profile",
                "execution__scan_request__requested_by",
            )
            .prefetch_related("port_results")
            .filter(execution__is_archived=False)
            .order_by("-generated_at")
        )
        queryset = data_visibility_service.get_user_visible_results(self.request.user, queryset=queryset)

        self.filter_form = ResultFilterForm(self.request.GET or None, user=self.request.user)
        if self.filter_form.is_valid():
            cleaned = self.filter_form.cleaned_data
            q = (cleaned.get("q") or "").strip()
            if q:
                queryset = queryset.filter(
                    Q(target_snapshot__icontains=q)
                    | Q(execution__execution_id__icontains=q)
                    | Q(execution__scan_request__target__name__icontains=q)
                )
            if cleaned.get("date_from"):
                queryset = queryset.filter(generated_at__date__gte=cleaned["date_from"])
            if cleaned.get("date_to"):
                queryset = queryset.filter(generated_at__date__lte=cleaned["date_to"])
            if cleaned.get("target"):
                queryset = queryset.filter(execution__scan_request__target=cleaned["target"])
            if cleaned.get("execution_status"):
                queryset = queryset.filter(execution__status=cleaned["execution_status"])
            if cleaned.get("profile"):
                queryset = queryset.filter(execution__scan_request__profile=cleaned["profile"])
            if cleaned.get("service"):
                queryset = queryset.filter(port_results__service_name__icontains=cleaned["service"])
            if cleaned.get("risk_level"):
                queryset = queryset.filter(port_results__risk_level=cleaned["risk_level"])
        return queryset.distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = self.filter_form
        summary_source = data_visibility_service.get_user_visible_results(
            self.request.user,
            queryset=ScanResult.objects.filter(execution__is_archived=False),
        )
        context["result_summary"] = {
            "total": summary_source.count(),
            "high_risk": summary_source.filter(port_results__risk_level="high").distinct().count(),
            "medium_risk": summary_source.filter(port_results__risk_level="medium").distinct().count(),
            "hosts_down": summary_source.filter(host_status=ScanResult.HostStatus.DOWN).count(),
        }
        context["scope_label"] = "All" if data_visibility_service.user_can_view_all_data(self.request.user) else "My"
        context["breadcrumbs"] = [
            {"label": "Results", "url": ""},
        ]
        return context


class ScanResultDetailView(CapabilityRequiredMixin, DetailView):
    capability_key = PermissionRule.PermissionKey.VIEW_RESULTS
    model = ScanResult
    template_name = "scans/result_detail.html"
    context_object_name = "result"

    def get_queryset(self):
        queryset = ScanResult.objects.select_related(
            "execution",
            "execution__scan_request",
            "execution__scan_request__target",
            "execution__scan_request__profile",
            "execution__scan_request__requested_by",
        ).prefetch_related("port_results")
        return data_visibility_service.get_user_visible_results(self.request.user, queryset=queryset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        result = context["result"]
        context.update(build_result_detail_context(result, user=self.request.user))
        context["tab"] = self.request.GET.get("tab", "overview")
        context["breadcrumbs"] = [
            {"label": "Results", "url": reverse("scans:results")},
            {"label": result.execution.execution_id, "url": ""},
        ]
        return context


class ScanRawOutputView(CapabilityRequiredMixin, DetailView):
    capability_key = PermissionRule.PermissionKey.VIEW_RESULTS
    model = ScanResult
    template_name = "scans/raw_output.html"
    context_object_name = "result"

    def get_queryset(self):
        queryset = ScanResult.objects.select_related("execution__scan_request__requested_by")
        return data_visibility_service.get_user_visible_results(self.request.user, queryset=queryset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["breadcrumbs"] = [
            {"label": "Results", "url": reverse("scans:results")},
            {"label": self.object.execution.execution_id, "url": reverse("scans:result-detail", kwargs={"pk": self.object.pk})},
            {"label": "Raw Output", "url": ""},
        ]
        return context


class ScanParsedOutputView(CapabilityRequiredMixin, DetailView):
    capability_key = PermissionRule.PermissionKey.VIEW_RESULTS
    model = ScanResult
    template_name = "scans/parsed_output.html"
    context_object_name = "result"

    def get_queryset(self):
        queryset = ScanResult.objects.select_related("execution__scan_request__requested_by")
        return data_visibility_service.get_user_visible_results(self.request.user, queryset=queryset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(build_result_detail_context(self.object, user=self.request.user))
        context["parsed"] = self.object.parsed_output_json or {}
        context["breadcrumbs"] = [
            {"label": "Results", "url": reverse("scans:results")},
            {"label": self.object.execution.execution_id, "url": reverse("scans:result-detail", kwargs={"pk": self.object.pk})},
            {"label": "Parsed Output", "url": ""},
        ]
        return context


class ScanResultCompareView(CapabilityRequiredMixin, TemplateView):
    capability_key = PermissionRule.PermissionKey.COMPARE_RESULTS
    template_name = "scans/result_compare.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        if request.headers.get("HX-Request"):
            return render(request, "partials/comparison_summary.html", context)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        current_result = None
        target = None
        pk = self.kwargs.get("pk")
        if pk:
            current_queryset = data_visibility_service.get_user_visible_results(
                self.request.user,
                queryset=ScanResult.objects.select_related(
                    "execution__scan_request__target",
                    "execution__scan_request__requested_by",
                ),
            )
            current_result = get_object_or_404(current_queryset, pk=pk)
            target = current_result.execution.scan_request.target

        initial = {}
        if current_result and not self.request.GET:
            previous = build_comparison_from_current(current_result, user=self.request.user)
            if previous:
                initial = {
                    "left_result": previous["base_result"].pk,
                    "right_result": previous["current_result"].pk,
                }
            else:
                initial = {"right_result": current_result.pk}

        form = CompareResultsForm(self.request.GET or None, target=target, initial=initial, user=self.request.user)
        comparison = None
        if self.request.GET and form.is_valid():
            left_result = form.cleaned_data["left_result"]
            right_result = form.cleaned_data["right_result"]
            if left_result.pk == right_result.pk:
                messages.warning(self.request, "Choose two different results to compare.")
            else:
                comparison = compare_results(left_result, right_result)
        elif current_result and not self.request.GET:
            comparison = build_comparison_from_current(current_result, user=self.request.user)

        context.update(
            {
                "form": form,
                "current_result": current_result,
                "comparison": comparison,
                "breadcrumbs": [
                    {"label": "Results", "url": reverse("scans:results")},
                    {"label": "Compare", "url": ""},
                ],
            }
        )
        return context


class HostDetailView(CapabilityRequiredMixin, DetailView):
    capability_key = PermissionRule.PermissionKey.VIEW_RESULTS
    model = Target
    template_name = "scans/host_detail.html"
    context_object_name = "target"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(build_host_detail_context(self.object, user=self.request.user))
        context["breadcrumbs"] = [
            {"label": "Results", "url": reverse("scans:results")},
            {"label": "Host Detail", "url": ""},
        ]
        return context

    def get_queryset(self):
        queryset = Target.objects.all()
        return data_visibility_service.get_user_visible_targets(self.request.user, queryset=queryset)


class ResultPortsPartialView(CapabilityRequiredMixin, View):
    capability_key = PermissionRule.PermissionKey.VIEW_RESULTS

    def get(self, request, pk: int) -> HttpResponse:
        queryset = data_visibility_service.get_user_visible_results(request.user, queryset=ScanResult.objects.all())
        result = get_object_or_404(queryset, pk=pk)
        return render(
            request,
            "partials/result_ports_table.html",
            {
                "result": result,
                "port_results": result.port_results.all().order_by("port", "protocol"),
                "has_multi_host_rows": _has_multi_host_rows(result),
            },
        )
