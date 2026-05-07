from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views import View
from django.views.generic import DetailView, ListView

from apps.ops.models import PermissionRule
from apps.ops.rbac import CapabilityRequiredMixin
from apps.ops.services import data_visibility_service
from apps.scans.forms import RunningFilterForm
from apps.scans.models import ScanExecution
from apps.scans.services.execution_service import (
    cancel_execution,
    ensure_executions_for_ready_requests,
    retry_execution,
    simulate_execution_tick,
)


def _redirect_back(request: HttpRequest, fallback: str) -> HttpResponse:
    return redirect(request.META.get("HTTP_REFERER") or fallback)


def _simulation_enabled() -> bool:
    return bool(getattr(settings, "SCANOPS_ENABLE_SIMULATION", False))


class RunningScanListView(CapabilityRequiredMixin, ListView):
    capability_key = PermissionRule.PermissionKey.VIEW_SCANS
    model = ScanExecution
    template_name = "scans/running_scans.html"
    context_object_name = "executions"
    paginate_by = 12

    def get_template_names(self):
        if self.request.headers.get("HX-Request"):
            return ["partials/running_table.html"]
        return [self.template_name]

    def get_queryset(self):
        ensure_executions_for_ready_requests()
        queryset = (
            ScanExecution.objects.select_related(
                "scan_request",
                "scan_request__target",
                "scan_request__profile",
                "scan_request__requested_by",
            )
            .filter(is_archived=False)
            .order_by("-created_at")
        )
        queryset = data_visibility_service.get_user_visible_executions(self.request.user, queryset=queryset)
        self.filter_form = RunningFilterForm(self.request.GET or None, user=self.request.user)
        if self.filter_form.is_valid():
            cleaned = self.filter_form.cleaned_data
            q = (cleaned.get("q") or "").strip()
            if q:
                queryset = queryset.filter(
                    Q(scan_request__target__target_value__icontains=q)
                    | Q(scan_request__target__name__icontains=q)
                    | Q(execution_id__icontains=q)
                    | Q(worker_name__icontains=q)
                )
            if cleaned.get("status"):
                queryset = queryset.filter(status=cleaned["status"])
            if cleaned.get("queue_status"):
                queryset = queryset.filter(queue_status=cleaned["queue_status"])
            if cleaned.get("requested_by"):
                queryset = queryset.filter(scan_request__requested_by=cleaned["requested_by"])
            if cleaned.get("target"):
                queryset = queryset.filter(scan_request__target=cleaned["target"])
        return queryset.distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        executions = list(context["executions"])
        if _simulation_enabled():
            for execution in executions:
                if execution.status in {ScanExecution.Status.QUEUED, ScanExecution.Status.RUNNING}:
                    simulate_execution_tick(execution)
        context["executions"] = executions
        context["filter_form"] = self.filter_form
        summary_source = data_visibility_service.get_user_visible_executions(
            self.request.user,
            queryset=ScanExecution.objects.filter(is_archived=False),
        )
        context["summary"] = {
            "running": summary_source.filter(status=ScanExecution.Status.RUNNING).count(),
            "queued": summary_source.filter(status=ScanExecution.Status.QUEUED).count(),
            "failed": summary_source.filter(status=ScanExecution.Status.FAILED).count(),
            "completed": summary_source.filter(status=ScanExecution.Status.COMPLETED).count(),
        }
        context["scope_label"] = "All" if data_visibility_service.user_can_view_all_data(self.request.user) else "My"
        context["breadcrumbs"] = [
            {"label": "Running", "url": ""},
        ]
        return context


class ScanQueueView(CapabilityRequiredMixin, ListView):
    capability_key = PermissionRule.PermissionKey.VIEW_SCANS
    model = ScanExecution
    template_name = "scans/scan_queue.html"
    context_object_name = "executions"
    paginate_by = 12

    def get_template_names(self):
        if self.request.headers.get("HX-Request"):
            return ["partials/queue_table.html"]
        return [self.template_name]

    def get_queryset(self):
        ensure_executions_for_ready_requests()
        queryset = (
            ScanExecution.objects.select_related(
                "scan_request",
                "scan_request__target",
                "scan_request__profile",
                "scan_request__requested_by",
            )
            .filter(
                is_archived=False,
                status__in=[ScanExecution.Status.QUEUED, ScanExecution.Status.RUNNING],
            )
            .order_by("priority", "created_at")
        )
        queryset = data_visibility_service.get_user_visible_executions(self.request.user, queryset=queryset)
        self.filter_form = RunningFilterForm(self.request.GET or None, user=self.request.user)
        if self.filter_form.is_valid():
            cleaned = self.filter_form.cleaned_data
            q = (cleaned.get("q") or "").strip()
            if q:
                queryset = queryset.filter(
                    Q(scan_request__target__target_value__icontains=q)
                    | Q(scan_request__target__name__icontains=q)
                    | Q(execution_id__icontains=q)
                    | Q(worker_name__icontains=q)
                )
            if cleaned.get("queue_status"):
                queryset = queryset.filter(queue_status=cleaned["queue_status"])
            if cleaned.get("target"):
                queryset = queryset.filter(scan_request__target=cleaned["target"])
            if cleaned.get("requested_by"):
                queryset = queryset.filter(scan_request__requested_by=cleaned["requested_by"])
            if cleaned.get("status"):
                queryset = queryset.filter(status=cleaned["status"])
        return queryset.distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        executions = list(context["executions"])
        for index, execution in enumerate(executions, start=(context["page_obj"].start_index() if context.get("page_obj") else 1)):
            execution.queue_position = index
            execution.estimated_wait_minutes = max(1, (index - 1) * 2)
        context["executions"] = executions
        context["filter_form"] = self.filter_form
        queue_source = data_visibility_service.get_user_visible_executions(
            self.request.user,
            queryset=ScanExecution.objects.filter(is_archived=False),
        )
        context["queue_summary"] = {
            "total": queue_source.filter(status=ScanExecution.Status.QUEUED).count(),
            "assigned": queue_source.filter(queue_status=ScanExecution.QueueStatus.ASSIGNED).count(),
            "processing": queue_source.filter(queue_status=ScanExecution.QueueStatus.PROCESSING).count(),
            "failed": queue_source.filter(queue_status=ScanExecution.QueueStatus.ERROR).count(),
        }
        context["scope_label"] = "All" if data_visibility_service.user_can_view_all_data(self.request.user) else "My"
        context["breadcrumbs"] = [
            {"label": "Running", "url": reverse("scans:running")},
            {"label": "Queue", "url": ""},
        ]
        return context


class ScanMonitorDetailView(CapabilityRequiredMixin, DetailView):
    capability_key = PermissionRule.PermissionKey.VIEW_SCANS
    model = ScanExecution
    template_name = "scans/live_monitor.html"
    context_object_name = "execution"

    def get_queryset(self):
        queryset = ScanExecution.objects.select_related(
            "scan_request",
            "scan_request__target",
            "scan_request__profile",
            "scan_request__requested_by",
        )
        return data_visibility_service.get_user_visible_executions(self.request.user, queryset=queryset)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        execution = context["execution"]
        if _simulation_enabled():
            simulate_execution_tick(execution)
        context["result"] = getattr(execution, "result", None)
        context["recent_events"] = execution.event_logs.all()[:60]
        context["breadcrumbs"] = [
            {"label": "Running", "url": reverse("scans:running")},
            {"label": execution.execution_id, "url": ""},
        ]
        return context


class MonitorStatusPartialView(CapabilityRequiredMixin, View):
    capability_key = PermissionRule.PermissionKey.VIEW_SCANS

    def get(self, request, pk: int) -> HttpResponse:
        queryset = data_visibility_service.get_user_visible_executions(
            request.user,
            queryset=ScanExecution.objects.select_related("scan_request", "scan_request__target", "scan_request__profile"),
        )
        execution = get_object_or_404(
            queryset,
            pk=pk,
        )
        if _simulation_enabled():
            simulate_execution_tick(execution)
        return render(
            request,
            "partials/live_status_panel.html",
            {"execution": execution, "result": getattr(execution, "result", None)},
        )


class MonitorLogPartialView(CapabilityRequiredMixin, View):
    capability_key = PermissionRule.PermissionKey.VIEW_SCANS

    def get(self, request, pk: int) -> HttpResponse:
        queryset = data_visibility_service.get_user_visible_executions(request.user, queryset=ScanExecution.objects.all())
        execution = get_object_or_404(queryset, pk=pk)
        logs = execution.event_logs.all()[:80]
        return render(
            request,
            "partials/live_log_panel.html",
            {"execution": execution, "logs": logs},
        )


class ExecutionCancelView(CapabilityRequiredMixin, View):
    capability_key = PermissionRule.PermissionKey.CONTROL_SCAN_EXECUTIONS

    def post(self, request, pk: int) -> HttpResponse:
        queryset = data_visibility_service.get_user_visible_executions(request.user, queryset=ScanExecution.objects.all())
        execution = get_object_or_404(queryset, pk=pk)
        cancel_execution(execution, message=f"Cancelled by {request.user.username}.")
        messages.warning(request, f"{execution.execution_id} was cancelled.")
        return _redirect_back(request, reverse("scans:running"))


class ExecutionRetryView(CapabilityRequiredMixin, View):
    capability_key = PermissionRule.PermissionKey.CONTROL_SCAN_EXECUTIONS

    def post(self, request, pk: int) -> HttpResponse:
        queryset = data_visibility_service.get_user_visible_executions(request.user, queryset=ScanExecution.objects.all())
        execution = get_object_or_404(queryset, pk=pk)
        new_execution = retry_execution(execution)
        messages.success(request, f"Retry queued as {new_execution.execution_id}.")
        return _redirect_back(request, reverse("scans:running"))
