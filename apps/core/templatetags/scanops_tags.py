from __future__ import annotations

from django import template

from apps.ops.services import data_visibility_service, permission_service


register = template.Library()


@register.filter
def split_tags(value: str) -> list[str]:
    if not value:
        return []
    return [tag.strip() for tag in value.split(",") if tag.strip()]


@register.filter
def target_type_badge(value: str) -> str:
    styles = {
        "ip": "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20",
        "domain": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20",
        "cidr": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "ipv6": "bg-purple-500/10 text-purple-300 border border-purple-500/20",
    }
    return styles.get(value, "bg-slate-700/30 text-slate-300 border border-slate-700")


@register.filter
def status_badge(value: str) -> str:
    styles = {
        "active": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "inactive": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "approved": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "pending": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "super_admin": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20",
        "security_admin": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "analyst": "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20",
        "operator": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "viewer": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "monitoring": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "archived": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "restricted": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "online": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "degraded": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "offline": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "healthy": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "warning": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "unknown": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "queued": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20",
        "running": "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20",
        "completed": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "failed": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "cancelled": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "generated": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "waiting": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "assigned": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "processing": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "done": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "error": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "triggered": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "skipped": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "pending": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "validated": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "draft": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "rejected": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "enabled": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "disabled": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "ports_added": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "ports_removed": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "service_changed": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "os_changed": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "asset_created": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20",
        "asset_updated": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
    }
    return styles.get(value, "bg-slate-700/30 text-slate-300 border border-slate-700")


@register.filter
def risk_badge(value: str) -> str:
    styles = {
        "info": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
        "low": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "medium": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "high": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "critical": "bg-rose-500/20 text-rose-200 border border-rose-500/40",
    }
    return styles.get(value, "bg-slate-700/30 text-slate-300 border border-slate-700")


@register.filter
def port_state_badge(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized == "open":
        return "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
    if normalized == "closed":
        return "bg-rose-500/10 text-rose-300 border border-rose-500/20"
    if "filtered" in normalized:
        return "bg-amber-500/10 text-amber-300 border border-amber-500/20"
    return "bg-slate-500/10 text-slate-300 border border-slate-500/20"


@register.filter
def severity_badge(value: str) -> str:
    styles = {
        "info": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "success": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "warning": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "error": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
    }
    return styles.get(value, "bg-slate-700/30 text-slate-300 border border-slate-700")


@register.filter
def report_type_badge(value: str) -> str:
    styles = {
        "executive_summary": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20",
        "technical_report": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "comparison_report": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "per_host_report": "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20",
    }
    return styles.get(value, "bg-slate-700/30 text-slate-300 border border-slate-700")


@register.filter
def notification_type_badge(value: str) -> str:
    styles = {
        "scan_completed": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
        "scan_failed": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "schedule_triggered": "bg-blue-500/10 text-blue-300 border border-blue-500/20",
        "report_generated": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/20",
        "asset_changed": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
        "policy_alert": "bg-rose-500/10 text-rose-300 border border-rose-500/20",
        "system_alert": "bg-slate-500/10 text-slate-300 border border-slate-500/20",
    }
    return styles.get(value, "bg-slate-700/30 text-slate-300 border border-slate-700")


@register.filter
def dict_get(value: dict, key):
    if not isinstance(value, dict):
        return None
    return value.get(key)


@register.filter
def has_capability(user, capability_key: str) -> bool:
    return permission_service.user_has_permission(user, capability_key)


@register.filter
def is_super_admin(user) -> bool:
    return permission_service.is_super_admin(user)


@register.filter
def role_slug(user) -> str:
    return permission_service.get_user_role_slug(user) or ""


@register.filter
def role_name(user) -> str:
    return permission_service.get_user_role_name(user)


@register.filter
def can_view_all_data(user) -> bool:
    return data_visibility_service.user_can_view_all_data(user)
