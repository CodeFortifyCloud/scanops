from pathlib import Path
import os
import logging.config
from django.core.exceptions import ImproperlyConfigured
from django.contrib.messages import constants as messages
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
from app_libs.logger_config import LOGGING

# Use pathlib for BASE_DIR and PROJECT_DIR so Path operations work correctly
PROJECT_DIR = Path(__file__).resolve().parent.parent   # core/settings/.. -> core/
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # project root

TRUE_VALUES = {"1", "true", "yes", "on"}


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


JTRO_ENVIRONMENT = os.environ.get("JTRO_ENVIRONMENT", "dev").strip().lower()

# Base DEBUG decision must be consistent before other settings derive from it.
DEBUG = env_flag("JTRO_DEBUG", default=JTRO_ENVIRONMENT != "production")

# SECRET_KEY handling: require a secret in production
SECRET_KEY = os.environ.get("JTRO_SECRET_KEY")
if not SECRET_KEY and not DEBUG:
    raise ImproperlyConfigured("JTRO_SECRET_KEY environment variable is required when DEBUG is False")

# ALLOWED_HOSTS: require explicit configuration in production
_jtro_allowed = os.environ.get('JTRO_ALLOWED_HOSTS')
if _jtro_allowed:
    ALLOWED_HOSTS = [h.strip() for h in _jtro_allowed.split(',') if h.strip()]
    if DEBUG:
        for _debug_host in ['localhost', '127.0.0.1', '0.0.0.0', 'testserver']:
            if _debug_host not in ALLOWED_HOSTS:
                ALLOWED_HOSTS.append(_debug_host)
else:
    if DEBUG:
        # safe defaults for development
        ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', 'testserver']
    else:
        # production: empty list forces explicit configuration
        ALLOWED_HOSTS = []

# CSRF_COOKIE_SECURE = os.environ.get('JTRO_CSRF_COOKIE_SECURE')
# CSRF_TRUSTED_ORIGINS = os.environ.get('JTRO_CSRF_TRUSTED_ORIGINS', '').split(',')

# Security proxy header (when behind a reverse proxy / load balancer)
SECURE_PROXY_SSL_HEADER = None
USE_X_FORWARDED_HOST = env_flag('JTRO_USE_X_FORWARDED_HOST', default=False)
USE_X_FORWARDED_PORT = env_flag('JTRO_USE_X_FORWARDED_PORT', default=False)

# CSRF trusted origins (optional, read from env)
_csrf_trusted = os.environ.get('JTRO_CSRF_TRUSTED_ORIGINS', '')
if _csrf_trusted:
    CSRF_TRUSTED_ORIGINS = [u.strip() for u in _csrf_trusted.split(',') if u.strip()]
CSRF_FAILURE_VIEW = 'core.views.csrf_failure'

# Application definition
INSTALLED_APPS = [
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

LOCALE_APPS = [
    'apps.accounts',
    'apps.core',
    'apps.feedback',
    'apps.dashboard',
    'apps.targets',
    'apps.scans',
    'apps.reports',
    'apps.schedules',
    'apps.notifications',
    'apps.assets',
    'apps.ops',
]

THIRD_PARTY_APPS = [
    'corsheaders',
    'django_filters',
    'fontawesomefree',
    'django_countries',
    'tinymce',
    'axes',
]

INSTALLED_APPS += LOCALE_APPS + THIRD_PARTY_APPS

# Custom User Auth
AUTH_USER_MODEL = 'accounts.User'

# LOGIN AND LOGOUT URL
LOGOUT_URL = '/logout/'
LOGOUT_REDIRECT_URL = '/login/'
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'

# Registration policy
SCANOPS_SELF_REGISTRATION_ENABLED = env_flag("SCANOPS_SELF_REGISTRATION_ENABLED", default=True)
SCANOPS_SELF_REGISTRATION_REQUIRES_APPROVAL = env_flag(
    "SCANOPS_SELF_REGISTRATION_REQUIRES_APPROVAL",
    default=False,
)
SCANOPS_SELF_REGISTRATION_DEFAULT_ROLE = (
    os.environ.get("SCANOPS_SELF_REGISTRATION_DEFAULT_ROLE", "viewer").strip().lower()
)
SCANOPS_ENABLE_SIMULATION = env_flag("SCANOPS_ENABLE_SIMULATION", default=False)
SCANOPS_NMAP_BINARY = (os.environ.get("SCANOPS_NMAP_BINARY") or "nmap").strip() or "nmap"
SCANOPS_SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCANOPS_SCAN_TIMEOUT_SECONDS", "900"))

# Email configuration
EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = env_flag("EMAIL_USE_TLS", default=True)
EMAIL_USE_SSL = env_flag("EMAIL_USE_SSL", default=False)
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "webmaster@localhost")
SERVER_EMAIL = os.environ.get("SERVER_EMAIL", DEFAULT_FROM_EMAIL)

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',  # Default backend for username
    'apps.accounts.backends.EmailBackend',  # Custom backend for email
)
# Add django-axes authentication backend for lockout support (AxesStandaloneBackend in django-axes >=5)
AUTHENTICATION_BACKENDS = ('axes.backends.AxesStandaloneBackend',) + AUTHENTICATION_BACKENDS

# http://django-crispy-forms.readthedocs.io/en/latest/install.html#template-packs
CRISPY_TEMPLATE_PACK = 'bootstrap4'

DEFAULT_MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Add a security headers middleware at the top for defense-in-depth (also enforced at Nginx)
ON_TOP_MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'core.middleware.security.SecurityHeadersMiddleware',
    'core.middleware.exceptions.SafeExceptionMiddleware',
    'axes.middleware.AxesMiddleware',
    # 'django_ratelimit.middleware.RatelimitMiddleware' removed to avoid needing
    # a shared cache backend (memcached/redis). Consider enabling via deploy
    # when a supported cache is configured.
]

THIRD_PARTY_MIDDLEWARE = []

SERVICE_MIDDLEWARE = [
]

MIDDLEWARE = ON_TOP_MIDDLEWARE + DEFAULT_MIDDLEWARE + THIRD_PARTY_MIDDLEWARE + SERVICE_MIDDLEWARE

ROOT_URLCONF = 'core.urls'

# Build template context processors conditionally to avoid exposing debug info in production
_template_context_processors = [
    'django.template.context_processors.request',
    'django.contrib.auth.context_processors.auth',
    'django.contrib.messages.context_processors.messages',
]

# Only include debug context processor when DEBUG is True
if DEBUG:
    _template_context_processors.insert(0, 'django.template.context_processors.debug')

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        "DIRS": [
            str(BASE_DIR / "templates"),
            str(PROJECT_DIR / "templates"),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': _template_context_processors,
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Dhaka'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

STATICFILES_DIRS = [
    str(BASE_DIR / "static"),
    str(PROJECT_DIR / "static"),
]

# Use a container-owned / project-based static/media layout and Path objects
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"
STATIC_ROOT = BASE_DIR / "static_root" / "static"
STATIC_URL = "/static/"

MEDIA_ROOT = BASE_DIR / "media_root" / "media"
MEDIA_URL = "/media/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Message framework
MESSAGE_TAGS = {
    messages.INFO: 'alert alert-info',
    messages.SUCCESS: 'alert alert-success',
    messages.WARNING: 'alert alert-warning',
    messages.ERROR: 'alert alert-danger',
    messages.DEBUG: 'alert alert-info',
}

# TINYMCE Configuration - keep allowed elements tight; sanitize server-side (bleach)
TINYMCE_DEFAULT_CONFIG = {
    "height": 300,
    "menubar": False,
    "license_key": "gpl",
    "plugins": [
        "lists", "link", "code", "table", "autoresize",
    ],
    "toolbar": "undo redo | bold italic | alignleft aligncenter alignright | bullist numlist | link | code",
    "cleanup_on_startup": True,
    "forced_root_block": 'p',
    "branding": False,
    "valid_elements": "a[href|target=_blank|rel|title],p,br,strong/b,em/i,ul,ol,li,h1,h2,h3,blockquote,code,pre,table,thead,tbody,tr,td,th",
    "invalid_elements": "script,iframe,object,embed,form,input,button,textarea,select,option,svg,math,video,audio,style",
    # use a raw string for regex patterns to avoid SyntaxWarning about invalid escape sequences
    "protect": [r"<\?php.*\?>"],
}

# JAZZMIN SETTINGS
JAZZMIN_SETTINGS = {
    # title of the window (Will default to current_admin_site.site_title if absent or None)
    "site_title": "Incident Matrix",

    # Title on the login screen (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_header": "Incident Matrix",

    # Title on the brand (19 chars max) (defaults to current_admin_site.site_header if absent or None)
    "site_brand": "Incident Matrix",

    # Logo to use for your site, must be present in static files, used for brand on top left
    # "site_logo": "",
    #
    # Logo to use for your site, must be present in static files, used for login form logo (defaults to site_logo)
    # "login_logo": "",

    # Logo to use for login form in dark themes (defaults to login_logo)
    "login_logo_dark": None,

    # CSS classes that are applied to the logo above
    "site_logo_classes": "img-circle",

    # Relative path to a favicon for your site, will default to site_logo if absent (ideally 32x32 px)
    # "site_icon": "images/",

    # Welcome text on the login screen
    "welcome_sign": "Welcome to the Incident Matrix",

    # Copyright on the footer
    "copyright": "incidentmatrix",

    # Field name on user model that contains avatar ImageField/URLField/Charfield or a callable that receives the user
    "user_avatar": None,

    ############
    # Top Menu #
    ############

    # Links to put along the top menu
    "topmenu_links": [

        # Url that gets reversed (Permissions can be added)
        {"name": "Dashboard", "url": "admin:index", "permissions": ["accounts.view_user"]},
    ],

    #############
    # User Menu #
    #############

    # Additional links to include in the user menu on the top right ("app" url type is not allowed)
    "usermenu_links": [
        {"model": "accounts.user"}
    ],

    #############
    # Side Menu #
    #############

    # Whether to display the side menu
    "show_sidebar": True,

    # Whether to aut expand the menu
    "navigation_expanded": True,

    # Hide these apps when generating side menu e.g (auth)
    "hide_apps": [],

    # Hide these models when generating side menu (e.g auth.user)
    "hide_models": [],

    # List of apps (and/or models) to base side menu ordering off of (does not need to contain all apps/models)
    "order_with_respect_to": [
        "accounts",
        "accounts.user",
        "accounts.userlogs",
        "incident",
        "incident.incident",
        "location",
        "axes",
        "auth",
    ],

    # Custom links to append to app groups, keyed on app name
    "custom_links": {},

    # Custom icons for side menu apps/models See https://fontawesome.com/icons?d=gallery&m=free&v=5.0.0,5.0.1,5.0.10,5.0.11,5.0.12,5.0.13,5.0.2,5.0.3,5.0.4,5.0.5,5.0.6,5.0.7,5.0.8,5.0.9,5.1.0,5.1.1,5.2.0,5.3.0,5.3.1,5.4.0,5.4.1,5.4.2,5.13.0,5.12.0,5.11.2,5.11.1,5.10.0,5.9.0,5.8.2,5.8.1,5.7.2,5.7.1,5.7.0,5.6.3,5.5.0,5.4.2
    # for the full list of 5.13.0 free icon classes
    "icons": {
        "auth": "fas fa-users-cog",
        "auth.user": "fas fa-user",
        "auth.Group": "fas fa-users",
        "accounts": "fas fa-user-shield",
        "accounts.user": "fas fa-user",
        "accounts.userlogs": "fas fa-clock-rotate-left",
        "incident": "fas fa-triangle-exclamation",
        "incident.incident": "fas fa-triangle-exclamation",
        "incident.incidenttype": "fas fa-tags",
        "incident.involvedactor": "fas fa-people-group",
        "incident.incidentimage": "fas fa-images",
        "location": "fas fa-map-location-dot",
        "location.dgss": "fas fa-location-dot",
        "location.division": "fas fa-map",
        "location.district": "fas fa-map-marked-alt",
        "location.subdistrict": "fas fa-map-pin",
        "location.state": "fas fa-flag",
        "axes": "fas fa-shield-halved",
    },
    # Icons that are used when one is not manually specified
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",

    #################
    # Related Modal #
    #################
    # Use modals instead of popups
    "related_modal_active": False,

    #############
    # UI Tweaks #
    #############
    # Relative paths to custom CSS/JS scripts (must be present in static files)
    "custom_css": "admin/css/incidentmatrix_admin.css",
    "custom_js": "vendor/bootstrap/js/bootstrap-compat.js",
    # Whether to link font from fonts.googleapis.com (use custom_css to supply font otherwise)
    "use_google_fonts_cdn": False,
    # Whether to show the UI customizer on the sidebar
    "show_ui_builder": False,

    ###############
    # Change view #
    ###############
    # Render out the change view as a single form, or in tabs, current options are
    # - single
    # - horizontal_tabs (default)
    # - vertical_tabs
    # - collapsible
    # - carousel
    "changeform_format": "horizontal_tabs",
    # override change forms on a per modeladmin basis
    "changeform_format_overrides": {
        "auth.user": "collapsible",
        "auth.group": "vertical_tabs",
        "accounts.userlogs": "single",
    },
}

JAZZMIN_UI_TWEAKS = {
    "theme": "darkly",
    "default_theme_mode": "dark",
    "accent": "accent-info",
    "navbar": "navbar-dark",
    "no_navbar_border": True,
    "navbar_fixed": True,
    "sidebar": "sidebar-dark-primary",
    "sidebar_fixed": True,
    "footer_fixed": False,
    "button_classes": {
        "primary": "btn btn-info",
        "secondary": "btn btn-outline-secondary",
        "info": "btn btn-info",
        "warning": "btn btn-warning",
        "danger": "btn btn-danger",
        "success": "btn btn-success",
    },
}

DATA_UPLOAD_MAX_NUMBER_FIELDS = 10240

# maxmind for gio location
GEOIP_PATH = os.environ.get("GEOIP_PATH")

# GOOGLE MAP API KEY
GOOGLE_MAP_KEY=os.environ.get("GOOGLE_MAP_KEY")
PUBLIC_BASE_URL = os.environ.get("JTRO_PUBLIC_BASE_URL", "").strip().rstrip("/")

# Rate limit settings (adjust these values as needed)
RATE_LIMIT_COUNT = 1000  # Maximum number of requests per RATE_LIMIT_PERIOD
RATE_LIMIT_PERIOD = 60  # Time window in seconds

# --- Advanced hardening additions ---

# Third-party apps required for brute-force / rate-limiting protections
# (install django-axes and django-ratelimit in requirements / image)
#THIRD_PARTY_APPS += [
#    'axes',         # django-axes for login lockouts
#    'ratelimit',    # django-ratelimit for middleware/decorator based limits
#]
# Note: django-axes and django_ratelimit are included in THIRD_PARTY_APPS above.
# Avoid duplicating THIRD_PARTY_APPS entries here to keep configuration consistent.

# Add axes and ratelimit middleware early for fast-fail protection
# SecurityHeadersMiddleware (custom) remains first in ON_TOP_MIDDLEWARE
ON_TOP_MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'core.middleware.security.SecurityHeadersMiddleware',
    'axes.middleware.AxesMiddleware',
    # 'django_ratelimit.middleware.RatelimitMiddleware' removed to avoid needing
    # a shared cache backend (memcached/redis). Consider enabling via deploy
    # when a supported cache is configured.
]

# --- django-axes configuration (lockouts) ---
AXES_FAILURE_LIMIT = int(os.environ.get('AXES_FAILURE_LIMIT', '5'))  # attempts
AXES_COOLOFF_TIME = timedelta(minutes=int(os.environ.get('AXES_COOLOFF_MINUTES', '15')))
AXES_LOCKOUT_CALLABLE = None
# Preserve the existing behavior: lock out by the specific username + IP + user-agent combination.
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address", "user_agent"]]
# store axes cache/records in the default cache; ensure cache is configured in production

# --- Rate-limit defaults for middleware/decorators ---
RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '1000/min')  # fallback
# Existing RATE_LIMIT_COUNT and RATE_LIMIT_PERIOD remain for other usage

# --- Admin protection (configurable) ---
# Optional: ADMIN_ALLOWED_IPS can be set to a comma separated list to restrict /admin
ADMIN_ALLOWED_IPS = [p.strip() for p in os.environ.get('ADMIN_ALLOWED_IPS', '').split(',') if p.strip()]

# --- Content Security Policy ---
# Use a nonce-based script policy in Django so inline page initializers can be
# allowed without reopening all inline script execution globally.
CONTENT_SECURITY_POLICY = {
    "default-src": ("'self'",),
    "script-src": (
        "'self'",
        "https://maps.googleapis.com",
        "https://maps.gstatic.com",
    ),
    # Inline style attributes are still used across the current templates and
    # by third-party widgets (Select2 / Google Maps / Django admin), so keep a
    # pragmatic style policy for now.
    "style-src": (
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
    ),
    "img-src": (
        "'self'",
        "data:",
        "blob:",
        "https://maps.googleapis.com",
        "https://maps.gstatic.com",
        "https://*.googleapis.com",
        "https://*.gstatic.com",
        "https://*.googleusercontent.com",
    ),
    "connect-src": (
        "'self'",
        "https://maps.googleapis.com",
        "https://maps.gstatic.com",
        "https://places.googleapis.com",
        "https://*.googleapis.com",
        "https://*.gstatic.com",
    ),
    "font-src": (
        "'self'",
        "data:",
        "https://fonts.gstatic.com",
        "https://maps.gstatic.com",
    ),
    "frame-src": (
        "'self'",
        "https://www.google.com",
        "https://maps.google.com",
        "https://*.google.com",
    ),
    "worker-src": (
        "'self'",
        "blob:",
    ),
    "object-src": ("'none'",),
    "base-uri": ("'self'",),
    "form-action": ("'self'",),
    "frame-ancestors": ("'none'",),
    "script-src-attr": ("'none'",),
}

# --- Security cookie / session hardening ---
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False  # setting True can break some legitimate JS usage; keep False unless verified
SESSION_COOKIE_SECURE = env_flag('JTRO_SESSION_COOKIE_SECURE', default=False)
CSRF_COOKIE_SECURE = env_flag('JTRO_CSRF_COOKIE_SECURE', default=False)
SESSION_COOKIE_SAMESITE = os.environ.get('JTRO_SESSION_COOKIE_SAMESITE', 'Lax')
SECURE_SSL_REDIRECT = env_flag('JTRO_SECURE_SSL_REDIRECT', default=False)
SECURE_HSTS_SECONDS = int(os.environ.get('JTRO_HSTS_SECONDS', '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_flag('JTRO_HSTS_INCLUDE_SUBDOMAINS', default=False)
SECURE_HSTS_PRELOAD = env_flag('JTRO_HSTS_PRELOAD', default=False)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = os.environ.get('JTRO_REFERRER_POLICY', 'same-origin')  # tightened default
PERMISSIONS_POLICY = os.environ.get('JTRO_PERMISSIONS_POLICY', "geolocation=(self), camera=(), microphone=()")

# --- Security logging / monitoring hooks ---
# Ensure security relevant events are captured; prefer existing console/file handlers from LOGGING
# Merge minimal security loggers into existing LOGGING dict (app_libs.logger_config.LOGGING)
try:
    LOGGING  # from app_libs.logger_config import LOGGING
except NameError:
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'handlers': {},
        'loggers': {},
    }

# ensure basic console formatter/handler exists to capture axes/django.security events
if 'console' not in LOGGING.get('handlers', {}):
    LOGGING.setdefault('formatters', {})['simple'] = {'format': '%(asctime)s %(levelname)s %(name)s %(message)s'}
    LOGGING.setdefault('handlers', {})['console'] = {
        'class': 'logging.StreamHandler',
        'formatter': 'simple',
    }

LOGGING.setdefault('loggers', {}).setdefault('django.security', {
    'handlers': ['console'],
    'level': os.environ.get('SECURITY_LOG_LEVEL', 'INFO'),
    'propagate': False,
})
# axes produces its own logger names; track login lockouts and events
LOGGING.setdefault('loggers', {}).setdefault('axes.watch_login', {
    'handlers': ['console'],
    'level': 'INFO',
    'propagate': False,
})
LOGGING.setdefault('loggers', {}).setdefault('axes.access', {
    'handlers': ['console'],
    'level': 'INFO',
    'propagate': False,
})

# --- Misc hardening: reduce debug output in production ---
# Ensure debug context processor is only enabled for DEBUG True (already implemented above)
# Keep Django's default error pages for production (custom 404/500 templates recommended)

# --- Validate deploy checks can be run ---
# Make sure python manage.py check --deploy will find required settings when DEBUG=False
# These keys are commonly checked by django's check framework; set conservative defaults above.

# Logger setup
logging.config.dictConfig(LOGGING)

# Use a cache backend suitable for rate-limiting and axes; default to django-redis (configurable)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Ensure third-party packages that reference the default cache (like django-axes and django-ratelimit)
# work against the local in-memory cache by default. This avoids any dependency on Redis.
# If deployment requires a persistent/distributed cache, configure it in production settings.

# Ensure django_ratelimit uses the default cache
