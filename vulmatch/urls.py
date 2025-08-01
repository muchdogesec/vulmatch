"""
URL configuration for vulmatch project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework import routers
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from vulmatch.server import views
from vulmatch.server.ctibutler_views import ctibutler_views

from django.http import JsonResponse
def handler404(*args, **kwargs):
    return JsonResponse(dict(code=404, message='non-existent page'), status=404)

def handler500(*args, **kwargs):
    return JsonResponse(dict(code=500, message='internal server error'), status=500)


API_VERSION = "v1"

router = routers.SimpleRouter(use_regex_path=False)
router.register("jobs", views.JobView, "jobs-view")
# arango-cti-processor
router.register("arango-cve-processor/<str:mode>", views.ACPView, "acp-view")
# nvd
router.register("cve", views.CveView, "cve-view")
router.register("cpe", views.CpeView, "cpe-view")

router.register("kev", views.KevView, "kev-view")
router.register("epss", views.EPSSView, "epss-view")

### more views
router.register("cwe", ctibutler_views.CweView, "cwe-view")
router.register("capec", ctibutler_views.CapecView, "capec-view")
router.register("attack", ctibutler_views.AttackView, "attack-view")

healthcheck = routers.SimpleRouter(use_regex_path=False)
healthcheck.register('', views.HealthCheck, "service-status-view")

urlpatterns = [
    path(f'api/healthcheck/', include(healthcheck.urls)),
    path(f'api/{API_VERSION}/', include(router.urls)),
    path('admin/', admin.site.urls),
    # YOUR PATTERNS
    path('api/schema/', views.SchemaViewCached.as_view(), name='schema'),
    # Optional UI:
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
