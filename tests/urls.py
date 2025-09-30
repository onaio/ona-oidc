from django.urls import include, path

urlpatterns = [
    path("", include("oidc.urls", namespace="oidc")),
]

