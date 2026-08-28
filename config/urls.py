"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.1/topics/http/urls/
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
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),  # SFR-001, SFR-002
    path('api/users/', include('accounts.user_urls')),  # SEC-003 (관리자용 사용자 관리)
    path('api/', include('projects.urls')),  # SFR-004, SFR-005, SFR-006
    path('api/', include('analysis.urls')),  # SFR-007, SFR-008, SFR-009
    path('api/', include('catalog.urls')),  # SFR-013, SFR-014, SFR-016, SFR-017
]
