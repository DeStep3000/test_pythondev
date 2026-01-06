from api.views import (DocumentsCreateView, LoginView, LogoutView, MeView,
                       RefreshView, RegisterView, ReportsView,
                       SoftDeleteMeView)
from django.urls import path

urlpatterns = [
    path("auth/register", RegisterView.as_view()),
    path("auth/login", LoginView.as_view()),
    path("auth/refresh", RefreshView.as_view()),
    path("auth/logout", LogoutView.as_view()),
    path("auth/me", MeView.as_view()),
    path("auth/me/delete", SoftDeleteMeView.as_view()),

    path("mock/reports", ReportsView.as_view()),
    path("mock/documents", DocumentsCreateView.as_view()),
]
