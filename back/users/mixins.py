from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import AccessMixin, UserPassesTestMixin
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from functools import wraps


class LoginRequiredMixin(AccessMixin):
    """
    Verify if user is logged in.
    If user requires mfa, then force it after logging in.
    """

    def dispatch(self, request, *args, **kwargs):
        # Make sure user is logged in
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        # User is logged in and therefore setting language
        request.session[settings.LANGUAGE_SESSION_KEY] = self.request.user.language

        # If MFA has been enabled, then force it
        if request.user.requires_otp and not request.session.get("passed_mfa", False):
            path = self.request.get_full_path()
            return redirect_to_login(path, "/mfa/")

        return super().dispatch(request, *args, **kwargs)


class ManagerPermMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_admin_or_manager


class AdminPermMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_admin


class IsAdminOrNewHireManagerMixin(UserPassesTestMixin):
    def test_func(self):
        new_hire = get_object_or_404(get_user_model(), id=self.kwargs.get("pk", -1))
        return self.request.user.is_admin or new_hire.manager == self.request.user


def manager_required(view_func):
    """
    Decorator for views that checks that the user is a manager or admin.
    Similar to the ManagerPermMixin but for function-based views.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseRedirect(settings.LOGIN_URL)

        if not hasattr(request.user, 'is_admin_or_manager') or not request.user.is_admin_or_manager:
            return HttpResponseRedirect('/')

        return view_func(request, *args, **kwargs)

    return _wrapped_view
