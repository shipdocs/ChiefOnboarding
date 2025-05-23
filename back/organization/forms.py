import base64
import os
import pytz
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Div, Field, Layout, Submit
from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _


def generate_fernet_salt():
    """Generate a secure random Fernet salt."""
    return base64.urlsafe_b64encode(os.urandom(16)).decode()


def generate_secret_key():
    """Generate a secure random SECRET_KEY."""
    return get_random_string(length=64)


class InitalAdminAccountForm(UserCreationForm):
    name = forms.CharField(label=_("Name"), max_length=500)
    timezone = forms.ChoiceField(
        label=_("Timezone"), choices=[(x, x) for x in pytz.common_timezones]
    )
    language = forms.ChoiceField(
        label=_("Language"),
        choices=settings.LANGUAGES,
    )
    generate_security_keys = forms.BooleanField(
        label=_("Generate secure encryption keys"),
        help_text=_("Recommended: Generate secure random keys for encryption. These will be saved to your .env file."),
        initial=True,
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            HTML("<h2>Organization</h2>"),
            Div(
                Div(Field("name"), css_class="col-12"),
                Div(Field("timezone"), css_class="col-12"),
                Div(Field("language"), css_class="col-12"),
                css_class="row",
            ),
            HTML("<h2>Account</h2>"),
            Div(
                Div(Field("first_name"), css_class="col-6"),
                Div(Field("last_name"), css_class="col-6"),
                css_class="row",
            ),
            Div(
                Div(Field("email"), css_class="col-12"),
                Div(Field("password1"), css_class="col-12"),
                Div(Field("password2"), css_class="col-12"),
                css_class="row",
            ),
            Submit(name="submit", value="Submit"),
        )

    class Meta:
        model = get_user_model()
        fields = (
            "name",
            "timezone",
            "language",
            "first_name",
            "last_name",
            "email",
            "password1",
            "password2",
        )
