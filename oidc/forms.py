from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()


class ImportUserForm(forms.ModelForm):
    """Create a user without asking for a password (for SSO/OIDC imports)."""

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_unusable_password()  # no local password

        if commit:
            user.save()

        return user
