"""
Renderers for the oidc app
"""

from django.views.decorators.debug import sensitive_variables

from rest_framework.renderers import TemplateHTMLRenderer


class SensitiveTemplateHTMLRenderer(TemplateHTMLRenderer):
    """
    Renders templates with the response data hidden from error reports.

    Django renders a response after the view returns, outside the view's
    sensitive_variables, and the data can hold an ID token.
    """

    @sensitive_variables()
    def render(self, data, accepted_media_type=None, renderer_context=None):
        return super().render(data, accepted_media_type, renderer_context)
