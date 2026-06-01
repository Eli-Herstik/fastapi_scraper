"""Network request/response interceptor for Playwright."""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from playwright.async_api import Request, Response

from . import auth_analyzer

logger = logging.getLogger(__name__)


class NetworkInterceptor:
    """Intercept and store network requests/responses."""

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.source_url: str = ""
        self.navigation_depth: int = 0

    def set_context(self, source_url: str, navigation_depth: int = 0):
        self.source_url = source_url
        self.navigation_depth = navigation_depth

    async def handle_request(self, request: Request) -> Dict[str, Any]:
        return {
            'url': request.url,
            'method': request.method,
            'headers': request.headers,
            'post_data': await self._get_post_data(request),
            'resource_type': request.resource_type,
            'timestamp': int(datetime.now().timestamp() * 1000),
            'source_url': self.source_url,
            'navigation_depth': self.navigation_depth,
            'authentication': auth_analyzer.detect_authentication(request.headers, request.url),
        }

    async def handle_response(
        self,
        request_data: Dict[str, Any],
        response: Optional[Response] = None,
    ) -> Dict[str, Any]:
        try:
            if response is None:
                raise ValueError("Response is None")
            if not hasattr(response, 'status'):
                raise ValueError(f"Response object is invalid: {type(response)}")

            status = response.status if hasattr(response, 'status') else 0
            try:
                headers = response.headers
                if hasattr(headers, '__await__'):
                    headers = await headers
            except Exception:
                headers = {}

            response_data = {
                'status': status,
                'headers': headers,
                'timestamp': int(datetime.now().timestamp() * 1000),
            }

            if status == 401:
                self._apply_auth_challenge(headers, request_data, response_data)

            if status in (301, 302, 303, 307, 308):
                self._apply_idp_redirect(headers, request_data, response_data)

            request_data['response'] = response_data
            self.requests.append(request_data)
            return request_data
        except Exception as e:
            logger.error("Error handling response for %s: %s", request_data.get('url'), e, exc_info=True)
            status = 0
            if response and hasattr(response, 'status'):
                try:
                    status = response.status
                except Exception:
                    status = 0

            request_data['response'] = {
                'status': status,
                'error': str(e),
                'timestamp': int(datetime.now().timestamp() * 1000),
            }
            if request_data not in self.requests:
                self.requests.append(request_data)
            return request_data

    def _apply_auth_challenge(self, headers, request_data, response_data) -> None:
        auth_challenge = self._get_header_value(headers, 'WWW-Authenticate')
        if not auth_challenge:
            return
        response_data['auth_challenge'] = auth_challenge
        if request_data.get('authentication', 'None') in ['None', 'anonymous']:
            lower = auth_challenge.lower()
            if lower.startswith('basic'):
                request_data['authentication'] = f"Required: Basic ({auth_challenge})"
            elif lower.startswith('bearer'):
                request_data['authentication'] = f"Required: OAuth/Bearer ({auth_challenge})"
            elif lower.startswith('negotiate'):
                request_data['authentication'] = f"Required: Negotiate ({auth_challenge})"
            else:
                request_data['authentication'] = f"Required: {auth_challenge}"

    def _apply_idp_redirect(self, headers, request_data, response_data) -> None:
        location = self._get_header_value(headers, 'Location')
        if not location:
            return
        idp = auth_analyzer.detect_idp_redirect(location)
        if idp:
            response_data['idp_redirect'] = idp
            request_data['authentication'] = f"IdP Redirect: {idp}"

    @staticmethod
    def _get_header_value(headers: Dict[str, str], name: str) -> Optional[str]:
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return None

    @staticmethod
    async def _get_post_data(request: Request) -> Optional[Dict[str, Any]]:
        if request.method not in ['POST', 'PUT', 'PATCH']:
            return None
        try:
            post_data = request.post_data
            if post_data:
                try:
                    return json.loads(post_data)
                except json.JSONDecodeError:
                    if 'application/x-www-form-urlencoded' in request.headers.get('content-type', ''):
                        from urllib.parse import parse_qs
                        return dict(parse_qs(post_data))
                    return {'raw': post_data}
        except Exception:
            pass
        return None

    def get_requests(self) -> List[Dict[str, Any]]:
        return self.requests.copy()

    def clear(self):
        self.requests.clear()
