"""Wire Playwright page/context events to the NetworkInterceptor, deduplicating by URL."""
import logging
from datetime import datetime
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Page

from .interceptor import NetworkInterceptor

logger = logging.getLogger(__name__)


class RequestCapture:
    """Bridge Playwright events to NetworkInterceptor with de-duplication."""

    def __init__(self, interceptor: NetworkInterceptor, start_url: str):
        self.interceptor = interceptor
        self.start_host = urlparse(start_url).netloc
        self.pending_requests: dict = {}
        self.captured_urls: set = set()

    def attach(self, page: Page, context: BrowserContext) -> None:
        """Attach listeners to the main page and future pages opened in the context."""
        self._setup_page(page)
        context.on('page', self._setup_page)

    def _is_external_url(self, url: str) -> bool:
        try:
            return urlparse(url).netloc != self.start_host
        except Exception:
            return True

    def _setup_page(self, target_page: Page) -> None:
        target_page.on('request', self._on_request)
        target_page.on('response', self._on_response)
        target_page.on('requestfailed', self._on_request_failed)
        target_page.on('requestfinished', self._on_request_finished)

    async def _on_request(self, request) -> None:
        url_key = request.url
        if not self._is_external_url(url_key):
            return
        if url_key not in self.pending_requests:
            self.pending_requests[url_key] = await self.interceptor.handle_request(request)

    async def _on_response(self, response) -> None:
        request = response.request
        url_key = request.url
        if not self._is_external_url(url_key):
            return
        if url_key in self.captured_urls:
            return

        request_data = self.pending_requests.get(url_key)
        if not request_data:
            request_data = await self.interceptor.handle_request(request)

        try:
            await self.interceptor.handle_response(request_data, response)
        except Exception as e:
            logger.error("Error handling response for %s: %s", url_key, e, exc_info=True)
            self.captured_urls.add(url_key)
        finally:
            self.pending_requests.pop(url_key, None)

    async def _on_request_failed(self, request) -> None:
        url_key = request.url
        if not self._is_external_url(url_key):
            return
        if url_key in self.captured_urls:
            return

        request_data = await self.interceptor.handle_request(request)
        request_data['response'] = {
            'status': 0,
            'error': 'Request failed',
            'timestamp': int(datetime.now().timestamp() * 1000),
        }
        self.interceptor.requests.append(request_data)
        self.captured_urls.add(url_key)

    async def _on_request_finished(self, request) -> None:
        url_key = request.url
        if not self._is_external_url(url_key):
            return
        if url_key in self.captured_urls:
            return

        request_data = self.pending_requests.get(url_key) or await self.interceptor.handle_request(request)

        try:
            response = await request.response()
            if response and hasattr(response, 'status'):
                try:
                    await self.interceptor.handle_response(request_data, response)
                except Exception as body_error:
                    logger.warning("Could not read body for %s: %s", url_key, body_error)
                    request_data['response'] = {
                        'status': getattr(response, 'status', 0),
                        'error': f'Body not available: {body_error}',
                        'timestamp': int(datetime.now().timestamp() * 1000),
                    }
                    self.interceptor.requests.append(request_data)
            else:
                request_data['response'] = {
                    'status': 0,
                    'note': 'Request finished but no response available',
                    'timestamp': int(datetime.now().timestamp() * 1000),
                }
                self.interceptor.requests.append(request_data)
        except Exception as e:
            request_data['response'] = {
                'status': 0,
                'note': f'Request finished but response not accessible: {e}',
                'timestamp': int(datetime.now().timestamp() * 1000),
            }
            self.interceptor.requests.append(request_data)
        finally:
            self.captured_urls.add(url_key)
