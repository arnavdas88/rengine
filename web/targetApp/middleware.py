from django.utils.functional import SimpleLazyObject

import threading

local = threading.local()


def get_actual_value(request):
    if request.user is None:
        return None
    return request.user #here should have value, so any code using request.user will work

class BaseMiddleware(object):

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        local.user = SimpleLazyObject(lambda: get_actual_value(request)) # request.user
        response = self.get_response(request)
        return response
    
    def process_request(self, request):
        local.user = SimpleLazyObject(lambda: get_actual_value(request))
