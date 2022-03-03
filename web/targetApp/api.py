import validators
import csv
import io
import os

from datetime import timedelta
from operator import and_, or_
from functools import reduce
from django import http
from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from django.db.models import Count, Q
from django.utils.safestring import mark_safe

from targetApp.models import *
from startScan.models import *
from scanEngine.models import *
from targetApp.forms import *
from reNgine.common_func import *

from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from rest_framework.response import Response
from rest_framework import authentication, permissions

from targetApp.serializers import *


class Target(APIView):
    """
    List all snippets, or create a new snippet.
    """

    authentication_classes = [authentication.TokenAuthentication]
    # def get(self, request, format=None):
    #     snippets = Snippet.objects.all()
    #     serializer = SnippetSerializer(snippets, many=True)
    #     return Response(serializer.data)

    def post(self, request, format=None):
        add_target_form = TargetSerializer(request.data or None)

        if add_target_form.is_valid(raise_exception=True):
            Domain.objects.create(
                **add_target_form.cleaned_data,
                insert_date=timezone.now())
            messages.add_message(
                request,
                messages.INFO,
                'Target domain ' +
                add_target_form.cleaned_data['name'] +
                ' added successfully')
            return JsonResponse({'status':'success'})
