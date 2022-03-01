import os
import requests
import itertools

from datetime import datetime

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django_celery_beat.models import PeriodicTask, IntervalSchedule, ClockedSchedule
from django.utils import timezone
from django.conf import settings
from django.core import serializers

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from startScan.models import *
from targetApp.models import *
from scanEngine.models import EngineType, Configuration
from reNgine.tasks import initiate_scan, create_scan_activity
from reNgine.celery import app

from reNgine.common_func import *
from api.serializers import DomainSerializer, EmailSerializer, EngineSerializer, PeriodicTaskSerializer, ScanHistorySerializer, ScanActivitySerializer, VulnerabilitySerializer


@api_view()
@permission_classes([IsAuthenticated])
def scan_history(request):
    scan_history = ScanHistory.objects.filter(domain__in = Domain.objects.all())
    host = scan_history.all().order_by('-start_scan_date')
    host = ScanHistorySerializer(host, many=True)
    context = {'scan_history_active': 'active', "scan_history": host.data}
    return Response(context)


@api_view()
@permission_classes([IsAuthenticated])
def detail_scan(request, id=None):
    context = {}
    if id:
        context['scan_history_id'] = id
        context['subdomain_count'] = Subdomain.objects.filter(
            scan_history__id=id).values('name').distinct().count()
        context['alive_count'] = Subdomain.objects.filter(
            scan_history__id=id).values('name').distinct().filter(
            http_status__exact=200).count()
        context['important_count'] = Subdomain.objects.filter(
            scan_history__id=id).values('name').distinct().filter(
            is_important=True).count()

        context['scan_activity'] = ScanActivitySerializer(ScanActivity.objects.filter(
            scan_of__id=id).order_by('-time'), many=True).data

        context['endpoint_count'] = EndPoint.objects.filter(
            scan_history__id=id).values('http_url').distinct().count()
        context['endpoint_alive_count'] = EndPoint.objects.filter(
            scan_history__id=id, http_status__exact=200).values('http_url').distinct().count()

        history = get_object_or_404(ScanHistory, id=id)
        context['history'] = ScanHistorySerializer(history).data


        info_count = Vulnerability.objects.filter(
            scan_history__id=id, severity=0).count()
        low_count = Vulnerability.objects.filter(
            scan_history__id=id, severity=1).count()
        medium_count = Vulnerability.objects.filter(
            scan_history__id=id, severity=2).count()
        high_count = Vulnerability.objects.filter(
            scan_history__id=id, severity=3).count()
        critical_count = Vulnerability.objects.filter(
            scan_history__id=id, severity=4).count()

        context['vulnerability_list'] = VulnerabilitySerializer(Vulnerability.objects.filter(
            scan_history__id=id).order_by('-severity').all()[:20], many=True).data

        context['total_vulnerability_count'] = info_count + low_count + \
            medium_count + high_count + critical_count
        context['info_count'] = info_count
        context['low_count'] = low_count
        context['medium_count'] = medium_count
        context['high_count'] = high_count
        context['critical_count'] = critical_count
        context['scan_history_active'] = 'active'

        emails = Email.objects.filter(
            emails__in=ScanHistory.objects.filter(
                id=id))

        context['exposed_count'] = emails.exclude(password__isnull=True).count()

        context['email_count'] = emails.count()

        context['employees_count'] = Employee.objects.filter(
            employees__in=ScanHistory.objects.filter(id=id)).count()

        domain_id = ScanHistory.objects.filter(id=id)

        context['most_recent_scans'] = ScanHistory.objects.filter(domain__id=domain_id[0].domain.id).order_by('-start_scan_date')[:5]
        context['most_recent_scans'] = ScanHistorySerializer(context['most_recent_scans'], many=True).data

        if domain_id:
            domain_id = domain_id[0].domain.id
            scan_history = ScanHistory.objects.filter(domain=domain_id).filter(subdomain_discovery=True).filter(id__lte=id).filter(scan_status=2)
            if scan_history.count() > 1:
                last_scan = scan_history.order_by('-start_scan_date')[1]
                context['last_scan'] = last_scan

    # badge count for gfs
    if history.used_gf_patterns:
        count_gf = {}
        for gf in history.used_gf_patterns.split(','):
            count_gf[gf] = EndPoint.objects.filter(scan_history__id=id, matched_gf_patterns__icontains=gf).count()
            context['matched_gf_count'] = count_gf
    return Response(context)

@api_view()
@permission_classes([IsAuthenticated])
def all_subdomains(request):
    context = {}
    
    scan_history = ScanHistory.objects.filter(domain__in = Domain.objects.all())
    subdomain = Subdomain.objects.filter(scan_history__in=scan_history)

    context['subdomain_count'] = subdomain.values('name').distinct().count()
    context['alive_count'] = subdomain.values('name').distinct().filter(
        http_status__exact=200).count()
    context['important_count'] = subdomain.values('name').distinct().filter(
        is_important=True).count()

    context['scan_history_active'] = 'active'

    return Response(context)

@api_view()
@permission_classes([IsAuthenticated])
def detail_vuln_scan(request, id=None):
    if id:
        # history = get_object_or_404(ScanHistory, id=id)
        scan_history = ScanHistory.objects.filter(domain__in = Domain.objects.all())
        context = {'scan_history_id': id}
        history = ScanHistorySerializer(scan_history.get(id=id))

        history = history.data
        context['history'] = history

    else:
        context = {'vuln_scan_active': 'true'}
    return Response(context)

@api_view()
@permission_classes([IsAuthenticated])
def visualise(request, id):
    scan_history = ScanHistory.objects.filter(domain__in = Domain.objects.all())
    scan_history = scan_history.get(id=id)
    scan_history = ScanHistorySerializer(scan_history)
    context = {
        'scan_id': id,
        'scan_history': scan_history.data,
    }
    return Response(context)



def create_scan_object(host_id, engine_type):
    '''
    create task with pending status so that celery task will execute when
    threads are free
    '''
    # get current time
    current_scan_time = timezone.now()
    # fetch engine and domain object
    engine_object = EngineType.objects.get(pk=engine_type)
    domain = Domain.objects.get(pk=host_id)
    task = ScanHistory()
    task.scan_status = -1
    task.domain = domain
    task.scan_type = engine_object
    task.start_scan_date = current_scan_time
    task.save()
    # save last scan date for domain model
    domain.start_scan_date = current_scan_time
    domain.save()
    return Response(task.id)

# POST
@api_view()
@permission_classes([IsAuthenticated])
def start_scan_ui(request, domain_id):
    domain = get_object_or_404(Domain, id=domain_id)
    if request.method == "POST":
        # get imported subdomains
        imported_subdomains = [subdomain.rstrip() for subdomain in request.POST['importSubdomainTextArea'].split('\n')]
        imported_subdomains = [subdomain for subdomain in imported_subdomains if subdomain]

        out_of_scope_subdomains = [subdomain.rstrip() for subdomain in request.POST['outOfScopeSubdomainTextarea'].split('\n')]
        out_of_scope_subdomains = [subdomain for subdomain in out_of_scope_subdomains if subdomain]
        # get engine type
        engine_type = request.POST['scan_mode']
        scan_history_id = create_scan_object(domain_id, engine_type)
        # start the celery task
        celery_task = initiate_scan.apply_async(
            args=(
                domain_id,
                scan_history_id,
                0,
                engine_type,
                imported_subdomains,
                out_of_scope_subdomains
                ))
        ScanHistory.objects.filter(
            id=scan_history_id).update(
            celery_id=celery_task.id)
        messages.add_message(
            request,
            messages.INFO,
            'Scan Started for ' +
            domain.name)
        return HttpResponseRedirect(reverse('api_scan_history'))
    engine = EngineType.objects.order_by('id')
    custom_engine_count = EngineType.objects.filter(
        default_engine=False).count()
    context = {
        'scan_history_active': 'active',
        'domain': DomainSerializer(domain).data,
        'engines': EngineSerializer(engine, many=True).data,
        'custom_engine_count': custom_engine_count}
    return Response(context)

# POST
@api_view()
@permission_classes([IsAuthenticated])
def start_multiple_scan(request):
    # domain = get_object_or_404(Domain, id=host_id)
    domain_text = ""
    if request.method == "POST":
        if request.POST.get('scan_mode', 0):
            # if scan mode is available, then start the scan
            # get engine type
            engine_type = request.POST['scan_mode']
            list_of_domains = request.POST['list_of_domain_id']
            for domain_id in list_of_domains.split(","):
                # start the celery task
                scan_history_id = create_scan_object(domain_id, engine_type)
                celery_task = initiate_scan.apply_async(
                    args=(domain_id, scan_history_id, 0, engine_type))
                ScanHistory.objects.filter(
                    id=scan_history_id).update(
                    celery_id=celery_task.id)
            messages.add_message(
                request,
                messages.INFO,
                'Scan Started for multiple targets')
            return HttpResponseRedirect(reverse('api_scan_history'))
        else:
            # this else condition will have post request from the scan page
            # containing all the targets id
            list_of_domain_name = []
            list_of_domain_id = []
            for key, value in request.POST.items():
                print(value)
                if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                    domain = get_object_or_404(Domain, id=value)
                    list_of_domain_name.append(domain.name)
                    list_of_domain_id.append(value)
            domain_text = ", ".join(list_of_domain_name)
            domain_ids = ",".join(list_of_domain_id)
    engine = EngineType.objects
    custom_engine_count = EngineType.objects.filter(
        default_engine=False).count()
    context = {
        'scan_history_active': 'active',
        'engines': engine,
        'domain_list': domain_text,
        'domain_ids': domain_ids,
        'custom_engine_count': custom_engine_count}
    return Response(context)

# POST
@api_view()
@permission_classes([IsAuthenticated])
def start_organization_scan(request, id):
    organization = get_object_or_404(Organization, id=id)
    if request.method == "POST":
        # get engine type
        engine_type = request.POST['scan_mode']
        for domain in organization.get_domains():
            scan_history_id = create_scan_object(domain.id, engine_type)
            # start the celery task
            celery_task = initiate_scan.apply_async(
                args=(domain.id,
                    scan_history_id,
                    0,
                    engine_type,
                    None
                ))
            ScanHistory.objects.filter(
                id=scan_history_id).update(
                celery_id=celery_task.id)
        messages.add_message(
            request,
            messages.INFO,
            'Scan Started for {} domains in organization {}'.format(
                len(organization.get_domains()),
                organization.name
            )
        )
        return HttpResponseRedirect(reverse('api_scan_history'))
    engine = EngineType.objects.order_by('id')
    custom_engine_count = EngineType.objects.filter(
        default_engine=False).count()
    domain_list = organization.get_domains()
    context = {
        'organization_data_active': 'true',
        'list_organization_li': 'active',
        'organization': organization,
        'engines': engine,
        'domain_list': domain_list,
        'custom_engine_count': custom_engine_count}
    return Response(context)
