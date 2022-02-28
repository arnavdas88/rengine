
from django.db import models
from django.utils import timezone
from django.apps import apps

from django.contrib.auth import get_user_model

from .middleware import local
NULL_AND_BLANK = {'null': True, 'blank': True}


class ModelManager(models.Manager):
    def get_queryset(self):
        if hasattr(local, 'user'):
            return super().get_queryset().filter(creator=local.user)
        else:
            return super().get_queryset()

class BaseModel(models.Model):
    created = models.DateTimeField(default=timezone.now)
    modified = models.DateTimeField(default=timezone.now)
    creator = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, **NULL_AND_BLANK)

    objects = ModelManager()

    def save(self, *args, **kwargs):
        if self.pk is None and hasattr(local, 'user'):
            self.creator = local.user
            # self.created = timezone.now()
            # self.modified = timezone.now()
        return super(BaseModel, self).save(*args, **kwargs)

    class Meta:
        abstract = True

class Organization(BaseModel):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300, unique=True)
    description = models.TextField(blank=True, null=True)
    insert_date = models.DateTimeField()
    domains = models.ManyToManyField('Domain', related_name='domains')

    def __str__(self):
        return self.name

    def get_domains(self):
        return Domain.objects.filter(domains__in=Organization.objects.filter(id=self.id))


class Domain(BaseModel):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=300, unique=True)
    h1_team_handle = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    insert_date = models.DateTimeField()
    start_scan_date = models.DateTimeField(null=True)

    def get_organization(self):
        return Organization.objects.filter(domains__id=self.id)

    def get_recent_scan_id(self):
        ScanHistory = apps.get_model('startScan.ScanHistory')
        obj = ScanHistory.objects.filter(domain__id=self.id).order_by('-id')
        if obj:
            return obj[0].id

    def __str__(self):
        return self.name
