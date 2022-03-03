from rest_framework import serializers
from rest_framework.exceptions import APIException

from targetApp.models import *
from startScan.models import *
from scanEngine.models import *
from targetApp.forms import *
from reNgine.common_func import *

class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = ['id', 'name', 'h1_team_handle', 'description']
    
    def validate(self, attrs):
        name = attrs['name']
        if Domain.objects.filter(name=name).count() > 0:
            # raise forms.ValidationError("{} target/domain already exists".format(name))
            raise APIException({'details': "{} target/domain already exists".format(name)})

        return super().validate(attrs)
