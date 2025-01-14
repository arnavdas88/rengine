# Generated by Django 3.2.4 on 2022-02-28 06:54

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('scanEngine', '0001_initial'),
        ('targetApp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Dork',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('type', models.CharField(blank=True, max_length=500, null=True)),
                ('description', models.CharField(blank=True, max_length=1500, null=True)),
                ('url', models.CharField(blank=True, max_length=1500, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Email',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('address', models.CharField(blank=True, max_length=200, null=True)),
                ('password', models.CharField(blank=True, max_length=200, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=1000, null=True)),
                ('designation', models.CharField(blank=True, max_length=1000, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='EndPoint',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('http_url', models.CharField(max_length=5000)),
                ('content_length', models.IntegerField(blank=True, default=0, null=True)),
                ('page_title', models.CharField(blank=True, max_length=1000, null=True)),
                ('http_status', models.IntegerField(blank=True, default=0, null=True)),
                ('content_type', models.CharField(blank=True, max_length=100, null=True)),
                ('discovered_date', models.DateTimeField(blank=True, null=True)),
                ('response_time', models.FloatField(blank=True, null=True)),
                ('webserver', models.CharField(blank=True, max_length=1000, null=True)),
                ('is_default', models.BooleanField(blank=True, default=False, null=True)),
                ('matched_gf_patterns', models.CharField(blank=True, max_length=2000, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='IpAddress',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('address', models.CharField(blank=True, max_length=100, null=True)),
                ('is_cdn', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Port',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('number', models.IntegerField(default=0)),
                ('service_name', models.CharField(blank=True, max_length=100, null=True)),
                ('description', models.CharField(blank=True, max_length=1000, null=True)),
                ('is_uncommon', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='ScanHistory',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('start_scan_date', models.DateTimeField()),
                ('scan_status', models.IntegerField()),
                ('results_dir', models.CharField(blank=True, max_length=100)),
                ('celery_id', models.CharField(blank=True, max_length=100)),
                ('subdomain_discovery', models.BooleanField(default=False, null=True)),
                ('dir_file_search', models.BooleanField(default=False, null=True)),
                ('port_scan', models.BooleanField(default=False, null=True)),
                ('fetch_url', models.BooleanField(default=False, null=True)),
                ('vulnerability_scan', models.BooleanField(default=False, null=True)),
                ('osint', models.BooleanField(default=False, null=True)),
                ('screenshot', models.BooleanField(default=True, null=True)),
                ('stop_scan_date', models.DateTimeField(null=True)),
                ('used_gf_patterns', models.CharField(blank=True, max_length=500, null=True)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='targetApp.domain')),
                ('dorks', models.ManyToManyField(related_name='dorks', to='startScan.Dork')),
                ('emails', models.ManyToManyField(related_name='emails', to='startScan.Email')),
                ('employees', models.ManyToManyField(related_name='employees', to='startScan.Employee')),
                ('scan_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='scanEngine.enginetype')),
            ],
        ),
        migrations.CreateModel(
            name='Subdomain',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=1000)),
                ('is_imported_subdomain', models.BooleanField(default=False)),
                ('is_important', models.BooleanField(blank=True, default=False, null=True)),
                ('http_url', models.CharField(blank=True, max_length=1000, null=True)),
                ('screenshot_path', models.CharField(blank=True, max_length=1000, null=True)),
                ('http_header_path', models.CharField(blank=True, max_length=1000, null=True)),
                ('directory_json', models.JSONField(blank=True, null=True)),
                ('checked', models.BooleanField(blank=True, default=False, null=True)),
                ('discovered_date', models.DateTimeField(blank=True, null=True)),
                ('cname', models.CharField(blank=True, max_length=1500, null=True)),
                ('is_cdn', models.BooleanField(blank=True, default=False, null=True)),
                ('http_status', models.IntegerField(default=0)),
                ('content_type', models.CharField(blank=True, max_length=100, null=True)),
                ('response_time', models.FloatField(blank=True, null=True)),
                ('webserver', models.CharField(blank=True, max_length=1000, null=True)),
                ('content_length', models.IntegerField(blank=True, default=0, null=True)),
                ('page_title', models.CharField(blank=True, max_length=1000, null=True)),
                ('ip_addresses', models.ManyToManyField(related_name='ip_addresses', to='startScan.IpAddress')),
                ('scan_history', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.scanhistory')),
                ('target_domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='targetApp.domain')),
            ],
        ),
        migrations.CreateModel(
            name='Technology',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=100, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('template_used', models.CharField(max_length=100)),
                ('name', models.CharField(max_length=400)),
                ('severity', models.IntegerField()),
                ('description', models.CharField(blank=True, max_length=10000, null=True)),
                ('extracted_results', models.CharField(blank=True, max_length=3000, null=True)),
                ('reference', models.CharField(blank=True, max_length=3000, null=True)),
                ('tags', models.CharField(blank=True, max_length=1000, null=True)),
                ('http_url', models.CharField(max_length=8000, null=True)),
                ('matcher_name', models.CharField(blank=True, max_length=400, null=True)),
                ('discovered_date', models.DateTimeField(null=True)),
                ('open_status', models.BooleanField(blank=True, default=True, null=True)),
                ('hackerone_report_id', models.CharField(blank=True, max_length=50, null=True)),
                ('endpoint', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='startScan.endpoint')),
                ('scan_history', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.scanhistory')),
                ('subdomain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='startScan.subdomain')),
                ('target_domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='targetApp.domain')),
            ],
        ),
        migrations.AddField(
            model_name='subdomain',
            name='technologies',
            field=models.ManyToManyField(related_name='technologies', to='startScan.Technology'),
        ),
        migrations.CreateModel(
            name='ScanActivity',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=1000)),
                ('time', models.DateTimeField()),
                ('status', models.IntegerField()),
                ('scan_of', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.scanhistory')),
            ],
        ),
        migrations.CreateModel(
            name='MetaFinderDocument',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('doc_name', models.CharField(blank=True, max_length=1000, null=True)),
                ('url', models.CharField(blank=True, max_length=5000, null=True)),
                ('title', models.CharField(blank=True, max_length=1000, null=True)),
                ('author', models.CharField(blank=True, max_length=1000, null=True)),
                ('producer', models.CharField(blank=True, max_length=1000, null=True)),
                ('creator', models.CharField(blank=True, max_length=1000, null=True)),
                ('os', models.CharField(blank=True, max_length=1000, null=True)),
                ('http_status', models.IntegerField(blank=True, default=0, null=True)),
                ('creation_date', models.CharField(blank=True, max_length=1000, null=True)),
                ('modified_date', models.CharField(blank=True, max_length=1000, null=True)),
                ('scan_history', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.scanhistory')),
                ('subdomain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='startScan.subdomain')),
                ('target_domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='targetApp.domain')),
            ],
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='ports',
            field=models.ManyToManyField(related_name='ports', to='startScan.Port'),
        ),
        migrations.AddField(
            model_name='endpoint',
            name='scan_history',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.scanhistory'),
        ),
        migrations.AddField(
            model_name='endpoint',
            name='subdomain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='startScan.subdomain'),
        ),
        migrations.AddField(
            model_name='endpoint',
            name='target_domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='targetApp.domain'),
        ),
        migrations.AddField(
            model_name='endpoint',
            name='technologies',
            field=models.ManyToManyField(related_name='technology', to='startScan.Technology'),
        ),
    ]
