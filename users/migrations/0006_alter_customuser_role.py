# Generated by Django 5.1.3 on 2024-12-09 11:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_customuser_reset_token_customuser_token_expiration'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('membre', 'Membre')], max_length=10),
        ),
    ]
