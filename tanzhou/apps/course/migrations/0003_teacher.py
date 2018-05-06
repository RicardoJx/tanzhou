# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-05-02 08:03
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('course', '0002_buy_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='Teacher',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('teacher_name', models.CharField(max_length=30, verbose_name='老师名')),
                ('teacher_des', models.CharField(max_length=100, verbose_name='老师描述')),
                ('teacher_img', models.ImageField(upload_to='img/tea/&Y/%m', verbose_name='老师图')),
                ('teacher_course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='course.Course', verbose_name='课程名')),
            ],
            options={
                'verbose_name': '老师',
                'verbose_name_plural': '老师',
            },
        ),
    ]
