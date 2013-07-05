#!/usr/bin/python2
# -*- coding: utf-8 -*-

"""
Zabbix JSON-RPC/DB API
"""
import os
from setuptools import setup, find_packages, findall


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='zabbix',
    url='https://github.com/iavael/zabbix-python',
    version='0.1',
    license='GNU LGPL 2.1',
    author='Iavael',
    author_email='iavaelooeyt@gmail.com',
    description='Zabbix JSON-RPC/DB API',
    long_description=read('README'),
    packages=['zabbix'],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
)
