from distutils.core import setup

setup(
    name='dns-monitor',
    version='0.1',
    packages=['dnsmon', 'dnsmon.tests', 'dnsmon.webapp'],
    url='',
    license='apache 2',
    author='3ev0',
    author_email='ipooters@gmail.com',
    description='Monitor domains/IPs for changes'
)
