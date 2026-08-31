import pytest
from vuln.cpe_normalizer import normalize_technology, sanitize_version, build_cpe_23


def test_sanitize_version():
    assert sanitize_version("2.4.49 (Ubuntu)") == "2.4.49"
    assert sanitize_version("v1.24.0-release") == "1.24.0"
    assert sanitize_version("9.6p1-1ubuntu1") == "9.6p1"
    assert sanitize_version("8.0.35-0ubuntu0.22.04.1") == "8.0.35"
    assert sanitize_version("") == ""


def test_normalize_apache_httpd():
    identity = normalize_technology(raw_name="httpd", raw_version="2.4.49")
    assert identity.vendor == "apache"
    assert identity.product == "http_server"
    assert identity.version == "2.4.49"
    assert identity.cpe_23 == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert "Apache HTTP Server" in identity.display_name


def test_normalize_apache_coyote():
    identity = normalize_technology(raw_name="Apache-Coyote", raw_version="1.1", banner="Server: Apache-Coyote/1.1")
    assert identity.vendor == "apache"
    assert identity.product == "tomcat"
    assert identity.version == "1.1"
    assert identity.cpe_23 == "cpe:2.3:a:apache:tomcat:1.1:*:*:*:*:*:*:*"
    assert "Apache Tomcat" in identity.display_name


def test_normalize_nginx_banner():
    identity = normalize_technology(raw_name="Nginx Web Server", raw_version="1.24.0", banner="Server: nginx/1.24.0 (Ubuntu)")
    assert identity.vendor == "nginx"
    assert identity.product == "nginx"
    assert identity.version == "1.24.0"
    assert identity.cpe_23 == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"


def test_normalize_openssh():
    identity = normalize_technology(raw_name="OpenSSH", raw_version="9.6p1", banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18")
    assert identity.vendor == "openbsd"
    assert identity.product == "openssh"
    assert identity.version == "9.6p1"
    assert identity.cpe_23 == "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"


def test_normalize_postgresql_service_hint():
    identity = normalize_technology(raw_name="postgres", service_hint="postgresql", raw_version="16.1")
    assert identity.vendor == "postgresql"
    assert identity.product == "postgresql"
    assert identity.version == "16.1"
    assert identity.cpe_23 == "cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*"


def test_normalize_operating_system():
    identity = normalize_technology(raw_name="Ubuntu Linux", raw_version="22.04")
    assert identity.category == "o"
    assert identity.vendor == "canonical"
    assert identity.product == "ubuntu_linux"
    assert identity.cpe_23 == "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*"
