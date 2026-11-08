import os

import pytest
from ruamel.yaml import YAML

HDR = {'X-CSRF-Token': 'testtoken', 'X-Requested-With': 'fetch'}

FORM = {'address': ':443', 'redirect_to': '', 'underscore_headers': '', 'trusted_ips': '',
        'forwarded_insecure': False, 'proxy_trusted_ips': '', 'proxy_insecure': False,
        'middlewares': '', 'tls_enabled': False, 'tls_cert_resolver': '', 'tls_options': '',
        'as_default': False, 'read_timeout': '60s', 'write_timeout': '', 'idle_timeout': ''}

WITH_PORT = ("entryPoints:\n  websecure:\n    address: ':443'\n"
             "    http3:\n      advertisedPort: 8443\n")
BARE_KEY = "entryPoints:\n  websecure:\n    address: ':443'\n    http3:\n"
NO_HTTP3 = "entryPoints:\n  websecure:\n    address: ':443'\n"


@pytest.fixture
def static_file():
    path = os.environ['STATIC_CONFIG_PATH']
    with open(path) as fh:
        original = fh.read()
    yield path
    with open(path, 'w') as fh:
        fh.write(original)


def _section(client, raw, http3, **extra):
    return client.post('/api/static/section', headers=HDR, json={
        'action': 'edit', 'section': 'entrypoints', 'name': 'websecure', 'old_name': 'websecure',
        'data': dict(FORM, http3=http3, **extra), 'current_raw': raw})


def _save(client, path, raw, http3, **extra):
    res = _section(client, raw, http3, **extra)
    assert res.status_code == 200, res.data
    saved = client.post('/api/static/config', headers=HDR, json={'content': res.get_json()['raw']})
    assert saved.status_code == 200, saved.data
    with open(path) as fh:
        return YAML(typ='safe').load(fh)['entryPoints']['websecure']


def test_save_keeps_http3_advertised_port(client, static_file):
    ep = _save(client, static_file, WITH_PORT, True)
    assert ep['http3'] == {'advertisedPort': 8443}
    assert ep['transport']['respondingTimeouts']['readTimeout'] == '60s'


def test_ticking_http3_writes_empty_block(client, static_file):
    assert _save(client, static_file, NO_HTTP3, True)['http3'] == {}


def test_ticking_http3_replaces_bare_key(client, static_file):
    assert _save(client, static_file, BARE_KEY, True)['http3'] == {}


def test_unticking_http3_removes_block(client, static_file):
    assert 'http3' not in _save(client, static_file, WITH_PORT, False)


def test_the_advertised_port_is_written(client, static_file):
    ep = _save(client, static_file, NO_HTTP3, True, http3_advertised_port='443')
    assert ep['http3'] == {'advertisedPort': 443}


def test_the_advertised_port_replaces_the_old_one(client, static_file):
    ep = _save(client, static_file, WITH_PORT, True, http3_advertised_port=' 443 ')
    assert ep['http3'] == {'advertisedPort': 443}


def test_the_advertised_port_replaces_a_bare_key(client, static_file):
    ep = _save(client, static_file, BARE_KEY, True, http3_advertised_port='443')
    assert ep['http3'] == {'advertisedPort': 443}


def test_a_number_from_an_api_client_is_accepted(client, static_file):
    ep = _save(client, static_file, NO_HTTP3, True, http3_advertised_port=8443)
    assert ep['http3'] == {'advertisedPort': 8443}


@pytest.mark.parametrize('empty', ['', '  ', None])
def test_an_empty_advertised_port_removes_it(client, static_file, empty):
    ep = _save(client, static_file, WITH_PORT, True, http3_advertised_port=empty)
    assert ep['http3'] == {}


def test_unticking_http3_drops_the_advertised_port_too(client, static_file):
    assert 'http3' not in _save(client, static_file, WITH_PORT, False, http3_advertised_port='443')


@pytest.mark.parametrize('bad', ['0', '65536', '-1', '44.3', 'https', '4 43', True])
def test_a_bad_advertised_port_is_refused(client, static_file, bad):
    with open(static_file) as fh:
        before = fh.read()
    res = _section(client, WITH_PORT, True, http3_advertised_port=bad)
    assert res.status_code == 400
    assert 'advertised port' in res.get_json()['error']
    with open(static_file) as fh:
        assert fh.read() == before


def _entry_points(**eps):
    lines = ['entryPoints:']
    for name, (address, http3) in eps.items():
        lines += [f'  {name}:', f"    address: '{address}'"]
        if http3:
            lines.append('    http3: {}')
    return '\n'.join(lines) + '\n'


def _edit(client, raw, name, address, http3=False, action='edit'):
    return client.post('/api/static/section', headers=HDR, json={
        'action': action, 'section': 'entrypoints', 'name': name, 'old_name': name,
        'data': dict(FORM, address=address, http3=http3, read_timeout=''), 'current_raw': raw})


def _on_disk(path):
    with open(path) as fh:
        return YAML(typ='safe').load(fh)


def _refused(res, *names):
    assert res.status_code == 400, res.data
    error = res.get_json()['error']
    assert all(n in error for n in names), error


def test_turning_on_http3_next_to_a_udp_entry_point_is_refused(client, static_file):
    before = _on_disk(static_file)
    raw = _entry_points(websecure=(':443', False), quic=(':443/udp', False))
    _refused(_edit(client, raw, 'websecure', ':443', http3=True), 'websecure', 'quic', '443')
    assert _on_disk(static_file) == before


def test_adding_a_udp_entry_point_on_the_http3_port_is_refused(client, static_file):
    before = _on_disk(static_file)
    raw = _entry_points(websecure=(':443', True))
    _refused(_edit(client, raw, 'quic', ':443/udp', action='add'), 'websecure', 'quic', '443')
    assert _on_disk(static_file) == before


@pytest.mark.parametrize('h3_address,udp_address', [
    (':443', ':443/udp'),
    (':443/tcp', ':443/UDP'),
    ('0.0.0.0:443', '[::1]:443/udp'),
    ('[::]:443', '10.0.0.5:443/udp'),
    ('10.0.0.5:443', ':443/udp'),
    ('10.0.0.5:443', '10.0.0.5:443/udp'),
    ('[::1]:443', '[0:0:0:0:0:0:0:1]:443/udp'),
])
def test_overlapping_addresses_clash(client, static_file, h3_address, udp_address):
    raw = _entry_points(quic=(udp_address, False))
    _refused(_edit(client, raw, 'websecure', h3_address, http3=True, action='add'), 'websecure', 'quic')


@pytest.mark.parametrize('h3_address,udp_address,http3', [
    ('1.2.3.4:443', '5.6.7.8:443/udp', True),
    (':443', ':8443/udp', True),
    (':443', ':443/udp', False),
])
def test_separate_listeners_save(client, static_file, h3_address, udp_address, http3):
    raw = _entry_points(quic=(udp_address, False))
    res = _edit(client, raw, 'websecure', h3_address, http3=http3, action='add')
    assert res.status_code == 200, res.data
    saved = client.post('/api/static/config', headers=HDR, json={'content': res.get_json()['raw']})
    assert saved.status_code == 200 and 'warnings' not in saved.get_json()
    eps = _on_disk(static_file)['entryPoints']
    assert eps['quic']['address'] == udp_address
    assert eps['websecure']['address'] == h3_address
    assert ('http3' in eps['websecure']) == http3


def test_reuse_port_on_both_is_still_refused(client, static_file):
    raw = ("entryPoints:\n  quic:\n    address: ':443/udp'\n    reusePort: true\n"
           "  websecure:\n    address: ':443'\n    reusePort: true\n")
    _refused(_edit(client, raw, 'websecure', ':443', http3=True), 'websecure', 'quic')


def test_an_existing_clash_does_not_block_other_entry_points(client, static_file):
    raw = _entry_points(websecure=(':443', True), quic=(':443/udp', False), web=(':80', False))
    assert _edit(client, raw, 'web', ':8080').status_code == 200


def test_turning_off_http3_clears_the_clash(client, static_file):
    raw = _entry_points(websecure=(':443', True), quic=(':443/udp', False))
    res = _edit(client, raw, 'websecure', ':443')
    assert res.status_code == 200, res.data
    client.post('/api/static/config', headers=HDR, json={'content': res.get_json()['raw']})
    assert 'http3' not in _on_disk(static_file)['entryPoints']['websecure']


@pytest.mark.parametrize('key', ['entryPoints', 'entrypoints'])
def test_the_raw_editor_saves_a_clash_with_a_warning(client, static_file, key):
    content = _entry_points(websecure=(':443', True), quic=(':443/udp', False)).replace('entryPoints', key)
    res = client.post('/api/static/config', headers=HDR, json={'content': content})
    assert res.status_code == 200, res.data
    warnings = res.get_json()['warnings']
    assert len(warnings) == 1 and 'websecure' in warnings[0] and 'quic' in warnings[0]
    with open(static_file) as fh:
        assert fh.read() == content.strip()


def test_the_raw_editor_does_not_warn_without_a_clash(client, static_file):
    content = _entry_points(websecure=(':443', True), quic=(':8443/udp', False))
    res = client.post('/api/static/config', headers=HDR, json={'content': content})
    assert res.status_code == 200 and 'warnings' not in res.get_json()
