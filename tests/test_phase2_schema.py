from satori.phase2.schema import build_os_inference_skeleton, SCHEMA_VERSION, SIGNATURE_TABLE_VERSION


def test_schema_skeleton_has_required_fields():
    s = build_os_inference_skeleton('host:abc')
    assert s['os_inference_schema_version'] == SCHEMA_VERSION
    assert s['signature_table_version'] == SIGNATURE_TABLE_VERSION
    assert s['generated_by']
    assert s['host_id'] == 'host:abc'
    assert isinstance(s['candidates'], list)
    assert 'metadata' in s and 'protocol_count' in s['metadata']
