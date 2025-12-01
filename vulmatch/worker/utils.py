def add_vulmatch_extras(obj):
    if obj['type'] != 'vulnerability':
        return
    extras: dict = obj.setdefault('_vulmatch', {})
    for ref in obj.get('external_references', []):
        if ref['external_id'] == 'vulnStatus':
            extras['vulnStatus'] = ref['description']
    return