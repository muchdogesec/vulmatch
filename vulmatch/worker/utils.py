def add_vulmatch_extras(obj):
    if obj['type'] != 'vulnerability':
        return
    extras: dict = obj.setdefault('_vulmatch', {})
    for ref in obj.get('external_references', []):
        source_name = ref['source_name']
        match source_name:
            case 'vulnStatus':
                extras['vulnStatus'] = ref['description']
            case 'cwe':
                extras.setdefault('weaknesses', []).append(ref['external_id'])
    return