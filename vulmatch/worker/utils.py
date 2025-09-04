def add_cvss_score_to_cve_object(obj):
    if obj['type'] == 'vulnerability':
        obj['_cvss_base_score'] = get_primary_cvss(obj)

def get_primary_cvss(obj):
    x_cvss = list(obj.get('x_cvss', {}).values())
    if not x_cvss:
        return
    primary_cvss = x_cvss[-1]
    for cvss in reversed(x_cvss):
        if cvss['type'].lower() == 'primary':
            primary_cvss = cvss
            break
    if primary_cvss:
        return primary_cvss.get('base_score')
    return