
def add_cvss_score_to_cve_object(obj):
    if obj['type'] == 'vulnerability':
        x_cvss = list(obj.get('x_cvss', {}).values())
        if not x_cvss:
            return
        primary_cvss = x_cvss[-1]
        for cvss in reversed(x_cvss):
            if cvss['type'].lower() == 'primary':
                primary_cvss = cvss
                break
        if primary_cvss:
            obj['_cvss_base_score'] = primary_cvss['base_score']