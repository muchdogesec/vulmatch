import requests
import time
import json

# Set the base URL and headers
base_url = 'http://127.0.0.1:8005/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Data for the CVE update
cve_data = {
    "last_modified_earliest": "2024-09-26",
    "last_modified_latest": "2024-09-26"
}

# Data for the CPE update
cpe_data = {
    "last_modified_earliest": "2021-01-01",
    "last_modified_latest": "2024-08-31"
}

# Data for the attack-enterprise update
attack_enterprise_data = {
    "version": "15_1"
}

# Data for the attack-ics update
attack_ics_data = {
    "version": "15_1"
}

# Data for the attack-mobile update
attack_mobile_data = {
    "version": "15_1"
}

# Data for the CAPEC update
capec_data = {
    "version": "3_9"
}

# Data for the CWE update
cwe_data = {
    "version": "4_15"
}

# Function to initiate the CVE update
def initiate_cve_update():
    print(f"Initiating CVE update with data: {json.dumps(cve_data, indent=2)}")
    response = requests.post(f'{base_url}/cve/', headers=headers, json=cve_data)
    
    if response.status_code == 201:
        print("CVE update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CVE update: {response.status_code} - {response.text}")
        return None

# Function to initiate the CPE update
def initiate_cpe_update():
    print(f"Initiating CPE update with data: {json.dumps(cpe_data, indent=2)}")
    response = requests.post(f'{base_url}/cpe/', headers=headers, json=cpe_data)
    
    if response.status_code == 201:
        print("CPE update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CPE update: {response.status_code} - {response.text}")
        return None

# Function to initiate the attack-enterprise update
def initiate_attack_enterprise_update():
    print(f"Initiating attack-enterprise update with data: {json.dumps(attack_enterprise_data, indent=2)}")
    response = requests.post(f'{base_url}/attack-enterprise/', headers=headers, json=attack_enterprise_data)
    
    if response.status_code == 201:
        print("attack-enterprise update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate attack-enterprise update: {response.status_code} - {response.text}")
        return None

# Function to initiate the attack-ics update
def initiate_attack_ics_update():
    print(f"Initiating attack-ics update with data: {json.dumps(attack_ics_data, indent=2)}")
    response = requests.post(f'{base_url}/attack-ics/', headers=headers, json=attack_ics_data)
    
    if response.status_code == 201:
        print("attack-ics update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate attack-ics update: {response.status_code} - {response.text}")
        return None

# Function to initiate the attack-mobile update
def initiate_attack_mobile_update():
    print(f"Initiating attack-mobile update with data: {json.dumps(attack_mobile_data, indent=2)}")
    response = requests.post(f'{base_url}/attack-mobile/', headers=headers, json=attack_mobile_data)
    
    if response.status_code == 201:
        print("attack-mobile update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate attack-mobile update: {response.status_code} - {response.text}")
        return None

# Function to initiate the CAPEC update
def initiate_capec_update():
    print(f"Initiating CAPEC update with data: {json.dumps(capec_data, indent=2)}")
    response = requests.post(f'{base_url}/capec/', headers=headers, json=capec_data)
    
    if response.status_code == 201:
        print("CAPEC update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CAPEC update: {response.status_code} - {response.text}")
        return None

# Function to initiate the CWE update
def initiate_cwe_update():
    print(f"Initiating CWE update with data: {json.dumps(cwe_data, indent=2)}")
    response = requests.post(f'{base_url}/cwe/', headers=headers, json=cwe_data)
    
    if response.status_code == 201:
        print("CWE update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CWE update: {response.status_code} - {response.text}")
        return None

# Function to check the job status
def check_job_status(job_id):
    job_url = f'{base_url}/jobs/{job_id}/'
    print(f"Checking job status for job ID: {job_id}")
    response = requests.get(job_url, headers=headers)
    if response.status_code == 200:
        job_status = response.json()
        print(f"Job status response: {json.dumps(job_status, indent=2)}")
        return job_status
    else:
        print(f"Failed to check job status: {response.status_code} - {response.text}")
        return None

# Function to monitor the jobs in sequence
def monitor_jobs():
    # Step 1: CVE update
    job_id = initiate_cve_update()
    if not job_id:
        return
    monitor_job_status(job_id, "CVE")

    # Step 2: CPE update
    job_id = initiate_cpe_update()
    if not job_id:
        return
    monitor_job_status(job_id, "CPE")

    # Step 3: attack-enterprise update
    job_id = initiate_attack_enterprise_update()
    if not job_id:
        return
    monitor_job_status(job_id, "attack-enterprise")

    # Step 4: attack-ics update
    job_id = initiate_attack_ics_update()
    if not job_id:
        return
    monitor_job_status(job_id, "attack-ics")

    # Step 5: attack-mobile update
    job_id = initiate_attack_mobile_update()
    if not job_id:
        return
    monitor_job_status(job_id, "attack-mobile")

    # Step 6: CAPEC update
    job_id = initiate_capec_update()
    if not job_id:
        return
    monitor_job_status(job_id, "CAPEC")

    # Step 7: CWE update
    job_id = initiate_cwe_update()
    if not job_id:
        return
    monitor_job_status(job_id, "CWE")

# Function to monitor a single job status
def monitor_job_status(job_id, job_name):
    print(f"{job_name} job initiated with ID: {job_id}")
    while True:
        job_status = check_job_status(job_id)
        if job_status:
            state = job_status['state']
            if state == 'pending':
                print(f"{job_name} job still pending. Retrying in 10 seconds...")
                time.sleep(10)
            else:
                print(f"{job_name} job completed with state: {state}")
                print(f"Full response: {json.dumps(job_status, indent=2)}")
                break
        else:
            print(f"Failed to retrieve {job_name} job status, stopping monitoring.")
            break

# Run the script
if __name__ == "__main__":
    monitor_jobs()
