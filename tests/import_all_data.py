import requests
import time

# Set the base URL and headers
base_url = 'http://127.0.0.1:8005/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Data for the first API request
data = {
    "last_modified_earliest": "2024-01-01",
    "last_modified_latest": "2023-08-31"
}

# Function to make the POST request to the /cpe/ endpoint
def initiate_cpe_update():
    response = requests.post(f'{base_url}/cpe/', headers=headers, json=data)
    if response.status_code == 200:
        return response.json()['id']  # Extract and return the 'id'
    else:
        print(f"Failed to initiate cpe-update: {response.status_code} - {response.text}")
        return None

# Function to check the job status
def check_job_status(job_id):
    job_url = f'{base_url}/jobs/{job_id}/'
    response = requests.get(job_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to check job status: {response.status_code} - {response.text}")
        return None

# Main function to initiate the update and poll the job status
def monitor_cpe_update():
    job_id = initiate_cpe_update()
    if not job_id:
        return

    print(f"Job initiated with ID: {job_id}")

    # Keep checking the job status until it's no longer 'pending'
    while True:
        job_status = check_job_status(job_id)
        if job_status:
            state = job_status['state']
            if state == 'pending':
                print("Job still pending. Retrying in 10 seconds...")
                time.sleep(10)  # Wait 10 seconds before retrying
            else:
                print(f"Job completed with state: {state}")
                print(f"Full response: {job_status}")
                break

# Run the script
if __name__ == "__main__":
    monitor_cpe_update()
