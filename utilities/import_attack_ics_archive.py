import argparse
import requests
import time

# Base URLs of the API
BASE_URL = 'http://127.0.0.1:8005/api/v1/attack-ics/'
JOB_STATUS_URL = 'http://127.0.0.1:8005/api/v1/jobs/'

# List of all available versions
ALL_VERSIONS = [
    "8.0", "8.1", "8.2", "9.0", "10.0", "10.1", "11.0", 
    "11.1", "11.2", "11.3", "12.0", "12.1", "13.0", "13.1", "14.0", "14.1", 
    "15.0", "15.1"
]

# Function to post version and get job ID
def post_version(version):
    url = BASE_URL
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Replace . with _ for version formatting
    version_str = str(version).replace('.', '_')
    data = {
        "version": version_str
    }
    
    print(f"Sending POST request for version: {version_str}")
    response = requests.post(url, headers=headers, json=data)
    
    # Print full request and response for debugging
    print(f"Request Data: {data}")
    print(f"Response: {response.status_code}, {response.text}")
    
    # Accept both 200 OK and 201 Created as successful responses
    if response.status_code in [200, 201]:
        response_data = response.json()
        return response_data['id']  # Return job ID
    else:
        raise Exception(f"Failed to submit version {version}: {response.status_code} - {response.text}")

# Function to check job status
def check_job_status(job_id):
    url = f"{JOB_STATUS_URL}{job_id}/"
    
    while True:
        print(f"Checking job status for job ID: {job_id}")
        response = requests.get(url)
        
        # Print full request and response for debugging
        print(f"Job Status Response: {response.status_code}, {response.text}")
        
        if response.status_code == 200:
            response_data = response.json()
            if response_data['state'] == 'completed':
                print(f"Job {job_id} completed.")
                return
            else:
                print(f"Job {job_id} still in progress. Waiting...")
                time.sleep(30)  # Wait 30 seconds before checking again
        else:
            raise Exception(f"Failed to check job status: {response.status_code} - {response.text}")

def main():
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="Post versions and track job status.")
    parser.add_argument('versions', nargs='*', type=float, help="List of versions to post as numbers (e.g., 14.1, 15.0). If not provided, all versions will be imported.")
    args = parser.parse_args()

    # Use provided versions or default to all if none are provided
    versions = sorted(args.versions) if args.versions else sorted(ALL_VERSIONS)

    # Post each version and check job status
    for version in versions:
        try:
            job_id = post_version(version)
            check_job_status(job_id)
        except Exception as e:
            print(f"Error occurred: {e}")
            break

if __name__ == "__main__":
    main()
