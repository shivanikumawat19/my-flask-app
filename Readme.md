Malicious File Detector
This is a Flask application that detects malicious files using the VirusTotal API. Users can upload files, and the application will analyze them to check if they are flagged as malicious by any antivirus engines.

Features
Upload files for analysis.
Check for malicious status based on VirusTotal results.
Displays detailed analysis results, including file name, size, description, and verdict from various antivirus engines.
Prerequisites
Docker: Ensure Docker is installed on your machine.
Python: If you want to run it locally without Docker, make sure you have Python 3.10 or later installed.
Flask: The Flask framework must be installed if running locally. You can install it via pip:
pip install Flask requests
Docker Setup
You can easily run this application using Docker. The Docker image is available on Docker Hub.

Pull the Docker Image
To pull the Docker image, run the following command:

docker pull prachibb/malicious-file-detector
Run the Docker Container
After pulling the image, you can run the container with this command:

docker run -p 5000:5000 prachibb/malicious-file-detector
This will start the Flask application and map port 5000 in the container to port 5000 on your localhost.

Usage
Access the Application
Open your web browser and go to:

http://localhost:5000
Upload a File
On the homepage, click on the file upload button.
Select the file you want to analyze.
Click the "Submit" button.
View the Results
After submitting the file, the application will analyze it, and you will be redirected to a results page displaying:

The file name
File size
Description of the file type
The file hash
Results from various antivirus engines, indicating whether they found the file to be malicious or not.
Code Explanation
Main Application Logic
The main file of the application is app.py, which includes:

Flask Application Setup: Configures the Flask app and sets up the necessary routes.
File Upload Handling: Uses Flask's request handling to accept file uploads and temporarily saves uploaded files for processing.
API Interaction: Communicates with the VirusTotal API to upload files and retrieve analysis results.
Results Display: Processes and renders results in an HTML template, providing a user-friendly interface for displaying analysis data.
Key Functions
index(): Main route that handles GET and POST requests, displays the upload form, and processes the uploaded files.
type(words): Simulates a typing effect for a better user experience in the UI.
Analysis Process
File Upload: Users can upload files through the web interface.
VirusTotal API Call: The uploaded file is sent to the VirusTotal API for analysis, and a unique SHA1 hash is returned to request the file's report.
Result Processing: The application checks the report for the file's status from various antivirus engines, aggregating and formatting the results for display.
HTML Templates
The application includes the following HTML templates:

index.html: The homepage where users can upload files.
result.html: The page that displays the results of the analysis.