import os
import logging
import json
from datetime import datetime
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import config

logger = logging.getLogger(__name__)

# Google Drive API Scopes
SCOPES = [
    'https://www.googleapis.com/auth/drive.metadata.readonly'
]

# Initialize Google Drive API client
drive_service = None
credentials_path = os.environ.get('GOOGLE_CREDENTIALS_PATH')
token_path = os.path.join(config.DATA_DIR, 'drive_token.json')

def initialize_drive_client():
    """
    Initialize the Google Drive API client
    
    This checks for stored credentials and if not found, guides through OAuth flow
    
    Returns:
        bool: True if initialized successfully, False otherwise
    """
    global drive_service
    
    if not credentials_path:
        logger.error("GOOGLE_CREDENTIALS_PATH not set. Cannot initialize Drive.")
        return False
    
    try:
        creds = None
        # Try to load existing token
        if os.path.exists(token_path):
            logger.debug("Loading existing Drive token")
            with open(token_path, 'r') as token:
                creds = Credentials.from_authorized_user_info(json.load(token), SCOPES)
        
        # Check if credentials are valid
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logger.debug("Refreshing expired Drive token")
                creds.refresh(Request())
            else:
                logger.debug("Starting new OAuth flow for Drive")
                flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            logger.debug("Saving Drive token")
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
        
        # Build the service
        drive_service = build('drive', 'v3', credentials=creds)
        logger.debug("Google Drive client initialized successfully")
        return True
    
    except Exception as e:
        logger.error(f"Error initializing Google Drive client: {str(e)}")
        return False

def list_files(folder_id=None, max_results=20):
    """
    List files in Google Drive, optionally in a specific folder
    
    Args:
        folder_id (str, optional): The ID of the folder to list files from. Defaults to None (root).
        max_results (int, optional): Maximum number of results. Defaults to 20.
    
    Returns:
        list: List of files
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return []
    
    try:
        query = ""
        if folder_id:
            query = f"'{folder_id}' in parents"
        
        results = drive_service.files().list(
            q=query,
            pageSize=max_results,
            fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)"
        ).execute()
        
        items = results.get('files', [])
        
        if not items:
            logger.debug("No files found.")
            return []
        
        files = []
        for item in items:
            files.append({
                'id': item['id'],
                'name': item['name'],
                'mimeType': item['mimeType'],
                'createdTime': item['createdTime'],
                'modifiedTime': item['modifiedTime'],
                'isFolder': item['mimeType'] == 'application/vnd.google-apps.folder'
            })
        
        return files
    
    except Exception as e:
        logger.error(f"Error listing files: {str(e)}")
        return []

def search_files(query_text, max_results=20):
    """
    Search for files in Google Drive
    
    Args:
        query_text (str): Text to search for in file names and content
        max_results (int, optional): Maximum number of results. Defaults to 20.
    
    Returns:
        list: List of matching files
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return []
    
    try:
        # Search in file names
        query = f"name contains '{query_text}'"
        
        results = drive_service.files().list(
            q=query,
            pageSize=max_results,
            fields="nextPageToken, files(id, name, mimeType, createdTime, modifiedTime)"
        ).execute()
        
        items = results.get('files', [])
        
        if not items:
            logger.debug(f"No files matching '{query_text}' found.")
            return []
        
        files = []
        for item in items:
            files.append({
                'id': item['id'],
                'name': item['name'],
                'mimeType': item['mimeType'],
                'createdTime': item['createdTime'],
                'modifiedTime': item['modifiedTime'],
                'isFolder': item['mimeType'] == 'application/vnd.google-apps.folder'
            })
        
        return files
    
    except Exception as e:
        logger.error(f"Error searching files: {str(e)}")
        return []

def get_file(file_id):
    """
    Get metadata for a specific file
    
    Args:
        file_id (str): The ID of the file to get
    
    Returns:
        dict: The file metadata or None if not found
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return None
    
    try:
        file = drive_service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, createdTime, modifiedTime, webViewLink, parents"
        ).execute()
        
        file_data = {
            'id': file['id'],
            'name': file['name'],
            'mimeType': file['mimeType'],
            'createdTime': file['createdTime'],
            'modifiedTime': file['modifiedTime'],
            'webViewLink': file.get('webViewLink', ''),
            'parents': file.get('parents', []),
            'isFolder': file['mimeType'] == 'application/vnd.google-apps.folder'
        }
        
        return file_data
    
    except Exception as e:
        logger.error(f"Error getting file {file_id}: {str(e)}")
        return None

def upload_file(file_path, parent_folder_id=None, description=None):
    """
    [DISABLED - READ ONLY MODE] Upload a file to Google Drive
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        file_path (str): Path to the file to upload
        parent_folder_id (str, optional): ID of the folder to upload to. Defaults to root.
        description (str, optional): Description of the file. Defaults to None.
    
    Returns:
        dict: Always returns None (disabled)
    """
    logger.warning("File upload is disabled in read-only mode")
    return None

def create_folder(folder_name, parent_folder_id=None):
    """
    [DISABLED - READ ONLY MODE] Create a folder in Google Drive
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        folder_name (str): Name of the folder to create
        parent_folder_id (str, optional): ID of the parent folder. Defaults to root.
    
    Returns:
        dict: Always returns None (disabled)
    """
    logger.warning("Folder creation is disabled in read-only mode")
    return None

def share_file(file_id, email, role='reader'):
    """
    [DISABLED - READ ONLY MODE] Share a file with a specific user
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        file_id (str): ID of the file to share
        email (str): Email address to share with
        role (str, optional): Permission role to grant. Defaults to 'reader'.
            Options: 'owner', 'organizer', 'fileOrganizer', 'writer', 'commenter', 'reader'
    
    Returns:
        bool: Always returns False (disabled)
    """
    logger.warning("File sharing is disabled in read-only mode")
    return False

def export_file_as_pdf(file_id, output_path):
    """
    [DISABLED - READ ONLY MODE] Export a Google Doc, Sheet, or Slide as PDF
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        file_id (str): ID of the file to export
        output_path (str): Path where the PDF will be saved
    
    Returns:
        bool: Always returns False (disabled)
    """
    logger.warning("File export is disabled in read-only mode")
    return False

def upload_digest_to_drive(digest, parent_folder_id=None):
    """
    [DISABLED - READ ONLY MODE] Upload a CEO digest to Google Drive
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        digest (dict): The digest data to upload
        parent_folder_id (str, optional): ID of the folder to upload to. Defaults to root.
    
    Returns:
        dict: Always returns None (disabled)
    """
    logger.warning("Digest upload is disabled in read-only mode")
    return None