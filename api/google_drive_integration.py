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
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive'
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
    Upload a file to Google Drive
    
    Args:
        file_path (str): Path to the file to upload
        parent_folder_id (str, optional): ID of the folder to upload to. Defaults to root.
        description (str, optional): Description of the file. Defaults to None.
    
    Returns:
        dict: The uploaded file metadata or None if upload failed
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return None
    
    try:
        file_metadata = {
            'name': os.path.basename(file_path)
        }
        
        if description:
            file_metadata['description'] = description
            
        if parent_folder_id:
            file_metadata['parents'] = [parent_folder_id]
        
        media = MediaFileUpload(
            file_path,
            resumable=True
        )
        
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, mimeType, createdTime, modifiedTime, webViewLink'
        ).execute()
        
        logger.debug(f"File uploaded: {file.get('id')}")
        
        return {
            'id': file.get('id'),
            'name': file.get('name'),
            'mimeType': file.get('mimeType'),
            'createdTime': file.get('createdTime'),
            'modifiedTime': file.get('modifiedTime'),
            'webViewLink': file.get('webViewLink', '')
        }
    
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return None

def create_folder(folder_name, parent_folder_id=None):
    """
    Create a folder in Google Drive
    
    Args:
        folder_name (str): Name of the folder to create
        parent_folder_id (str, optional): ID of the parent folder. Defaults to root.
    
    Returns:
        dict: The created folder metadata or None if creation failed
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return None
    
    try:
        folder_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        
        if parent_folder_id:
            folder_metadata['parents'] = [parent_folder_id]
        
        folder = drive_service.files().create(
            body=folder_metadata,
            fields='id, name, mimeType, createdTime, modifiedTime, webViewLink'
        ).execute()
        
        logger.debug(f"Folder created: {folder.get('id')}")
        
        return {
            'id': folder.get('id'),
            'name': folder.get('name'),
            'mimeType': folder.get('mimeType'),
            'createdTime': folder.get('createdTime'),
            'modifiedTime': folder.get('modifiedTime'),
            'webViewLink': folder.get('webViewLink', ''),
            'isFolder': True
        }
    
    except Exception as e:
        logger.error(f"Error creating folder: {str(e)}")
        return None

def share_file(file_id, email, role='reader'):
    """
    Share a file with a specific user
    
    Args:
        file_id (str): ID of the file to share
        email (str): Email address to share with
        role (str, optional): Permission role to grant. Defaults to 'reader'.
            Options: 'owner', 'organizer', 'fileOrganizer', 'writer', 'commenter', 'reader'
    
    Returns:
        bool: True if shared successfully, False otherwise
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return False
    
    try:
        permission = {
            'type': 'user',
            'role': role,
            'emailAddress': email
        }
        
        drive_service.permissions().create(
            fileId=file_id,
            body=permission,
            sendNotificationEmail=True
        ).execute()
        
        logger.debug(f"File {file_id} shared with {email} as {role}")
        return True
    
    except Exception as e:
        logger.error(f"Error sharing file: {str(e)}")
        return False

def export_file_as_pdf(file_id, output_path):
    """
    Export a Google Doc, Sheet, or Slide as PDF
    
    Args:
        file_id (str): ID of the file to export
        output_path (str): Path where the PDF will be saved
    
    Returns:
        bool: True if exported successfully, False otherwise
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return False
    
    try:
        # Get file metadata to check mime type
        file = drive_service.files().get(fileId=file_id).execute()
        mime_type = file.get('mimeType', '')
        
        # Set the export MIME type based on the file type
        export_mime_type = 'application/pdf'
        
        # Check if the file is a Google Docs, Sheets, or Slides file
        if not (mime_type.startswith('application/vnd.google-apps.')):
            logger.error(f"File {file_id} is not a Google Docs, Sheets, or Slides file")
            return False
        
        # Export the file
        request = drive_service.files().export_media(
            fileId=file_id, 
            mimeType=export_mime_type
        )
        
        with open(output_path, 'wb') as f:
            downloaded = request.execute()
            f.write(downloaded)
        
        logger.debug(f"File {file_id} exported as PDF to {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error exporting file as PDF: {str(e)}")
        return False

def upload_digest_to_drive(digest, parent_folder_id=None):
    """
    Upload a CEO digest to Google Drive as JSON and create a summary document
    
    Args:
        digest (dict): The digest data to upload
        parent_folder_id (str, optional): ID of the parent folder. Defaults to None.
    
    Returns:
        dict: Information about the uploaded files or None if upload failed
    """
    if not drive_service:
        if not initialize_drive_client():
            logger.error("Failed to initialize Drive client.")
            return None
    
    try:
        # First, check or create a CEO Digests folder
        digest_folder_id = None
        
        if parent_folder_id:
            # Look for an existing CEO Digests folder in the specified parent
            results = drive_service.files().list(
                q=f"name='CEO Digests' and '{parent_folder_id}' in parents and mimeType='application/vnd.google-apps.folder'",
                pageSize=1,
                fields="files(id)"
            ).execute()
            
            items = results.get('files', [])
            
            if items:
                digest_folder_id = items[0]['id']
            else:
                # Create the folder
                folder = create_folder('CEO Digests', parent_folder_id)
                if folder:
                    digest_folder_id = folder['id']
        else:
            # Look for an existing CEO Digests folder in root
            results = drive_service.files().list(
                q="name='CEO Digests' and 'root' in parents and mimeType='application/vnd.google-apps.folder'",
                pageSize=1,
                fields="files(id)"
            ).execute()
            
            items = results.get('files', [])
            
            if items:
                digest_folder_id = items[0]['id']
            else:
                # Create the folder
                folder = create_folder('CEO Digests')
                if folder:
                    digest_folder_id = folder['id']
        
        if not digest_folder_id:
            logger.error("Failed to find or create CEO Digests folder")
            return None
        
        # Save digest to a temporary JSON file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_json_path = os.path.join(config.DATA_DIR, f"digest_{timestamp}.json")
        
        with open(temp_json_path, 'w') as f:
            json.dump(digest, f, indent=2)
        
        # Upload the JSON file
        json_file = upload_file(temp_json_path, digest_folder_id, f"CEO Digest - {digest.get('date', 'Today')}")
        
        # Clean up temporary file
        os.remove(temp_json_path)
        
        return {
            'folder_id': digest_folder_id,
            'json_file': json_file
        }
    
    except Exception as e:
        logger.error(f"Error uploading digest to Drive: {str(e)}")
        return None