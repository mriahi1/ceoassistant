import os
import logging
import base64
from email.mime.text import MIMEText
import json
from datetime import datetime
from googleapiclient.discovery import build
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import config

logger = logging.getLogger(__name__)

# Gmail API Scopes
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly'
]

# Initialize Gmail API client
gmail_service = None
credentials_path = os.environ.get('GOOGLE_CREDENTIALS_PATH')
token_path = os.path.join(config.DATA_DIR, 'gmail_token.json')

def initialize_gmail_client():
    """
    Initialize the Gmail API client
    
    This checks for stored credentials and if not found, guides through OAuth flow
    
    Returns:
        bool: True if initialized successfully, False otherwise
    """
    global gmail_service
    
    if not credentials_path:
        logger.error("GOOGLE_CREDENTIALS_PATH not set. Cannot initialize Gmail.")
        return False
    
    try:
        creds = None
        # Try to load existing token
        if os.path.exists(token_path):
            logger.debug("Loading existing Gmail token")
            with open(token_path, 'r') as token:
                creds = Credentials.from_authorized_user_info(json.load(token), SCOPES)
        
        # Check if credentials are valid
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logger.debug("Refreshing expired Gmail token")
                creds.refresh(Request())
            else:
                logger.debug("Starting new OAuth flow for Gmail")
                flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            logger.debug("Saving Gmail token")
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
        
        # Build the service
        gmail_service = build('gmail', 'v1', credentials=creds)
        logger.debug("Gmail client initialized successfully")
        return True
    
    except Exception as e:
        logger.error(f"Error initializing Gmail client: {str(e)}")
        return False

def get_unread_emails(max_results=20):
    """
    Get unread emails from Gmail
    
    Args:
        max_results (int, optional): Maximum number of results to return. Defaults to 20.
    
    Returns:
        list: List of unread emails
    """
    if not gmail_service:
        if not initialize_gmail_client():
            logger.error("Failed to initialize Gmail client.")
            return []
    
    try:
        results = gmail_service.users().messages().list(
            userId='me', 
            q='is:unread', 
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            logger.debug("No unread messages found.")
            return []
        
        unread_emails = []
        
        for message in messages:
            msg = gmail_service.users().messages().get(
                userId='me', id=message['id'], format='full'
            ).execute()
            
            # Get header fields
            headers = msg['payload']['headers']
            subject = ''
            sender = ''
            date = ''
            
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Date':
                    date = header['value']
            
            # Get message body
            body = ''
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = base64.urlsafe_b64decode(
                            part['body']['data']).decode('utf-8')
                        break
            elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
                body = base64.urlsafe_b64decode(
                    msg['payload']['body']['data']).decode('utf-8')
            
            unread_emails.append({
                'id': message['id'],
                'subject': subject,
                'sender': sender,
                'date': date,
                'body': body,
                'threadId': msg['threadId']
            })
        
        return unread_emails
    
    except Exception as e:
        logger.error(f"Error fetching unread emails: {str(e)}")
        return []

def get_recent_emails(max_results=50):
    """
    Get recent emails from Gmail
    
    Args:
        max_results (int, optional): Maximum number of results to return. Defaults to 50.
    
    Returns:
        list: List of recent emails
    """
    if not gmail_service:
        if not initialize_gmail_client():
            logger.error("Failed to initialize Gmail client.")
            return []
    
    try:
        results = gmail_service.users().messages().list(
            userId='me', 
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            logger.debug("No messages found.")
            return []
        
        recent_emails = []
        
        for message in messages:
            msg = gmail_service.users().messages().get(
                userId='me', id=message['id'], format='metadata'
            ).execute()
            
            # Get header fields
            headers = msg['payload']['headers']
            subject = ''
            sender = ''
            date = ''
            
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Date':
                    date = header['value']
            
            recent_emails.append({
                'id': message['id'],
                'subject': subject,
                'sender': sender,
                'date': date,
                'threadId': msg['threadId']
            })
        
        return recent_emails
    
    except Exception as e:
        logger.error(f"Error fetching recent emails: {str(e)}")
        return []

def get_email(email_id):
    """
    Get a specific email by ID
    
    Args:
        email_id (str): The ID of the email to get
    
    Returns:
        dict: The email data or None if not found
    """
    if not gmail_service:
        if not initialize_gmail_client():
            logger.error("Failed to initialize Gmail client.")
            return None
    
    try:
        msg = gmail_service.users().messages().get(
            userId='me', id=email_id, format='full'
        ).execute()
        
        # Get header fields
        headers = msg['payload']['headers']
        subject = ''
        sender = ''
        date = ''
        to = ''
        
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            elif header['name'] == 'From':
                sender = header['value']
            elif header['name'] == 'Date':
                date = header['value']
            elif header['name'] == 'To':
                to = header['value']
        
        # Get message body
        body = ''
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    body = base64.urlsafe_b64decode(
                        part['body']['data']).decode('utf-8')
                    break
        elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
            body = base64.urlsafe_b64decode(
                msg['payload']['body']['data']).decode('utf-8')
        
        email_data = {
            'id': email_id,
            'subject': subject,
            'sender': sender,
            'date': date,
            'to': to,
            'body': body,
            'threadId': msg['threadId'],
            'labelIds': msg['labelIds']
        }
        
        return email_data
    
    except Exception as e:
        logger.error(f"Error fetching email {email_id}: {str(e)}")
        return None

def send_email(to, subject, body, reply_to=None):
    """
    [DISABLED - READ ONLY MODE] Send an email from the authenticated user
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        to (str): Email recipient
        subject (str): Email subject
        body (str): Email body content
        reply_to (str, optional): Message ID to reply to. Defaults to None.
    
    Returns:
        bool: Always returns False (disabled)
    """
    logger.warning("Email sending is disabled in read-only mode")
    return False

def search_emails(query, max_results=20):
    """
    Search for emails using Gmail's search syntax
    
    Args:
        query (str): Search query (using Gmail search syntax)
        max_results (int, optional): Maximum number of results. Defaults to 20.
    
    Returns:
        list: List of matching email messages
    """
    if not gmail_service:
        if not initialize_gmail_client():
            logger.error("Failed to initialize Gmail client.")
            return []
    
    try:
        results = gmail_service.users().messages().list(
            userId='me', 
            q=query, 
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            logger.debug(f"No messages matching '{query}' found.")
            return []
        
        matching_emails = []
        
        for message in messages:
            msg = gmail_service.users().messages().get(
                userId='me', id=message['id'], format='metadata'
            ).execute()
            
            # Get header fields
            headers = msg['payload']['headers']
            subject = ''
            sender = ''
            date = ''
            
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Date':
                    date = header['value']
            
            matching_emails.append({
                'id': message['id'],
                'subject': subject,
                'sender': sender,
                'date': date,
                'threadId': msg['threadId']
            })
        
        return matching_emails
    
    except Exception as e:
        logger.error(f"Error searching emails: {str(e)}")
        return []

def mark_email_read(email_id):
    """
    [DISABLED - READ ONLY MODE] Mark an email as read
    
    This function is currently disabled as the application is running in read-only mode.
    
    Args:
        email_id (str): The ID of the email to mark as read
    
    Returns:
        bool: Always returns False (disabled)
    """
    logger.warning("Email modification is disabled in read-only mode")
    return False

def analyze_email_thread(thread_id):
    """
    Analyze a complete email thread
    
    Args:
        thread_id (str): The ID of the thread to analyze
    
    Returns:
        dict: The thread analysis data
    """
    if not gmail_service:
        if not initialize_gmail_client():
            logger.error("Failed to initialize Gmail client.")
            return None
    
    try:
        thread = gmail_service.users().threads().get(
            userId='me', id=thread_id
        ).execute()
        
        messages = thread.get('messages', [])
        
        thread_data = {
            'id': thread_id,
            'messages': [],
            'participants': set(),
            'subject': '',
            'start_date': None,
            'end_date': None
        }
        
        for message in messages:
            headers = message['payload']['headers']
            subject = ''
            sender = ''
            date = ''
            to = ''
            
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Date':
                    date = header['value']
                elif header['name'] == 'To':
                    to = header['value']
            
            # Extract body
            body = ''
            if 'parts' in message['payload']:
                for part in message['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        if 'data' in part['body']:
                            body = base64.urlsafe_b64decode(
                                part['body']['data']).decode('utf-8')
                            break
            elif 'body' in message['payload'] and 'data' in message['payload']['body']:
                body = base64.urlsafe_b64decode(
                    message['payload']['body']['data']).decode('utf-8')
            
            # Parse date
            try:
                parsed_date = datetime.strptime(date.split(' +')[0].strip(), '%a, %d %b %Y %H:%M:%S')
            except:
                parsed_date = datetime.now()
            
            # Update thread data
            thread_data['messages'].append({
                'id': message['id'],
                'subject': subject,
                'sender': sender,
                'date': date,
                'parsed_date': parsed_date,
                'body': body,
                'unread': 'UNREAD' in message['labelIds'] if 'labelIds' in message else False
            })
            
            # Update participants
            thread_data['participants'].add(sender)
            if to:
                for recipient in to.split(','):
                    thread_data['participants'].add(recipient.strip())
            
            # Set thread subject (from first message)
            if not thread_data['subject']:
                thread_data['subject'] = subject
            
            # Update start/end dates
            if not thread_data['start_date'] or parsed_date < thread_data['start_date']:
                thread_data['start_date'] = parsed_date
            if not thread_data['end_date'] or parsed_date > thread_data['end_date']:
                thread_data['end_date'] = parsed_date
        
        # Sort messages by date
        thread_data['messages'].sort(key=lambda x: x['parsed_date'])
        
        # Convert participants from set to list
        thread_data['participants'] = list(thread_data['participants'])
        
        return thread_data
    
    except Exception as e:
        logger.error(f"Error analyzing email thread: {str(e)}")
        return None