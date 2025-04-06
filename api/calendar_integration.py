import os
import logging
import datetime
from dateutil.parser import parse
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Try to import Google API libraries
try:
    from googleapiclient.discovery import build
    from google.oauth2 import service_account
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    import pickle
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    logger.warning("Google API libraries not available")
    GOOGLE_LIBS_AVAILABLE = False

# Google Calendar API configuration
CALENDAR_ENABLED = os.environ.get("CALENDAR_ENABLED", "false").lower() == "true"
GOOGLE_CREDENTIALS_PATH = os.environ.get("GOOGLE_CREDENTIALS_PATH")
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']
TOKEN_PATH = "data/calendar_token.pickle"

def initialize_calendar_client():
    """
    Initialize the Google Calendar API client
    
    This checks for stored credentials and if not found, guides through OAuth flow
    
    Returns:
        bool: True if initialized successfully, False otherwise
    """
    if not CALENDAR_ENABLED or not GOOGLE_LIBS_AVAILABLE:
        logger.warning("Google Calendar integration is not enabled or required libraries not installed")
        return False
    
    if not GOOGLE_CREDENTIALS_PATH:
        logger.warning("Google credentials path not set")
        return False
    
    try:
        creds = None
        
        # The token pickle file stores the user's access and refresh tokens
        if os.path.exists(TOKEN_PATH):
            with open(TOKEN_PATH, 'rb') as token:
                creds = pickle.load(token)
        
        # If there are no valid credentials, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(GOOGLE_CREDENTIALS_PATH, SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
            with open(TOKEN_PATH, 'wb') as token:
                pickle.dump(creds, token)
        
        # Create the Calendar API service
        global calendar_service
        calendar_service = build('calendar', 'v3', credentials=creds)
        
        return True
    except Exception as e:
        logger.error(f"Error initializing Google Calendar client: {str(e)}")
        return False

def get_calendar_list():
    """
    Get list of calendars for the authenticated user
    
    Returns:
        list: List of calendars
    """
    if 'calendar_service' not in globals():
        if not initialize_calendar_client():
            return []
    
    try:
        result = calendar_service.calendarList().list().execute()
        return result.get('items', [])
    except Exception as e:
        logger.error(f"Error getting calendar list: {str(e)}")
        return []

def get_calendar_events(calendar_id='primary', time_min=None, time_max=None, max_results=100):
    """
    Get events from a specific calendar
    
    Args:
        calendar_id (str, optional): Calendar ID. Defaults to 'primary'.
        time_min (datetime, optional): Start time. Defaults to now.
        time_max (datetime, optional): End time. Defaults to 7 days from now.
        max_results (int, optional): Maximum number of results. Defaults to 100.
    
    Returns:
        list: List of events
    """
    if 'calendar_service' not in globals():
        if not initialize_calendar_client():
            return []
    
    try:
        # Set default time range if not provided
        if not time_min:
            time_min = datetime.now()
        if not time_max:
            time_max = time_min + timedelta(days=7)
        
        # Format times for the API
        time_min_rfc = time_min.isoformat() + 'Z'
        time_max_rfc = time_max.isoformat() + 'Z'
        
        # Call the Calendar API
        events_result = calendar_service.events().list(
            calendarId=calendar_id,
            timeMin=time_min_rfc,
            timeMax=time_max_rfc,
            maxResults=max_results,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        return events_result.get('items', [])
    except Exception as e:
        logger.error(f"Error getting calendar events: {str(e)}")
        return []

def get_weekly_schedule(calendar_id='primary'):
    """
    Get the weekly schedule from the calendar
    
    Args:
        calendar_id (str, optional): Calendar ID. Defaults to 'primary'.
    
    Returns:
        dict: Weekly schedule with daily events
    """
    # Set the time range to the current week
    now = datetime.now()
    start_of_week = now - timedelta(days=now.weekday())
    start_of_week = datetime(start_of_week.year, start_of_week.month, start_of_week.day)
    end_of_week = start_of_week + timedelta(days=7)
    
    # Get events for the week
    events = get_calendar_events(
        calendar_id=calendar_id,
        time_min=start_of_week,
        time_max=end_of_week,
        max_results=500
    )
    
    # Organize events by day
    daily_events = {}
    
    for event in events:
        # Get start time
        start = event.get('start', {})
        if 'dateTime' in start:
            start_time = parse(start['dateTime'])
            all_day = False
        elif 'date' in start:
            start_time = parse(start['date']).replace(tzinfo=None)
            all_day = True
        else:
            continue
        
        # Get day key
        day_key = start_time.strftime('%Y-%m-%d')
        day_name = start_time.strftime('%A')
        
        # Initialize day if not exists
        if day_key not in daily_events:
            daily_events[day_key] = {
                'date': day_key,
                'day_name': day_name,
                'events': [],
                'all_day_events': [],
                'total_events': 0,
                'total_duration_minutes': 0,
                'time_slots': {
                    'morning': 0,    # 6-12
                    'afternoon': 0,  # 12-18
                    'evening': 0     # 18-24
                }
            }
        
        # Add event details
        event_detail = {
            'id': event.get('id'),
            'summary': event.get('summary', 'Untitled Event'),
            'location': event.get('location', ''),
            'description': event.get('description', ''),
            'all_day': all_day,
            'status': event.get('status', ''),
            'attendees': len(event.get('attendees', [])),
            'organizer': event.get('organizer', {}).get('email', '')
        }
        
        if all_day:
            daily_events[day_key]['all_day_events'].append(event_detail)
        else:
            # Add time information for non-all-day events
            end_time = parse(event.get('end', {}).get('dateTime', start['dateTime']))
            duration = (end_time - start_time).total_seconds() / 60
            
            event_detail.update({
                'start_time': start_time.strftime('%H:%M'),
                'end_time': end_time.strftime('%H:%M'),
                'duration_minutes': duration
            })
            
            daily_events[day_key]['events'].append(event_detail)
            daily_events[day_key]['total_duration_minutes'] += duration
            
            # Update time slot counters
            hour = start_time.hour
            if 6 <= hour < 12:
                daily_events[day_key]['time_slots']['morning'] += 1
            elif 12 <= hour < 18:
                daily_events[day_key]['time_slots']['afternoon'] += 1
            else:
                daily_events[day_key]['time_slots']['evening'] += 1
        
        daily_events[day_key]['total_events'] += 1
    
    return {
        'start_date': start_of_week.strftime('%Y-%m-%d'),
        'end_date': end_of_week.strftime('%Y-%m-%d'),
        'days': daily_events
    }

def get_daily_meeting_load():
    """
    Analyze the meeting load by day and time
    
    Returns:
        dict: Meeting load analysis
    """
    # Get weekly schedule
    schedule = get_weekly_schedule()
    
    # Calculate metrics
    total_events = 0
    total_duration = 0
    days = {}
    busiest_day = {"day": None, "events": 0}
    lightest_day = {"day": None, "events": float('inf')}
    
    for day_key, day_data in schedule.get('days', {}).items():
        total_events += day_data['total_events']
        total_duration += day_data['total_duration_minutes']
        
        # Track busiest/lightest days
        if day_data['total_events'] > busiest_day["events"]:
            busiest_day = {"day": day_key, "events": day_data['total_events']}
        
        if day_data['total_events'] < lightest_day["events"] and day_data['total_events'] > 0:
            lightest_day = {"day": day_key, "events": day_data['total_events']}
    
    # If no events were found, reset lightest day
    if lightest_day["day"] is None or lightest_day["events"] == float('inf'):
        lightest_day = {"day": None, "events": 0}
    
    return {
        'total_events': total_events,
        'total_duration_hours': round(total_duration / 60, 1),
        'average_meeting_duration': round(total_duration / total_events, 1) if total_events > 0 else 0,
        'busiest_day': busiest_day,
        'lightest_day': lightest_day,
        'days': schedule.get('days', {})
    }

def identify_meeting_conflicts():
    """
    Identify conflicts and back-to-back meetings in the schedule
    
    Returns:
        dict: Meeting conflict analysis
    """
    # Get weekly schedule
    schedule = get_weekly_schedule()
    
    conflicts = []
    back_to_back = []
    
    # Analyze each day
    for day_key, day_data in schedule.get('days', {}).items():
        events = day_data.get('events', [])
        
        # Skip if less than 2 events
        if len(events) < 2:
            continue
        
        # Sort events by start time
        sorted_events = sorted(events, key=lambda x: x.get('start_time', '00:00'))
        
        # Check for conflicts and back-to-back meetings
        for i in range(len(sorted_events)):
            current = sorted_events[i]
            
            # Skip all-day events
            if current.get('all_day', False):
                continue
            
            # Check for conflicts with other events
            for j in range(i + 1, len(sorted_events)):
                next_event = sorted_events[j]
                
                # Skip all-day events
                if next_event.get('all_day', False):
                    continue
                
                current_start = datetime.strptime(current.get('start_time', '00:00'), '%H:%M')
                current_end = datetime.strptime(current.get('end_time', '00:00'), '%H:%M')
                next_start = datetime.strptime(next_event.get('start_time', '00:00'), '%H:%M')
                next_end = datetime.strptime(next_event.get('end_time', '00:00'), '%H:%M')
                
                # Check for conflict (overlap)
                if current_start < next_end and next_start < current_end:
                    conflicts.append({
                        'day': day_key,
                        'event1': current,
                        'event2': next_event
                    })
                
                # Check for back-to-back (less than 15 min between)
                time_between = (next_start - current_end).total_seconds() / 60
                if 0 <= time_between < 15:
                    back_to_back.append({
                        'day': day_key,
                        'event1': current,
                        'event2': next_event,
                        'break_minutes': time_between
                    })
    
    return {
        'conflicts': conflicts,
        'back_to_back': back_to_back,
        'total_conflicts': len(conflicts),
        'total_back_to_back': len(back_to_back)
    }

def identify_meeting_priorities():
    """
    Identify high-priority meetings and suggest meetings that could be delegated
    
    Returns:
        dict: Meeting priority analysis
    """
    # Get weekly schedule
    schedule = get_weekly_schedule()
    
    # Keywords that might indicate high priority
    high_priority_keywords = ['urgent', 'important', 'priority', 'critical', 'exec', 'board', 'review', 'decision', 'approve', 'strategy']
    
    # Keywords that might indicate possible delegation
    delegation_keywords = ['update', 'status', 'routine', 'weekly', 'sync', 'check-in', 'standup', 'informational']
    
    # Lists to store categorized meetings
    high_priority = []
    possible_delegation = []
    
    # Analyze each day
    for day_key, day_data in schedule.get('days', {}).items():
        all_events = day_data.get('events', []) + day_data.get('all_day_events', [])
        
        for event in all_events:
            summary = event.get('summary', '').lower()
            description = event.get('description', '').lower()
            combined_text = f"{summary} {description}"
            
            # Check for high priority indicators
            is_high_priority = False
            for keyword in high_priority_keywords:
                if keyword in combined_text:
                    is_high_priority = True
                    break
            
            # Check for delegation indicators
            is_delegatable = False
            for keyword in delegation_keywords:
                if keyword in combined_text:
                    is_delegatable = True
                    break
            
            # Add to appropriate list
            if is_high_priority:
                high_priority.append({
                    'day': day_key,
                    'event': event
                })
            
            if is_delegatable and not is_high_priority:
                possible_delegation.append({
                    'day': day_key,
                    'event': event
                })
    
    return {
        'high_priority': high_priority,
        'possible_delegation': possible_delegation,
        'total_high_priority': len(high_priority),
        'total_possible_delegation': len(possible_delegation)
    }

def find_free_time_slots(min_duration_minutes=30, consider_working_hours=True):
    """
    Find free time slots in the schedule
    
    Args:
        min_duration_minutes (int, optional): Minimum duration in minutes. Defaults to 30.
        consider_working_hours (bool, optional): Only consider working hours. Defaults to True.
    
    Returns:
        dict: Free time slot analysis
    """
    # Get weekly schedule
    schedule = get_weekly_schedule()
    
    # Define working hours
    working_hours = {
        'start': datetime.strptime('09:00', '%H:%M'),
        'end': datetime.strptime('17:30', '%H:%M')
    }
    
    free_slots = []
    
    # Analyze each day
    for day_key, day_data in schedule.get('days', {}).items():
        events = day_data.get('events', [])
        
        # Skip if any all-day events (assuming they block the whole day)
        if day_data.get('all_day_events', []):
            continue
        
        # Sort events by start time
        sorted_events = sorted(events, key=lambda x: x.get('start_time', '00:00'))
        
        # Set day boundaries
        if consider_working_hours:
            day_start = working_hours['start']
            day_end = working_hours['end']
        else:
            day_start = datetime.strptime('00:00', '%H:%M')
            day_end = datetime.strptime('23:59', '%H:%M')
        
        # Initialize the current time to the day start
        current_time = day_start
        
        # Find free slots between events
        for event in sorted_events:
            event_start = datetime.strptime(event.get('start_time', '00:00'), '%H:%M')
            event_end = datetime.strptime(event.get('end_time', '00:00'), '%H:%M')
            
            # Skip events outside working hours if considering working hours
            if consider_working_hours:
                if event_end <= day_start or event_start >= day_end:
                    continue
                
                # Adjust event bounds to working hours
                event_start = max(event_start, day_start)
                event_end = min(event_end, day_end)
            
            # Check if there's a free slot before the event
            if current_time < event_start:
                duration_minutes = (event_start - current_time).total_seconds() / 60
                
                if duration_minutes >= min_duration_minutes:
                    free_slots.append({
                        'day': day_key,
                        'start_time': current_time.strftime('%H:%M'),
                        'end_time': event_start.strftime('%H:%M'),
                        'duration_minutes': duration_minutes
                    })
            
            # Move current time to after the event
            current_time = max(current_time, event_end)
        
        # Check if there's a free slot after the last event
        if current_time < day_end:
            duration_minutes = (day_end - current_time).total_seconds() / 60
            
            if duration_minutes >= min_duration_minutes:
                free_slots.append({
                    'day': day_key,
                    'start_time': current_time.strftime('%H:%M'),
                    'end_time': day_end.strftime('%H:%M'),
                    'duration_minutes': duration_minutes
                })
    
    # Group by day for better organization
    slots_by_day = {}
    for slot in free_slots:
        day = slot['day']
        if day not in slots_by_day:
            slots_by_day[day] = []
        slots_by_day[day].append(slot)
    
    # Calculate total free time
    total_free_minutes = sum(slot['duration_minutes'] for slot in free_slots)
    
    return {
        'free_slots': free_slots,
        'slots_by_day': slots_by_day,
        'total_free_slots': len(free_slots),
        'total_free_hours': round(total_free_minutes / 60, 1)
    }

def get_calendar_summary():
    """
    Get a comprehensive summary of the calendar
    
    Returns:
        dict: Calendar summary including schedule, meeting load, conflicts, and priorities
    """
    weekly_schedule = get_weekly_schedule()
    meeting_load = get_daily_meeting_load()
    conflicts = identify_meeting_conflicts()
    priorities = identify_meeting_priorities()
    free_time = find_free_time_slots()
    
    return {
        'weekly_schedule': weekly_schedule,
        'meeting_load': meeting_load,
        'conflicts': conflicts,
        'priorities': priorities,
        'free_time': free_time
    }

def get_all_calendar_data():
    """
    Get all relevant Google Calendar data for the dashboard
    
    Returns:
        dict: Consolidated Google Calendar data
    """
    if not initialize_calendar_client():
        logger.warning("Google Calendar client not initialized")
        return {"error": "Google Calendar client not initialized, check CALENDAR_ENABLED and GOOGLE_CREDENTIALS_PATH settings"}
    
    try:
        return get_calendar_summary()
    except Exception as e:
        logger.error(f"Error getting Google Calendar data: {str(e)}")
        return {"error": str(e)}