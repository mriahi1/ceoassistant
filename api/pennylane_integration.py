import os
import requests
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Pennylane API configuration
PENNYLANE_API_KEY = os.environ.get("PENNYLANE_API_KEY")
PENNYLANE_COMPANY_ID = os.environ.get("PENNYLANE_COMPANY_ID")
PENNYLANE_BASE_URL = os.environ.get("PENNYLANE_BASE_URL", "https://api.pennylane.tech/api/v1")

def initialize_pennylane_client():
    """
    Initialize the Pennylane API client
    
    Returns:
        bool: True if API key is configured, False otherwise
    """
    if not PENNYLANE_API_KEY or not PENNYLANE_COMPANY_ID:
        logger.warning("Pennylane API key or company ID not configured")
        return False
    
    return True

def _make_request(endpoint, method="GET", params=None, data=None):
    """
    Make a request to the Pennylane API
    
    Args:
        endpoint (str): API endpoint to call
        method (str, optional): HTTP method. Defaults to "GET".
        params (dict, optional): Query parameters. Defaults to None.
        data (dict, optional): Request body for POST/PUT requests. Defaults to None.
    
    Returns:
        dict: API response
    """
    if not PENNYLANE_API_KEY:
        raise ValueError("Pennylane API key not configured")
    
    headers = {
        "Authorization": f"Bearer {PENNYLANE_API_KEY}",
        "Content-Type": "application/json",
    }
    
    url = f"{PENNYLANE_BASE_URL}/{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=params)
        elif method == "POST":
            response = requests.post(url, headers=headers, params=params, json=data)
        elif method == "PUT":
            response = requests.put(url, headers=headers, params=params, json=data)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making request to Pennylane API: {str(e)}")
        raise

def get_company_info():
    """
    Get company information from Pennylane
    
    Returns:
        dict: Company information
    """
    return _make_request(f"companies/{PENNYLANE_COMPANY_ID}")

def get_bank_accounts():
    """
    Get bank accounts from Pennylane
    
    Returns:
        list: List of bank accounts
    """
    return _make_request(f"companies/{PENNYLANE_COMPANY_ID}/bank_accounts")

def get_bank_balance():
    """
    Get current bank balance from Pennylane
    
    Returns:
        dict: Bank balance information
    """
    accounts = get_bank_accounts()
    
    # Calculate total balance across all accounts
    total_balance = sum(account.get("balance", 0) for account in accounts.get("data", []))
    
    return {
        "total_balance": total_balance,
        "accounts": accounts.get("data", [])
    }

def get_invoices(period_start=None, period_end=None, status=None, limit=50):
    """
    Get invoices from Pennylane
    
    Args:
        period_start (str, optional): Start date (YYYY-MM-DD). Defaults to 30 days ago.
        period_end (str, optional): End date (YYYY-MM-DD). Defaults to today.
        status (str, optional): Invoice status filter. Defaults to None.
        limit (int, optional): Maximum number of results. Defaults to 50.
    
    Returns:
        list: List of invoices
    """
    if not period_start:
        period_start = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    if not period_end:
        period_end = datetime.now().strftime("%Y-%m-%d")
    
    params = {
        "period_start": period_start,
        "period_end": period_end,
        "limit": limit
    }
    
    if status:
        params["status"] = status
    
    return _make_request(f"companies/{PENNYLANE_COMPANY_ID}/customer_invoices", params=params)

def get_expenses(period_start=None, period_end=None, limit=50):
    """
    Get expenses from Pennylane
    
    Args:
        period_start (str, optional): Start date (YYYY-MM-DD). Defaults to 30 days ago.
        period_end (str, optional): End date (YYYY-MM-DD). Defaults to today.
        limit (int, optional): Maximum number of results. Defaults to 50.
    
    Returns:
        list: List of expenses
    """
    if not period_start:
        period_start = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    if not period_end:
        period_end = datetime.now().strftime("%Y-%m-%d")
    
    params = {
        "period_start": period_start,
        "period_end": period_end,
        "limit": limit
    }
    
    return _make_request(f"companies/{PENNYLANE_COMPANY_ID}/expenses", params=params)

def get_expense_categories():
    """
    Get expense categories from Pennylane
    
    Returns:
        list: List of expense categories
    """
    return _make_request(f"companies/{PENNYLANE_COMPANY_ID}/expense_categories")

def get_expense_trends(months=3):
    """
    Analyze expense trends over the past months
    
    Args:
        months (int, optional): Number of months to analyze. Defaults to 3.
    
    Returns:
        dict: Expense trend analysis
    """
    # Get expenses for the past X months
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30 * months)
    
    expenses = get_expenses(
        period_start=start_date.strftime("%Y-%m-%d"),
        period_end=end_date.strftime("%Y-%m-%d"),
        limit=500  # Get a larger sample for trend analysis
    )
    
    # Get categories
    categories = get_expense_categories()
    category_map = {cat.get("id"): cat.get("name") for cat in categories.get("data", [])}
    
    # Organize expenses by month and category
    monthly_expenses = {}
    categorized_expenses = {}
    
    for expense in expenses.get("data", []):
        expense_date = datetime.strptime(expense.get("date"), "%Y-%m-%d")
        month_key = expense_date.strftime("%Y-%m")
        amount = expense.get("total_amount", 0)
        category_id = expense.get("category_id")
        category_name = category_map.get(category_id, "Uncategorized")
        
        # Add to monthly totals
        if month_key not in monthly_expenses:
            monthly_expenses[month_key] = 0
        monthly_expenses[month_key] += amount
        
        # Add to category totals
        if category_name not in categorized_expenses:
            categorized_expenses[category_name] = 0
        categorized_expenses[category_name] += amount
    
    # Calculate month-over-month change
    sorted_months = sorted(monthly_expenses.keys())
    mom_changes = {}
    
    for i in range(1, len(sorted_months)):
        current_month = sorted_months[i]
        previous_month = sorted_months[i-1]
        
        current_amount = monthly_expenses[current_month]
        previous_amount = monthly_expenses[previous_month]
        
        if previous_amount > 0:
            percent_change = ((current_amount - previous_amount) / previous_amount) * 100
        else:
            percent_change = 100 if current_amount > 0 else 0
        
        mom_changes[current_month] = {
            "amount": current_amount,
            "previous_amount": previous_amount,
            "change_percent": round(percent_change, 2)
        }
    
    # Find top expense categories
    top_categories = sorted(categorized_expenses.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "monthly_totals": monthly_expenses,
        "month_over_month_changes": mom_changes,
        "top_categories": dict(top_categories),
        "total_expenses": sum(monthly_expenses.values())
    }

def get_profitability(period=None):
    """
    Get profitability metrics from Pennylane
    
    Args:
        period (str, optional): Period to analyze ('month', 'quarter', 'year'). Defaults to 'month'.
    
    Returns:
        dict: Profitability metrics
    """
    if not period:
        period = "month"
    
    # Set the date range based on the period
    end_date = datetime.now()
    
    if period == "month":
        start_date = datetime(end_date.year, end_date.month, 1)
    elif period == "quarter":
        quarter_start_month = ((end_date.month - 1) // 3) * 3 + 1
        start_date = datetime(end_date.year, quarter_start_month, 1)
    elif period == "year":
        start_date = datetime(end_date.year, 1, 1)
    else:
        raise ValueError(f"Invalid period: {period}")
    
    # Get revenue (invoices)
    invoices = get_invoices(
        period_start=start_date.strftime("%Y-%m-%d"),
        period_end=end_date.strftime("%Y-%m-%d"),
        limit=500
    )
    
    # Calculate total revenue
    total_revenue = sum(invoice.get("total_amount", 0) for invoice in invoices.get("data", []))
    
    # Get expenses
    expenses = get_expenses(
        period_start=start_date.strftime("%Y-%m-%d"),
        period_end=end_date.strftime("%Y-%m-%d"),
        limit=500
    )
    
    # Calculate total expenses
    total_expenses = sum(expense.get("total_amount", 0) for expense in expenses.get("data", []))
    
    # Calculate profit and margin
    profit = total_revenue - total_expenses
    margin = (profit / total_revenue * 100) if total_revenue > 0 else 0
    
    return {
        "period": period,
        "start_date": start_date.strftime("%Y-%m-%d"),
        "end_date": end_date.strftime("%Y-%m-%d"),
        "total_revenue": total_revenue,
        "total_expenses": total_expenses,
        "profit": profit,
        "margin_percent": round(margin, 2)
    }

def get_cash_flow(months=3):
    """
    Analyze cash flow over the past months
    
    Args:
        months (int, optional): Number of months to analyze. Defaults to 3.
    
    Returns:
        dict: Cash flow analysis
    """
    # Get date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30 * months)
    
    # Get invoices (cash in)
    invoices = get_invoices(
        period_start=start_date.strftime("%Y-%m-%d"),
        period_end=end_date.strftime("%Y-%m-%d"),
        limit=500
    )
    
    # Get expenses (cash out)
    expenses = get_expenses(
        period_start=start_date.strftime("%Y-%m-%d"),
        period_end=end_date.strftime("%Y-%m-%d"),
        limit=500
    )
    
    # Organize by month
    monthly_cash_flow = {}
    
    for invoice in invoices.get("data", []):
        invoice_date = datetime.strptime(invoice.get("date"), "%Y-%m-%d")
        month_key = invoice_date.strftime("%Y-%m")
        amount = invoice.get("total_amount", 0)
        
        if month_key not in monthly_cash_flow:
            monthly_cash_flow[month_key] = {"cash_in": 0, "cash_out": 0, "net": 0}
        
        monthly_cash_flow[month_key]["cash_in"] += amount
    
    for expense in expenses.get("data", []):
        expense_date = datetime.strptime(expense.get("date"), "%Y-%m-%d")
        month_key = expense_date.strftime("%Y-%m")
        amount = expense.get("total_amount", 0)
        
        if month_key not in monthly_cash_flow:
            monthly_cash_flow[month_key] = {"cash_in": 0, "cash_out": 0, "net": 0}
        
        monthly_cash_flow[month_key]["cash_out"] += amount
    
    # Calculate net cash flow
    total_cash_in = 0
    total_cash_out = 0
    
    for month, data in monthly_cash_flow.items():
        data["net"] = data["cash_in"] - data["cash_out"]
        total_cash_in += data["cash_in"]
        total_cash_out += data["cash_out"]
    
    return {
        "monthly_cash_flow": monthly_cash_flow,
        "total_cash_in": total_cash_in,
        "total_cash_out": total_cash_out,
        "net_cash_flow": total_cash_in - total_cash_out
    }

def get_all_pennylane_data():
    """
    Get all relevant Pennylane data for the dashboard
    
    Returns:
        dict: Consolidated Pennylane data
    """
    if not initialize_pennylane_client():
        logger.warning("Pennylane client not initialized")
        return {}
    
    try:
        profitability = get_profitability()
        bank_balance = get_bank_balance()
        expense_trends = get_expense_trends()
        cash_flow = get_cash_flow()
        
        return {
            "profitability": profitability,
            "bank_balance": bank_balance,
            "expense_trends": expense_trends,
            "cash_flow": cash_flow
        }
    except Exception as e:
        logger.error(f"Error getting Pennylane data: {str(e)}")
        return {}