import random
import uuid
from datetime import datetime, timedelta
import logging
import json

logger = logging.getLogger(__name__)

# Define constants for mock data generation
COMPANY_NAMES = [
    "Acme Technologies", "Globex Corporation", "Initech Systems", "Umbrella Corp", 
    "Cyberdyne Systems", "Soylent Green", "Stark Industries", "Wayne Enterprises",
    "Massive Dynamic", "Xanatos Enterprises", "Aperture Science", "Weyland-Yutani",
    "Tyrell Corporation", "Spacely Sprockets", "Cogswell Cogs", "Oceanic Airlines",
    "Nakatomi Trading Corp", "Wonka Industries", "Dunder Mifflin", "Bluth Company"
]

CONTACT_FIRST_NAMES = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Susan", "Richard", "Jessica", "Joseph", "Sarah",
    "Thomas", "Karen", "Charles", "Nancy", "Christopher", "Lisa", "Daniel", "Margaret"
]

CONTACT_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson",
    "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin",
    "Thompson", "Garcia", "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee"
]

DEAL_NAMES = [
    "Enterprise License", "Product Expansion", "New Implementation", "Services Contract",
    "Annual Renewal", "Multi-Year Agreement", "Platform Migration", "Software Bundle",
    "Consulting Services", "Support Package", "Training Program", "Custom Development",
    "Add-On License", "Maintenance Contract", "Partner Agreement", "Strategic Alliance"
]

SUBSCRIPTION_PLANS = [
    "Basic", "Standard", "Professional", "Enterprise", "Premium", "Plus", 
    "Starter", "Team", "Business", "Corporate", "Ultimate", "Essential"
]

PROJECT_NAMES = [
    "Alpha Development", "Beta Release", "Client Portal Redesign", "Data Migration",
    "Enterprise Integration", "Field Service Module", "Global Expansion",
    "Health Dashboard", "Infrastructure Upgrade", "Jupyter Integration",
    "Knowledge Base", "Legacy System Migration", "Mobile Application", 
    "Network Overhaul", "Operational Excellence", "Process Automation"
]

# Mock data generation functions
def generate_hubspot_mock_data():
    """Generate mock HubSpot data for the dashboard"""
    try:
        # Generate mock deals
        deals = []
        deal_stages = ["prospecting", "qualification", "proposal", "negotiation", "closed_won", "closed_lost"]
        stages_dist = [0.2, 0.25, 0.3, 0.15, 0.07, 0.03]  # Distribution of deals across stages
        
        for i in range(random.randint(30, 50)):
            # Determine stage based on distribution
            stage_idx = random.choices(range(len(deal_stages)), weights=stages_dist, k=1)[0]
            stage = deal_stages[stage_idx]
            
            # Generate random amount based on stage (later stages tend to have more refined/higher amounts)
            if stage in ["closed_won", "negotiation"]:
                amount = random.randint(50000, 500000)
            elif stage in ["proposal"]:
                amount = random.randint(20000, 300000)
            else:
                amount = random.randint(5000, 200000)
            
            # Generate random close date (future dates for open deals, past for closed)
            today = datetime.now()
            if stage in ["closed_won", "closed_lost"]:
                close_date = (today - timedelta(days=random.randint(1, 60))).strftime("%Y-%m-%d")
            else:
                close_date = (today + timedelta(days=random.randint(10, 120))).strftime("%Y-%m-%d")
            
            # Last modified date (more recent for active deals)
            if stage not in ["closed_won", "closed_lost"]:
                last_modified = int((today - timedelta(days=random.randint(0, 10))).timestamp() * 1000)
            else:
                last_modified = int((today - timedelta(days=random.randint(10, 60))).timestamp() * 1000)
            
            deal = {
                "id": str(uuid.uuid4()),
                "name": f"{random.choice(COMPANY_NAMES)} - {random.choice(DEAL_NAMES)}",
                "amount": amount,
                "close_date": close_date,
                "pipeline": "default",
                "stage": stage,
                "last_modified": str(last_modified)
            }
            deals.append(deal)
        
        # Generate mock contacts
        contacts = []
        lead_statuses = ["new", "open", "in progress", "qualified", "unqualified"]
        lifecycle_stages = ["subscriber", "lead", "marketing qualified lead", "sales qualified lead", "opportunity", "customer"]
        
        for i in range(random.randint(50, 100)):
            first_name = random.choice(CONTACT_FIRST_NAMES)
            last_name = random.choice(CONTACT_LAST_NAMES)
            company = random.choice(COMPANY_NAMES)
            
            contact = {
                "id": str(uuid.uuid4()),
                "first_name": first_name,
                "last_name": last_name,
                "email": f"{first_name.lower()}.{last_name.lower()}@{company.lower().replace(' ', '')}.com",
                "phone": f"+1{random.randint(2000000000, 9999999999)}",
                "company": company,
                "lead_status": random.choice(lead_statuses),
                "lifecycle_stage": random.choice(lifecycle_stages)
            }
            contacts.append(contact)
        
        # Generate mock activities
        activities = []
        activity_types = ["email", "call", "meeting", "note", "task"]
        
        for i in range(random.randint(20, 40)):
            days_ago = random.randint(0, 14)
            activity_date = datetime.now() - timedelta(days=days_ago)
            
            activity_type = random.choice(activity_types)
            
            if activity_type == "call":
                title = f"Call with {random.choice(CONTACT_FIRST_NAMES)} {random.choice(CONTACT_LAST_NAMES)}"
                description = f"Discussed {random.choice(['project timeline', 'pricing', 'implementation details', 'next steps', 'contract renewal'])}"
            elif activity_type == "email":
                title = f"Email to {random.choice(CONTACT_FIRST_NAMES)} {random.choice(CONTACT_LAST_NAMES)}"
                description = f"Sent information about {random.choice(['pricing', 'product features', 'contract details', 'upcoming meeting', 'follow-up'])}"
            elif activity_type == "meeting":
                title = f"Meeting with {random.choice(COMPANY_NAMES)}"
                description = f"Met with client to discuss {random.choice(['project progress', 'strategy', 'requirements', 'issues', 'roadmap'])}"
            else:
                title = f"{activity_type.capitalize()}: {random.choice(COMPANY_NAMES)}"
                description = f"Internal {activity_type} about {random.choice(['deal strategy', 'client feedback', 'action items', 'follow-up tasks', 'account review'])}"
            
            activity = {
                "id": str(uuid.uuid4()),
                "type": activity_type,
                "timestamp": int(activity_date.timestamp() * 1000),
                "title": title,
                "description": description
            }
            activities.append(activity)
        
        # Generate pipelines
        pipelines = [
            {
                "id": "default",
                "label": "Sales Pipeline",
                "stages": [
                    {"id": "prospecting", "label": "Prospecting"},
                    {"id": "qualification", "label": "Qualification"},
                    {"id": "proposal", "label": "Proposal"},
                    {"id": "negotiation", "label": "Negotiation"},
                    {"id": "closed_won", "label": "Closed Won"},
                    {"id": "closed_lost", "label": "Closed Lost"}
                ]
            }
        ]
        
        # Calculate metrics
        total_deal_value = sum(deal.get("amount", 0) for deal in deals)
        
        deals_by_stage = {}
        for deal in deals:
            stage = deal.get("stage", "unknown")
            if stage not in deals_by_stage:
                deals_by_stage[stage] = 0
            deals_by_stage[stage] += 1
        
        # Get deals updated in the last 7 days
        one_week_ago = int((datetime.now() - timedelta(days=7)).timestamp() * 1000)
        recent_deals = [
            deal for deal in deals
            if deal.get("last_modified") and int(deal.get("last_modified", 0)) > one_week_ago
        ]
        
        return {
            "deals": deals,
            "contacts": contacts,
            "activities": activities,
            "pipelines": pipelines,
            "metrics": {
                "total_deal_value": total_deal_value,
                "deals_by_stage": deals_by_stage,
                "recent_deals_count": len(recent_deals),
                "contacts_count": len(contacts)
            }
        }
    except Exception as e:
        logger.error(f"Error generating HubSpot mock data: {str(e)}")
        return {
            "deals": [],
            "contacts": [],
            "activities": [],
            "pipelines": [],
            "metrics": {
                "total_deal_value": 0,
                "deals_by_stage": {},
                "recent_deals_count": 0,
                "contacts_count": 0
            },
            "error": str(e)
        }

def generate_chargebee_mock_data():
    """Generate mock Chargebee data for the dashboard"""
    try:
        # Generate mock subscriptions
        subscriptions = []
        statuses = ["active", "active", "active", "active", "active", "active", "active", "active", "cancelled", "non_renewing"]  # Weighted distribution
        
        for i in range(random.randint(40, 70)):
            # Create customer ID
            customer_id = f"cust_{uuid.uuid4().hex[:8]}"
            
            # Select plan
            plan_type = random.choice(SUBSCRIPTION_PLANS)
            
            # Determine amount based on plan type
            if plan_type == "Basic" or plan_type == "Starter" or plan_type == "Essential":
                amount = random.randint(20, 100)
            elif plan_type == "Professional" or plan_type == "Team" or plan_type == "Standard":
                amount = random.randint(100, 500)
            else:  # Enterprise, Premium, etc.
                amount = random.randint(500, 5000)
            
            # Generate subscription dates
            today = datetime.now()
            created_at = today - timedelta(days=random.randint(30, 730))  # Between 1 month and 2 years ago
            current_term_start = created_at + timedelta(days=((today - created_at).days // 30) * 30)  # Align to monthly periods
            current_term_end = current_term_start + timedelta(days=30)  # Monthly subscription
            
            # Generate billing period
            billing_period = random.choice([1, 3, 6, 12])  # in months
            
            # Calculate next renewal date
            next_billing = current_term_end
            
            # Adjust for cancelled or non-renewing subscriptions
            status = random.choice(statuses)
            if status == "cancelled":
                cancelled_at = today - timedelta(days=random.randint(1, 60))
                next_billing = None
            elif status == "non_renewing":
                next_billing = current_term_end
            
            subscription = {
                "id": f"sub_{uuid.uuid4().hex[:10]}",
                "customer_id": customer_id,
                "plan_id": f"{plan_type}_plan",
                "status": status,
                "amount": amount,
                "billing_period": billing_period,
                "billing_period_unit": "month",
                "created_at": created_at.strftime("%Y-%m-%d"),
                "current_term_start": current_term_start.strftime("%Y-%m-%d"),
                "current_term_end": current_term_end.strftime("%Y-%m-%d"),
                "next_billing": next_billing.strftime("%Y-%m-%d") if next_billing else None
            }
            subscriptions.append(subscription)
        
        # Generate mock customers
        customers = []
        companies_used = set()
        
        for subscription in subscriptions:
            customer_id = subscription.get("customer_id")
            
            # Try to get a company name not already used
            available_companies = [c for c in COMPANY_NAMES if c not in companies_used]
            if not available_companies:
                available_companies = COMPANY_NAMES
                
            company = random.choice(available_companies)
            companies_used.add(company)
            
            first_name = random.choice(CONTACT_FIRST_NAMES)
            last_name = random.choice(CONTACT_LAST_NAMES)
            
            customer = {
                "id": customer_id,
                "first_name": first_name,
                "last_name": last_name,
                "email": f"{first_name.lower()}.{last_name.lower()}@{company.lower().replace(' ', '')}.com",
                "company": company,
                "created_at": (datetime.now() - timedelta(days=random.randint(60, 730))).strftime("%Y-%m-%d")
            }
            customers.append(customer)
        
        # Generate mock invoices
        invoices = []
        
        for subscription in subscriptions:
            if subscription.get("status") == "active":
                # Create between 1-6 invoices per active subscription
                for i in range(random.randint(1, 6)):
                    # Invoice date (from past 6 months)
                    invoice_date = (datetime.now() - timedelta(days=random.randint(1, 180))).strftime("%Y-%m-%d")
                    
                    # Calculate invoice amount (subscription amount + possible add-ons)
                    base_amount = subscription.get("amount", 0)
                    has_add_ons = random.random() < 0.3  # 30% chance of add-ons
                    
                    if has_add_ons:
                        add_on_amount = random.randint(10, int(base_amount * 0.5))
                        total_amount = base_amount + add_on_amount
                    else:
                        total_amount = base_amount
                    
                    # Determine invoice status
                    if random.random() < 0.9:  # 90% paid
                        status = "paid"
                        paid_at = datetime.strptime(invoice_date, "%Y-%m-%d") + timedelta(days=random.randint(0, 10))
                        paid_at = paid_at.strftime("%Y-%m-%d")
                    else:
                        status = "payment_due"
                        paid_at = None
                    
                    invoice = {
                        "id": f"inv_{uuid.uuid4().hex[:10]}",
                        "subscription_id": subscription.get("id"),
                        "customer_id": subscription.get("customer_id"),
                        "date": invoice_date,
                        "amount": total_amount,
                        "status": status,
                        "paid_at": paid_at
                    }
                    invoices.append(invoice)
        
        # Calculate MRR
        active_subs = [s for s in subscriptions if s.get("status") == "active"]
        mrr = sum(sub.get("amount", 0) for sub in active_subs)
        
        # Calculate metrics
        active_count = len(active_subs)
        cancelled_count = len([s for s in subscriptions if s.get("status") == "cancelled"])
        
        # Recent invoices (last 30 days)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        recent_invoices = [inv for inv in invoices if inv.get("date") >= thirty_days_ago]
        recent_revenue = sum(inv.get("amount", 0) for inv in recent_invoices)
        
        return {
            "subscriptions": subscriptions,
            "customers": customers,
            "invoices": invoices,
            "mrr": mrr,
            "metrics": {
                "active_subscriptions_count": active_count,
                "canceled_subscriptions_count": cancelled_count,
                "recent_invoices_count": len(recent_invoices),
                "recent_revenue": recent_revenue
            }
        }
    except Exception as e:
        logger.error(f"Error generating Chargebee mock data: {str(e)}")
        return {
            "subscriptions": [],
            "customers": [],
            "invoices": [],
            "mrr": 0,
            "metrics": {
                "active_subscriptions_count": 0,
                "canceled_subscriptions_count": 0,
                "recent_invoices_count": 0,
                "recent_revenue": 0
            },
            "error": str(e)
        }

def generate_ooti_mock_data():
    """Generate mock OOTI data for the dashboard"""
    try:
        # Generate mock projects
        projects = []
        statuses = ["active", "active", "active", "active", "completed", "on_hold", "at_risk"]  # Weighted distribution
        
        for i in range(random.randint(15, 25)):
            # Create project
            status = random.choice(statuses)
            
            # Generate realistic timelines
            today = datetime.now()
            start_date = today - timedelta(days=random.randint(30, 365))
            
            if status == "completed":
                end_date = start_date + timedelta(days=random.randint(30, 180))
                actual_end_date = end_date + timedelta(days=random.randint(-10, 30))  # Could be early or late
            elif status == "active" or status == "at_risk" or status == "on_hold":
                end_date = start_date + timedelta(days=random.randint(60, 365))
                actual_end_date = None
            else:
                end_date = None
                actual_end_date = None
            
            # Generate budget and spent amounts
            budget = random.randint(50000, 500000)
            
            if status == "completed":
                # Completed projects have final spend
                overspend_chance = random.random()
                if overspend_chance < 0.2:  # 20% chance of overspend
                    spent = budget * random.uniform(1.05, 1.3)  # 5-30% overspend
                elif overspend_chance < 0.6:  # 40% chance of exact spend
                    spent = budget
                else:  # 40% chance of underspend
                    spent = budget * random.uniform(0.8, 0.98)  # 2-20% underspend
            elif status == "active" or status == "at_risk":
                # Active projects have partial spend
                progress = random.uniform(0.1, 0.9)  # Completion percentage
                spent = budget * progress
                
                # At-risk projects might have higher spend relative to progress
                if status == "at_risk":
                    spent *= random.uniform(1.1, 1.3)  # 10-30% over budget for progress
            elif status == "on_hold":
                # On hold projects have some spend
                spent = budget * random.uniform(0.1, 0.5)
            else:
                spent = 0
            
            # Calculate completion percentage
            if status == "completed":
                completion = 100
            elif status == "active" or status == "at_risk" or status == "on_hold":
                # Base completion on spent percentage with some variation
                completion = (spent / budget) * 100
                completion = min(99, max(5, completion + random.uniform(-10, 10)))
            else:
                completion = 0
            
            project = {
                "id": f"proj_{uuid.uuid4().hex[:8]}",
                "name": random.choice(PROJECT_NAMES),
                "client": random.choice(COMPANY_NAMES),
                "status": status,
                "start_date": start_date.strftime("%Y-%m-%d"),
                "end_date": end_date.strftime("%Y-%m-%d") if end_date else None,
                "actual_end_date": actual_end_date.strftime("%Y-%m-%d") if actual_end_date else None,
                "budget": budget,
                "spent": spent,
                "completion_percentage": completion
            }
            projects.append(project)
        
        # Generate mock resource data
        resources = []
        departments = ["Engineering", "Design", "Product", "QA", "DevOps", "Implementation"]
        
        for dept in departments:
            # Define department size
            if dept == "Engineering":
                total_staff = random.randint(15, 30)
            elif dept == "Design":
                total_staff = random.randint(5, 12)
            elif dept == "Product":
                total_staff = random.randint(8, 15)
            elif dept == "QA":
                total_staff = random.randint(5, 10)
            elif dept == "DevOps":
                total_staff = random.randint(3, 8)
            else:  # Implementation
                total_staff = random.randint(8, 15)
            
            # Allocate staff
            allocation_rate = random.uniform(0.7, 0.95)
            allocated = int(total_staff * allocation_rate)
            
            # Calculate billable hours and utilization
            billable_hours = allocated * 40 * 4  # 40 hours per week, 4 weeks
            target_hours = total_staff * 40 * 4 * 0.8  # Assuming 80% target utilization
            utilization = (billable_hours / target_hours) * 100
            
            resource = {
                "department": dept,
                "total_staff": total_staff,
                "allocated": allocated,
                "available": total_staff - allocated,
                "billable_hours": billable_hours,
                "utilization": utilization
            }
            resources.append(resource)
        
        # Generate finance summary
        monthly_revenue = sum(project.get("budget", 0) / (project.get("end_date") and project.get("start_date") and 
                             (datetime.strptime(project.get("end_date"), "%Y-%m-%d") - 
                              datetime.strptime(project.get("start_date"), "%Y-%m-%d")).days or 30) * 30
                             for project in projects if project.get("status") in ["active", "at_risk"])
        
        cash_flow = monthly_revenue - sum(resource.get("total_staff", 0) * 8000 for resource in resources)  # Rough salary estimate
        
        finance_summary = {
            "monthly_revenue": monthly_revenue,
            "monthly_costs": monthly_revenue - cash_flow,
            "cash_flow": cash_flow,
            "accounts_receivable": sum(project.get("budget", 0) - project.get("spent", 0) 
                                     for project in projects if project.get("status") in ["active", "at_risk"]),
            "profit_margin": (cash_flow / monthly_revenue * 100) if monthly_revenue > 0 else 0
        }
        
        # Generate KPI indicators
        indicators = {
            "delivery_on_time": random.randint(70, 95),
            "client_satisfaction": random.randint(75, 98),
            "employee_satisfaction": random.randint(65, 90),
            "project_profitability": random.randint(15, 30),
            "resource_utilization": sum(r.get("utilization", 0) for r in resources) / len(resources) if resources else 0,
            "sales_pipeline_value": random.randint(2000000, 4000000),
            "win_rate": random.randint(25, 45),
            "average_deal_size": random.randint(150000, 300000),
            "budget_adherence": random.randint(80, 95),
            "project_success_rate": random.randint(75, 95)
        }
        
        # Calculate aggregate metrics
        active_projects_count = len([p for p in projects if p.get("status") == "active"])
        at_risk_projects_count = len([p for p in projects if p.get("status") == "at_risk"])
        
        total_budget = sum(p.get("budget", 0) for p in projects)
        total_spent = sum(p.get("spent", 0) for p in projects)
        
        budget_utilization = (total_spent / total_budget * 100) if total_budget > 0 else 0
        
        overall_resource_utilization = sum(r.get("utilization", 0) for r in resources) / len(resources) if resources else 0
        
        return {
            "projects": projects,
            "resources": resources,
            "finance_summary": finance_summary,
            "indicators": indicators,
            "metrics": {
                "active_projects_count": active_projects_count,
                "at_risk_projects_count": at_risk_projects_count,
                "total_budget": total_budget,
                "total_spent": total_spent,
                "total_remaining": total_budget - total_spent,
                "budget_utilization": budget_utilization,
                "overall_resource_utilization": overall_resource_utilization
            }
        }
    except Exception as e:
        logger.error(f"Error generating OOTI mock data: {str(e)}")
        return {
            "projects": [],
            "resources": [],
            "finance_summary": {},
            "indicators": {},
            "metrics": {
                "active_projects_count": 0,
                "at_risk_projects_count": 0,
                "total_budget": 0,
                "total_spent": 0,
                "total_remaining": 0,
                "budget_utilization": 0,
                "overall_resource_utilization": 0
            },
            "error": str(e)
        }