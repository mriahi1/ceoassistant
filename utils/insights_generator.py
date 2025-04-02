import logging
from datetime import datetime, timedelta
from api.openai_integration import generate_strategic_insights, generate_action_items, generate_key_metrics

logger = logging.getLogger(__name__)

def generate_insights(data):
    """
    Generate insights from the consolidated platform data
    
    Args:
        data (dict): Consolidated platform data
    
    Returns:
        list: List of insights
    """
    try:
        return generate_strategic_insights(data)
    except Exception as e:
        logger.error(f"Error generating insights: {str(e)}")
        return [
            "Unable to generate insights due to an error.",
            f"Error: {str(e)}"
        ]

def generate_pipeline_health_insights(data):
    """
    Generate insights specifically about sales pipeline health
    
    Args:
        data (dict): Consolidated platform data
    
    Returns:
        dict: Pipeline health analysis
    """
    try:
        # Extract HubSpot deals
        deals = data.get('hubspot', {}).get('deals', [])
        
        if not deals:
            return {
                "status": "No data",
                "insights": ["No deal data available to analyze pipeline health."]
            }
        
        # Calculate total value
        total_value = sum(deal.get('amount', 0) for deal in deals)
        
        # Group by stage
        stages = {}
        for deal in deals:
            stage = deal.get('stage', 'unknown')
            if stage not in stages:
                stages[stage] = {
                    'count': 0,
                    'value': 0
                }
            stages[stage]['count'] += 1
            stages[stage]['value'] += deal.get('amount', 0)
        
        # Calculate pipeline health score (simple version)
        # A real implementation would have more sophisticated logic
        pipeline_score = min(100, max(0, len(deals) * 5))
        
        # Identify deals closing in next 30 days
        today = datetime.now()
        closing_soon = []
        
        for deal in deals:
            if deal.get('close_date'):
                try:
                    close_date = datetime.strptime(deal.get('close_date'), '%Y-%m-%d')
                    if close_date and close_date <= today + timedelta(days=30):
                        closing_soon.append(deal)
                except (ValueError, TypeError):
                    pass
        
        # Generate insights
        insights = []
        
        if closing_soon:
            insights.append(f"{len(closing_soon)} deals worth ${sum(deal.get('amount', 0) for deal in closing_soon):,.2f} are scheduled to close in the next 30 days.")
        
        if pipeline_score < 30:
            insights.append("Pipeline health is critical. Immediate attention required to add more deals.")
        elif pipeline_score < 60:
            insights.append("Pipeline health is below target. Consider increasing prospecting activities.")
        else:
            insights.append("Pipeline health is good. Focus on moving deals through stages effectively.")
        
        # Add stage-specific insights
        if stages:
            # Find the stage with most deals stuck
            most_deals_stage = max(stages.items(), key=lambda x: x[1]['count'])
            insights.append(f"The {most_deals_stage[0]} stage has the most deals ({most_deals_stage[1]['count']}). Consider reviewing for bottlenecks.")
        
        return {
            "status": "Generated",
            "score": pipeline_score,
            "total_value": total_value,
            "deals_by_stage": stages,
            "deals_closing_soon": len(closing_soon),
            "value_closing_soon": sum(deal.get('amount', 0) for deal in closing_soon),
            "insights": insights
        }
    except Exception as e:
        logger.error(f"Error generating pipeline health insights: {str(e)}")
        return {
            "status": "Error",
            "insights": [f"Error analyzing pipeline health: {str(e)}"]
        }

def generate_revenue_insights(data):
    """
    Generate insights about revenue trends
    
    Args:
        data (dict): Consolidated platform data
    
    Returns:
        dict: Revenue insights
    """
    try:
        # Extract Chargebee data
        chargebee = data.get('chargebee', {})
        mrr = chargebee.get('mrr', 0)
        subscriptions = chargebee.get('subscriptions', [])
        invoices = chargebee.get('invoices', [])
        
        # Extract OOTI financial data
        ooti = data.get('ooti', {})
        finances = ooti.get('finance_summary', {})
        
        if not mrr and not finances:
            return {
                "status": "No data",
                "insights": ["No revenue data available to analyze trends."]
            }
        
        # Calculate basic metrics
        arr = mrr * 12 if mrr else 0
        active_subs = len([s for s in subscriptions if s.get('status') == 'active'])
        
        # Calculate average subscription value
        avg_sub_value = mrr / active_subs if active_subs > 0 else 0
        
        # Count recent invoices (last 30 days)
        today = datetime.now()
        thirty_days_ago = (today - timedelta(days=30)).isoformat()
        recent_invoices = [
            inv for inv in invoices
            if inv.get('date') and inv.get('date') > thirty_days_ago
        ]
        recent_revenue = sum(inv.get('amount', 0) for inv in recent_invoices)
        
        # Generate insights
        insights = []
        
        if mrr:
            insights.append(f"Current MRR is ${mrr:,.2f}, projecting to ${arr:,.2f} ARR.")
        
        if active_subs:
            insights.append(f"Average subscription value is ${avg_sub_value:,.2f} across {active_subs} active subscriptions.")
        
        if recent_invoices:
            insights.append(f"Generated ${recent_revenue:,.2f} in revenue over the last 30 days from {len(recent_invoices)} invoices.")
        
        if finances.get('monthly_revenue'):
            insights.append(f"Monthly revenue from OOTI is ${finances.get('monthly_revenue'):,.2f}.")
        
        if finances.get('cash_flow'):
            cash_flow = finances.get('cash_flow')
            if cash_flow < 0:
                insights.append(f"Negative cash flow of ${abs(cash_flow):,.2f}. Immediate attention required.")
            else:
                insights.append(f"Positive cash flow of ${cash_flow:,.2f}.")
        
        return {
            "status": "Generated",
            "mrr": mrr,
            "arr": arr,
            "active_subscriptions": active_subs,
            "avg_subscription_value": avg_sub_value,
            "recent_revenue": recent_revenue,
            "finance_summary": finances,
            "insights": insights
        }
    except Exception as e:
        logger.error(f"Error generating revenue insights: {str(e)}")
        return {
            "status": "Error",
            "insights": [f"Error analyzing revenue trends: {str(e)}"]
        }

def generate_operational_insights(data):
    """
    Generate insights about operational performance
    
    Args:
        data (dict): Consolidated platform data
    
    Returns:
        dict: Operational insights
    """
    try:
        # Extract OOTI data
        ooti = data.get('ooti', {})
        projects = ooti.get('projects', [])
        resources = ooti.get('resources', [])
        indicators = ooti.get('indicators', {})
        
        if not projects and not resources:
            return {
                "status": "No data",
                "insights": ["No operational data available to analyze performance."]
            }
        
        # Calculate metrics
        active_projects = len([p for p in projects if p.get('status') == 'active'])
        at_risk_projects = len([p for p in projects if p.get('status') == 'at_risk'])
        
        # Resource utilization
        total_staff = sum(r.get('total_staff', 0) for r in resources)
        total_allocated = sum(r.get('allocated', 0) for r in resources)
        utilization_rate = (total_allocated / total_staff * 100) if total_staff > 0 else 0
        
        # Calculate total budget and spent
        total_budget = sum(p.get('budget', 0) for p in projects)
        total_spent = sum(p.get('spent', 0) for p in projects)
        budget_utilization = (total_spent / total_budget * 100) if total_budget > 0 else 0
        
        # Generate insights
        insights = []
        
        if active_projects:
            insights.append(f"Managing {active_projects} active projects with a total budget of ${total_budget:,.2f}.")
        
        if at_risk_projects:
            insights.append(f"ALERT: {at_risk_projects} projects are currently at risk and require attention.")
        
        if utilization_rate:
            if utilization_rate > 90:
                insights.append(f"Resource utilization is very high at {utilization_rate:.1f}%. Consider hiring to prevent burnout.")
            elif utilization_rate < 70:
                insights.append(f"Resource utilization is low at {utilization_rate:.1f}%. Consider optimizing allocation.")
            else:
                insights.append(f"Resource utilization is healthy at {utilization_rate:.1f}%.")
        
        if budget_utilization:
            if budget_utilization > 85 and budget_utilization < 100:
                insights.append(f"Budget utilization is at {budget_utilization:.1f}%. Projects are approaching budget limits.")
            elif budget_utilization > 100:
                insights.append(f"ALERT: Budget overrun at {budget_utilization:.1f}%. Immediate cost control measures needed.")
            else:
                insights.append(f"Budget utilization is at {budget_utilization:.1f}%.")
        
        # Add insights from KPIs
        if indicators.get('delivery_on_time'):
            on_time = indicators.get('delivery_on_time')
            if on_time < 80:
                insights.append(f"On-time delivery is critical at {on_time}%. Review project management processes.")
            else:
                insights.append(f"On-time delivery is at {on_time}%.")
        
        if indicators.get('client_satisfaction'):
            satisfaction = indicators.get('client_satisfaction')
            if satisfaction < 80:
                insights.append(f"Client satisfaction is concerning at {satisfaction}%. Review service quality.")
            else:
                insights.append(f"Client satisfaction is healthy at {satisfaction}%.")
        
        return {
            "status": "Generated",
            "active_projects": active_projects,
            "at_risk_projects": at_risk_projects,
            "resource_utilization": utilization_rate,
            "budget_utilization": budget_utilization,
            "indicators": indicators,
            "insights": insights
        }
    except Exception as e:
        logger.error(f"Error generating operational insights: {str(e)}")
        return {
            "status": "Error",
            "insights": [f"Error analyzing operational performance: {str(e)}"]
        }
