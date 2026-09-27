from typing import List
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.graph_schemas import GraphData, FraudCampaign, EntityInvestigationResponse
from app.services.graph_engine import graph_engine

router = APIRouter()

@router.get("/graph/full", response_model=GraphData)
def get_full_graph(db: Session = Depends(get_db)):
    """
    Returns the complete entity relationship graph containing reports, phones, UPIs,
    domains, URLs, impersonated brands, and locations for interactive visualization.
    """
    return graph_engine.get_full_graph(db)

@router.get("/graph/campaigns", response_model=List[FraudCampaign])
def get_fraud_campaigns(db: Session = Depends(get_db)):
    """
    Identifies and clusters syndicated fraud campaigns connecting multiple reports
    that share common telephone numbers, UPI accounts, or domain infrastructure.
    """
    return graph_engine.detect_fraud_campaigns(db)

@router.get("/graph/investigate/{entity_value}", response_model=EntityInvestigationResponse)
def investigate_entity(
    entity_value: str,
    db: Session = Depends(get_db)
):
    """
    Deep threat intelligence search. Given an entity (phone, UPI, domain, or report ID),
    traverses 2-hop graph neighborhood to identify associated fraud campaigns and linked indicators.
    """
    if not entity_value.strip():
        raise HTTPException(status_code=400, detail="Entity query cannot be empty")
    return graph_engine.investigate_entity(db, entity_value)
