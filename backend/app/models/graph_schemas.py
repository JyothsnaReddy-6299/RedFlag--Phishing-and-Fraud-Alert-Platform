from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # REPORT, PHONE, UPI, URL, DOMAIN, BRAND, LOCATION, SCAM_TYPE
    properties: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # REPORTED_IN, HAS_PHONE, HAS_UPI, HAS_URL, IMPERSONATES, LOCATED_IN, CONNECTED_TO

class GraphData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class FraudCampaign(BaseModel):
    campaign_id: str
    name: str
    scam_category: str
    impersonated_brand: Optional[str] = None
    report_count: int
    threat_indicators_count: int
    associated_locations: List[str] = Field(default_factory=list)
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class EntityInvestigationResponse(BaseModel):
    queried_entity: str
    entity_type: Optional[str] = None
    found: bool
    connection_count: int
    connected_campaign_ids: List[str] = Field(default_factory=list)
    subgraph: GraphData
