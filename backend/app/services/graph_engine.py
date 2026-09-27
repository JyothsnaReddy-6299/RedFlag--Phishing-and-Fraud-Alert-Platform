import networkx as nx
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from app.db.models import Report, ThreatIndicator
from app.models.graph_schemas import GraphNode, GraphEdge, GraphData, FraudCampaign, EntityInvestigationResponse
from app.services.entity_extractor import entity_extractor

class ThreatGraphEngine:
    def __init__(self):
        self.graph = nx.MultiGraph()

    def sync_from_database(self, db: Session):
        """
        Reconstructs the threat relationship graph from database reports and threat indicators.
        """
        self.graph.clear()
        reports = db.query(Report).all()

        for r in reports:
            rep_node_id = f"Report:{r.report_id}"
            self.graph.add_node(
                rep_node_id,
                label=r.report_id,
                type="REPORT",
                category=r.scam_category,
                risk_score=r.initial_risk_score,
                status=r.status,
                created_at=r.created_at.isoformat() if r.created_at else None
            )

            # Scam Category Node
            if r.scam_category:
                cat_node_id = f"Category:{r.scam_category}"
                self.graph.add_node(cat_node_id, label=r.scam_category, type="SCAM_TYPE")
                self.graph.add_edge(rep_node_id, cat_node_id, relationship="CATEGORIZED_AS")

            # Phone Node
            if r.phone_number:
                phone_node_id = f"Phone:{r.phone_number}"
                self.graph.add_node(phone_node_id, label=r.phone_number, type="PHONE")
                self.graph.add_edge(rep_node_id, phone_node_id, relationship="HAS_PHONE")

            # UPI Node
            if r.upi_id:
                upi_node_id = f"UPI:{r.upi_id.lower()}"
                self.graph.add_node(upi_node_id, label=r.upi_id.lower(), type="UPI")
                self.graph.add_edge(rep_node_id, upi_node_id, relationship="HAS_UPI")

            # URL & Domain Nodes
            if r.raw_url:
                url_node_id = f"URL:{r.raw_url}"
                self.graph.add_node(url_node_id, label=r.raw_url, type="URL")
                self.graph.add_edge(rep_node_id, url_node_id, relationship="HAS_URL")

                try:
                    parsed = urlparse(r.raw_url if r.raw_url.startswith("http") else f"http://{r.raw_url}")
                    domain = parsed.netloc.split(":")[0].lower()
                    if domain.startswith("www."):
                        domain = domain[4:]
                    if domain:
                        domain_node_id = f"Domain:{domain}"
                        self.graph.add_node(domain_node_id, label=domain, type="DOMAIN")
                        self.graph.add_edge(url_node_id, domain_node_id, relationship="HOSTED_ON")
                        self.graph.add_edge(rep_node_id, domain_node_id, relationship="LINKED_TO")
                except Exception:
                    pass

            # Brand / Organization Node
            if r.organization:
                brand_node_id = f"Brand:{r.organization}"
                self.graph.add_node(brand_node_id, label=r.organization, type="BRAND")
                self.graph.add_edge(rep_node_id, brand_node_id, relationship="IMPERSONATES")

            # Location Node
            location = r.location_area or r.location_city
            if location:
                loc_node_id = f"Location:{location}"
                self.graph.add_node(loc_node_id, label=location, type="LOCATION")
                self.graph.add_edge(rep_node_id, loc_node_id, relationship="LOCATED_IN")

    def detect_fraud_campaigns(self, db: Session) -> List[FraudCampaign]:
        """
        Clusters connected reports into syndicated fraud campaigns.
        Uses infrastructure indicators (PHONE, UPI, URL, DOMAIN) to bridge reports,
        avoiding false bridges from high-degree generic hubs like common brand names or cities.
        """
        self.sync_from_database(db)

        # Build infrastructure-only subgraph for clustering
        infra_nodes = [
            n for n, attr in self.graph.nodes(data=True)
            if attr.get("type") in ["REPORT", "PHONE", "UPI", "URL", "DOMAIN"]
        ]
        infra_subgraph = self.graph.subgraph(infra_nodes).to_undirected()

        campaigns = []
        components = list(nx.connected_components(infra_subgraph))

        campaign_idx = 1
        for comp in components:
            comp_nodes = list(comp)
            reports_in_comp = [n for n in comp_nodes if self.graph.nodes[n].get("type") == "REPORT"]
            indicators_in_comp = [n for n in comp_nodes if self.graph.nodes[n].get("type") in ["PHONE", "UPI", "URL", "DOMAIN"]]

            # A campaign is flagged if there are multiple reports or multiple linked threat indicators
            if len(reports_in_comp) >= 2 or (len(reports_in_comp) >= 1 and len(indicators_in_comp) >= 2):
                # Expand component to include adjacent Brand, Category and Location nodes for full context
                expanded_nodes: Set[str] = set(comp_nodes)
                for node in comp_nodes:
                    for neighbor in self.graph.neighbors(node):
                        expanded_nodes.add(neighbor)

                subgraph = self.graph.subgraph(list(expanded_nodes))
                
                # Determine primary scam category, brand, and locations
                categories = [self.graph.nodes[n].get("label") for n in expanded_nodes if self.graph.nodes[n].get("type") == "SCAM_TYPE"]
                brands = [self.graph.nodes[n].get("label") for n in expanded_nodes if self.graph.nodes[n].get("type") == "BRAND"]
                locations = [self.graph.nodes[n].get("label") for n in expanded_nodes if self.graph.nodes[n].get("type") == "LOCATION"]

                primary_cat = categories[0] if categories else "MULTIVECTOR_FRAUD"
                primary_brand = brands[0] if brands else None
                
                campaign_id = f"CAMP-{campaign_idx:03d}"
                campaign_name = f"{primary_brand or 'Syndicated'} {primary_cat} Campaign #{campaign_idx}"

                graph_data = self._serialize_subgraph(subgraph)

                campaigns.append(FraudCampaign(
                    campaign_id=campaign_id,
                    name=campaign_name,
                    scam_category=primary_cat,
                    impersonated_brand=primary_brand,
                    report_count=len(reports_in_comp),
                    threat_indicators_count=len(indicators_in_comp),
                    associated_locations=list(set(locations)),
                    nodes=graph_data.nodes,
                    edges=graph_data.edges
                ))
                campaign_idx += 1

        return sorted(campaigns, key=lambda c: (c.report_count, c.threat_indicators_count), reverse=True)

    def investigate_entity(self, db: Session, entity_query: str) -> EntityInvestigationResponse:
        """
        Searches for an entity (phone, UPI, domain, URL, or report ID) and extracts its 2-hop neighborhood.
        """
        self.sync_from_database(db)
        query_clean = entity_query.strip().lower()

        # Find matching node
        target_node = None
        target_type = None

        for n, attr in self.graph.nodes(data=True):
            node_label = str(attr.get("label", "")).lower()
            if query_clean in node_label or node_label in query_clean:
                target_node = n
                target_type = attr.get("type")
                break

        if not target_node:
            return EntityInvestigationResponse(
                queried_entity=entity_query,
                entity_type=None,
                found=False,
                connection_count=0,
                connected_campaign_ids=[],
                subgraph=GraphData(nodes=[], edges=[])
            )

        # 2-hop neighborhood ego-graph
        ego_nodes = set([target_node])
        # 1-hop
        for n1 in self.graph.neighbors(target_node):
            ego_nodes.add(n1)
            # 2-hop
            for n2 in self.graph.neighbors(n1):
                ego_nodes.add(n2)

        subgraph = self.graph.subgraph(list(ego_nodes))
        serialized = self._serialize_subgraph(subgraph)

        # Find any connected campaigns
        campaigns = self.detect_fraud_campaigns(db)
        connected_camps = []
        for camp in campaigns:
            camp_node_ids = {node.id for node in camp.nodes}
            if target_node in camp_node_ids:
                connected_camps.append(camp.campaign_id)

        return EntityInvestigationResponse(
            queried_entity=entity_query,
            entity_type=target_type,
            found=True,
            connection_count=len(ego_nodes) - 1,
            connected_campaign_ids=connected_camps,
            subgraph=serialized
        )

    def get_full_graph(self, db: Session) -> GraphData:
        """Serializes the entire graph for dashboard visualization."""
        self.sync_from_database(db)
        return self._serialize_subgraph(self.graph)

    def _serialize_subgraph(self, sub: nx.Graph) -> GraphData:
        nodes = []
        for n, attr in sub.nodes(data=True):
            nodes.append(GraphNode(
                id=n,
                label=attr.get("label", n),
                type=attr.get("type", "UNKNOWN"),
                properties={k: v for k, v in attr.items() if k not in ["label", "type"]}
            ))

        edges = []
        for u, v, k, attr in sub.edges(data=True, keys=True):
            edges.append(GraphEdge(
                source=u,
                target=v,
                relationship=attr.get("relationship", "CONNECTED_TO")
            ))

        return GraphData(nodes=nodes, edges=edges)

graph_engine = ThreatGraphEngine()
