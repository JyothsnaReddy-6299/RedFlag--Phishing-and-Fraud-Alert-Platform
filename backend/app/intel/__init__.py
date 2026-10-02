"""RedFlag Intelligence layer.

Adds the NextGen AI Hacks 2026 contract capabilities on top of the existing
URL detection baseline:

  language  -> Tamil / English / Tanglish detection + normalization
  entities  -> phone / url / domain / email / UPI / handle / brand / amount / txn
  intent    -> urgency, authority, payment, credential, reward, threat
  scoring   -> interpretable 0-100 with decomposable risk_factors
  graph     -> deterministic campaign correlation
  storage   -> SQLite/Postgres persistence of analyses, reports, campaigns
"""

MODEL_VERSION = "redflag-intel-1.0.0"
