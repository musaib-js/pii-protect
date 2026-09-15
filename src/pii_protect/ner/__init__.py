"""
pii_protect.ner
================
Multi-layer NER detection engine
(regex / domain / GLiNER / spaCy / privacy-filter transformer).

Author: Musaib Altaf
"""

from pii_protect.ner.domain import (
    DomainEntity,
    DomainEntityConfigError,
    DomainEntityLayer,
    load_domain_entities,
    register_entity_type,
)
from pii_protect.ner.engine import (
    NEREngine,
    PrivacyFilterLayer,
    RegexNERLayer,
    SpacyNERLayer,
    SpanConflictResolver,
    TokenizerSafeSpanMerger,
)

__all__ = [
    "NEREngine",
    "RegexNERLayer",
    "SpacyNERLayer",
    "PrivacyFilterLayer",
    "TokenizerSafeSpanMerger",
    "SpanConflictResolver",
    "DomainEntity",
    "DomainEntityLayer",
    "DomainEntityConfigError",
    "load_domain_entities",
    "register_entity_type",
]
