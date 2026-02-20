"""
ComplianceTemplate — pre-built policy configs for common compliance frameworks.

Each template is a :class:`~antaris_guard.policy.CompositePolicy` that composes
existing policy primitives with compliance-appropriate settings.

Zero dependencies, pure Python, deterministic.

Supported frameworks
--------------------
* SOC 2  — System and Organization Controls 2
* HIPAA  — Health Insurance Portability and Accountability Act
* GDPR   — General Data Protection Regulation
* PCI DSS — Payment Card Industry Data Security Standard

Usage::

    from antaris_guard import ComplianceTemplate

    policy = ComplianceTemplate.HIPAA()
    guard  = PromptGuard(policy=policy)

    templates = ComplianceTemplate.list()  # ["GDPR", "HIPAA", "PCI_DSS", "SOC2"]
"""

from typing import List

from .policy import (
    CompositePolicy,
    ContentFilterPolicy,
    CostCapPolicy,
    RateLimitPolicy,
)


class ComplianceTemplate:
    """
    Factory for compliance-framework policy bundles.

    All class-methods return a :class:`~antaris_guard.policy.CompositePolicy`
    (AND operator) that combines rate limiting, PII / content filtering, and
    optional cost capping with settings tuned for the named framework.
    """

    # ------------------------------------------------------------------ #
    # Templates
    # ------------------------------------------------------------------ #

    @classmethod
    def SOC2(cls) -> CompositePolicy:
        """
        SOC 2 (System and Organization Controls 2) policy bundle.

        Controls applied
        ~~~~~~~~~~~~~~~~
        * Rate limiting  — 120 requests / minute per source
        * PII filtering  — blocks emails, SSNs, credit cards, phone numbers
        * Injection filter — blocks prompt-injection patterns
        * Cost cap       — $5.00 / hour guard

        Returns
        -------
        CompositePolicy (AND)
        """
        return CompositePolicy(
            policies=[
                RateLimitPolicy(
                    requests=120,
                    per="minute",
                    name="soc2_rate_limit",
                    version="soc2_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="pii",
                    name="soc2_pii_filter",
                    version="soc2_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="injection",
                    name="soc2_injection_filter",
                    version="soc2_1.0",
                ),
                CostCapPolicy(
                    max_cost=5.0,
                    per="hour",
                    cost_per_request=0.001,
                    name="soc2_cost_cap",
                    version="soc2_1.0",
                ),
            ],
            operator="and",
            name="SOC2",
            version="soc2_1.0",
        )

    @classmethod
    def HIPAA(cls) -> CompositePolicy:
        """
        HIPAA (Health Insurance Portability and Accountability Act) policy bundle.

        HIPAA mandates strict protection of Protected Health Information (PHI).
        This template applies aggressive PII filtering, tighter rate limits, and
        full content scanning (injection + toxicity).

        Controls applied
        ~~~~~~~~~~~~~~~~
        * Rate limiting  — 60 requests / minute (conservative for PHI systems)
        * Full PII filter — blocks all PII types (PHI protection)
        * Injection filter — blocks prompt-injection and toxicity
        * Cost cap       — $2.00 / hour (tighter spend guard)

        Returns
        -------
        CompositePolicy (AND)
        """
        return CompositePolicy(
            policies=[
                RateLimitPolicy(
                    requests=60,
                    per="minute",
                    name="hipaa_rate_limit",
                    version="hipaa_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="pii",
                    name="hipaa_pii_filter",
                    version="hipaa_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="all",
                    name="hipaa_full_filter",
                    version="hipaa_1.0",
                ),
                CostCapPolicy(
                    max_cost=2.0,
                    per="hour",
                    cost_per_request=0.001,
                    name="hipaa_cost_cap",
                    version="hipaa_1.0",
                ),
            ],
            operator="and",
            name="HIPAA",
            version="hipaa_1.0",
        )

    @classmethod
    def GDPR(cls) -> CompositePolicy:
        """
        GDPR (General Data Protection Regulation) policy bundle.

        GDPR focuses on personal data protection for EU residents.  This template
        applies comprehensive PII filtering (data minimisation principle) with
        moderate rate limiting.

        Controls applied
        ~~~~~~~~~~~~~~~~
        * Rate limiting  — 100 requests / minute
        * PII filter     — blocks emails, phone numbers, names, identifiers
        * Injection filter — blocks prompt-injection patterns
        * Cost cap       — $3.00 / hour

        Returns
        -------
        CompositePolicy (AND)
        """
        return CompositePolicy(
            policies=[
                RateLimitPolicy(
                    requests=100,
                    per="minute",
                    name="gdpr_rate_limit",
                    version="gdpr_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="pii",
                    name="gdpr_pii_filter",
                    version="gdpr_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="injection",
                    name="gdpr_injection_filter",
                    version="gdpr_1.0",
                ),
                CostCapPolicy(
                    max_cost=3.0,
                    per="hour",
                    cost_per_request=0.001,
                    name="gdpr_cost_cap",
                    version="gdpr_1.0",
                ),
            ],
            operator="and",
            name="GDPR",
            version="gdpr_1.0",
        )

    @classmethod
    def PCI_DSS(cls) -> CompositePolicy:
        """
        PCI DSS (Payment Card Industry Data Security Standard) policy bundle.

        PCI DSS requires protection of cardholder data.  This template applies
        strict filtering to prevent credit-card numbers from flowing through the
        AI pipeline and enforces tight rate limits to reduce fraud attack surface.

        Controls applied
        ~~~~~~~~~~~~~~~~
        * Rate limiting  — 30 requests / minute (strict, financial context)
        * PII filter     — blocks credit cards, CVVs, account numbers
        * Full content filter — injection + toxicity scanning
        * Cost cap       — $1.00 / hour (conservative)

        Returns
        -------
        CompositePolicy (AND)
        """
        return CompositePolicy(
            policies=[
                RateLimitPolicy(
                    requests=30,
                    per="minute",
                    name="pci_dss_rate_limit",
                    version="pci_dss_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="pii",
                    name="pci_dss_pii_filter",
                    version="pci_dss_1.0",
                ),
                ContentFilterPolicy(
                    filter_type="all",
                    name="pci_dss_full_filter",
                    version="pci_dss_1.0",
                ),
                CostCapPolicy(
                    max_cost=1.0,
                    per="hour",
                    cost_per_request=0.001,
                    name="pci_dss_cost_cap",
                    version="pci_dss_1.0",
                ),
            ],
            operator="and",
            name="PCI_DSS",
            version="pci_dss_1.0",
        )

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #

    @classmethod
    def list(cls) -> List[str]:
        """Return a sorted list of all available compliance template names."""
        return ["GDPR", "HIPAA", "PCI_DSS", "SOC2"]

    @classmethod
    def get(cls, name: str) -> CompositePolicy:
        """
        Get a compliance template by name (case-insensitive).

        Parameters
        ----------
        name:
            One of the values returned by :meth:`list`.

        Raises
        ------
        ValueError
            When *name* does not match a known template.
        """
        mapping = {
            "SOC2": cls.SOC2,
            "HIPAA": cls.HIPAA,
            "GDPR": cls.GDPR,
            "PCI_DSS": cls.PCI_DSS,
        }
        upper = name.upper().replace("-", "_")
        factory = mapping.get(upper)
        if factory is None:
            raise ValueError(
                f"Unknown compliance template {name!r}. "
                f"Available: {cls.list()}"
            )
        return factory()
