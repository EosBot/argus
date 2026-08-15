"""Analytical intelligence frameworks for ARGUS.

Implements structured analysis methodologies:
- MITRE ATT&CK technique mapping
- Diamond Model of Intrusion Analysis
- Cyber Kill Chain (Lockheed Martin)
- Analysis of Competing Hypotheses (ACH)
"""

from __future__ import annotations

import json
from typing import Any

# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Database (fallback when pyattck is unavailable)
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries send malicious emails to gain access.",
        "keywords": ["phish", "email", "malicious attachment", "spearphish"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries use command shells to execute commands.",
        "keywords": ["powershell", "bash", "cmd", "script", "shell"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "description": "Adversaries use task scheduling to execute programs.",
        "keywords": ["schtasks", "cron", "scheduled task", "at job"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Persistence",
        "description": "Adversaries steal or abuse existing accounts.",
        "keywords": ["credential", "brute force", "password spray", "stolen account"],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries dump credentials from the operating system.",
        "keywords": ["mimikatz", "lsass", "credential dump", "hash dump"],
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries enumerate system and domain accounts.",
        "keywords": ["net user", "whoami", "account enumeration", "ldap query"],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries probe network services.",
        "keywords": ["nmap", "port scan", "service discovery", "network scan"],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries use remote services to move laterally.",
        "keywords": ["rdp", "ssh", "smb", "winrm", "remote desktop"],
    },
    "T1080": {
        "name": "Taint Shared Content",
        "tactic": "Lateral Movement",
        "description": "Adversaries add malicious content to shared locations.",
        "keywords": ["shared folder", "network share", "drop file"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries exfiltrate data via non-standard protocols.",
        "keywords": ["exfil", "dns tunnel", "icmp tunnel", "data theft"],
    },
    "T1070": {
        "name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "description": "Adversaries delete or modify artifacts.",
        "keywords": ["clear logs", "timestomp", "delete file", "wipe"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries transfer tools into the environment.",
        "keywords": ["download", "tool transfer", "payload drop", "stager"],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries use web protocols for C2.",
        "keywords": ["http c2", "https beacon", "dns c2", "web service"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries encrypt data to disrupt availability.",
        "keywords": ["ransomware", "encrypt", "lockbit", "blackcat"],
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries perform DoS against endpoints.",
        "keywords": ["ddos", "denial of service", "flood", "resource exhaustion"],
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries bypass privilege controls.",
        "keywords": ["uac bypass", "sudo", "token impersonation", "privilege escalation"],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries inject code into processes.",
        "keywords": ["dll injection", "process hollowing", "reflective loading"],
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries disable security tools.",
        "keywords": ["disable av", "disable firewall", "tamper protection"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries exploit internet-facing applications.",
        "keywords": ["exploit", "rce", "sql injection", "xss", "0day"],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Adversaries exploit external remote services.",
        "keywords": ["vpn", "rdp gateway", "remote access", "external facing"],
    },
}

# ---------------------------------------------------------------------------
# Cyber Kill Chain phases
# ---------------------------------------------------------------------------

KILL_CHAIN_PHASES: list[dict[str, Any]] = [
    {
        "phase": "Reconnaissance",
        "description": "Research and identification of targets",
        "indicators": ["scanning", "osint", "social media", "whois", "dns enum"],
    },
    {
        "phase": "Weaponization",
        "description": "Coupling exploit with payload",
        "indicators": ["malware", "exploit kit", "payload", "backdoor"],
    },
    {
        "phase": "Delivery",
        "description": "Transmission of weapon to target",
        "indicators": ["phishing email", "usb drive", "watering hole", "supply chain"],
    },
    {
        "phase": "Exploitation",
        "description": "Triggering the exploit on target",
        "indicators": ["vulnerability", "zero-day", "code execution", "buffer overflow"],
    },
    {
        "phase": "Installation",
        "description": "Establishing persistent access",
        "indicators": ["implant", "rootkit", "persistence", "registry key"],
    },
    {
        "phase": "Command and Control",
        "description": "Remote manipulation of compromised systems",
        "indicators": ["c2", "beacon", "command channel", "reverse shell"],
    },
    {
        "phase": "Actions on Objectives",
        "description": "Achieving the adversary's goal",
        "indicators": ["data theft", "ransomware", "destruction", "extortion"],
    },
]


class FrameworkAnalyzer:
    """Analytical intelligence framework analyzer.

    Provides structured analysis using MITRE ATT&CK, Diamond Model,
    Cyber Kill Chain, and Analysis of Competing Hypotheses.
    """

    def __init__(self, use_pyattck: bool = False) -> None:
        """Initialize the analyzer.

        Args:
            use_pyattck: Attempt to use pyattck library if available.
        """
        self._pyattck_available = False
        if use_pyattck:
            try:
                import pyattck  # noqa: F401

                self._pyattck_available = True
            except ImportError:
                self._pyattck_available = False

    # ------------------------------------------------------------------
    # MITRE ATT&CK
    # ------------------------------------------------------------------

    def map_attack_techniques(self, evidence: list[dict]) -> list[dict]:
        """Map evidence items to MITRE ATT&CK techniques.

        Args:
            evidence: List of evidence dicts with at least a 'description'
                      or 'type' key.

        Returns:
            List of matched techniques with confidence scores.
        """
        results: list[dict] = []

        for item in evidence:
            text = self._extract_text(item)
            matches = self._match_techniques(text)
            if matches:
                results.append(
                    {
                        "evidence": item,
                        "techniques": matches,
                    }
                )

        return results

    def _match_techniques(self, text: str) -> list[dict]:
        """Match text against known MITRE techniques using keyword scoring."""
        text_lower = text.lower()
        matches: list[dict] = []

        for tech_id, tech in MITRE_TECHNIQUES.items():
            score = 0
            matched_keywords: list[str] = []

            for keyword in tech["keywords"]:
                if keyword.lower() in text_lower:
                    score += 1
                    matched_keywords.append(keyword)

            if score > 0:
                confidence = min(score / len(tech["keywords"]) * 3, 1.0)
                matches.append(
                    {
                        "id": tech_id,
                        "name": tech["name"],
                        "tactic": tech["tactic"],
                        "confidence": round(confidence, 2),
                        "matched_keywords": matched_keywords,
                    }
                )

        matches.sort(key=lambda m: m["confidence"], reverse=True)
        return matches

    # ------------------------------------------------------------------
    # Diamond Model
    # ------------------------------------------------------------------

    def diamond_model(self, evidence: dict) -> dict:
        """Analyze evidence using the Diamond Model of Intrusion Analysis.

        The Diamond Model examines four core features:
        - Adversary: Who is behind the attack
        - Capability: What tools/techniques they used
        - Infrastructure: What infrastructure they leveraged
        - Victim: Who was targeted

        Args:
            evidence: Evidence dict with keys like 'attacker', 'tools',
                      'infrastructure', 'target', 'description'.

        Returns:
            Diamond model analysis with four vertices.
        """
        description = evidence.get("description", "")

        adversary = {
            "identified": evidence.get("attacker", "Unknown"),
            "type": self._classify_adversary(description),
            "motivation": self._infer_motivation(description),
        }

        capability = {
            "tools": evidence.get("tools", []),
            "techniques": self._extract_techniques_from_text(description),
            "sophistication": self._assess_sophistication(description),
        }

        infrastructure = {
            "ips": evidence.get("ips", []),
            "domains": evidence.get("domains", []),
            "infrastructure_type": self._classify_infrastructure(description),
        }

        victim = {
            "identified": evidence.get("target", "Unknown"),
            "sector": evidence.get("sector", "Unknown"),
            "attack_surface": self._identify_attack_surface(description),
        }

        return {
            "adversary": adversary,
            "capability": capability,
            "infrastructure": infrastructure,
            "victim": victim,
            "meta": {
                "analysis_type": "Diamond Model",
                "version": "1.0",
            },
        }

    # ------------------------------------------------------------------
    # Cyber Kill Chain
    # ------------------------------------------------------------------

    def kill_chain(self, evidence: dict) -> dict:
        """Map evidence to the Cyber Kill Chain phases.

        Args:
            evidence: Evidence dict with 'description', 'indicators', or
                      'timeline' keys.

        Returns:
            Kill chain analysis with phase mappings.
        """
        text = self._extract_text(evidence)
        indicators = evidence.get("indicators", [])
        all_text = text + " " + " ".join(str(i) for i in indicators)

        phases: list[dict] = []
        highest_phase = 0

        for idx, phase in enumerate(KILL_CHAIN_PHASES):
            matched: list[str] = []
            for indicator in phase["indicators"]:
                if indicator.lower() in all_text.lower():
                    matched.append(indicator)

            is_active = len(matched) > 0
            if is_active:
                highest_phase = idx + 1

            phases.append(
                {
                    "phase": phase["phase"],
                    "description": phase["description"],
                    "active": is_active,
                    "matched_indicators": matched,
                    "order": idx + 1,
                }
            )

        return {
            "phases": phases,
            "highest_active_phase": highest_phase,
            "kill_chain_complete": highest_phase == len(KILL_CHAIN_PHASES),
            "assessment": self._kill_chain_assessment(highest_phase),
        }

    # ------------------------------------------------------------------
    # Analysis of Competing Hypotheses (ACH)
    # ------------------------------------------------------------------

    def competing_hypotheses(
        self, hypotheses: list[str], evidence: list[dict]
    ) -> list[dict]:
        """Apply Analysis of Competing Hypotheses methodology.

        ACH helps avoid cognitive bias by systematically evaluating
        multiple hypotheses against evidence, focusing on
        disconfirmation rather than confirmation.

        Args:
            hypotheses: List of hypothesis strings to evaluate.
            evidence: List of evidence dicts with 'description' and
                      optional 'reliability' keys.

        Returns:
            Ranked hypotheses with consistency scores.
        """
        results: list[dict] = []

        for hypothesis in hypotheses:
            consistency_score = 0.0
            supporting: list[str] = []
            contradicting: list[str] = []

            hyp_lower = hypothesis.lower()

            for item in evidence:
                item_text = self._extract_text(item).lower()
                reliability = item.get("reliability", "medium")

                # Check for keyword overlap
                hyp_words = set(hyp_lower.split())
                item_words = set(item_text.split())
                overlap = hyp_words & item_words

                weight = {"high": 1.0, "medium": 0.7, "low": 0.4}.get(
                    reliability, 0.7
                )

                if len(overlap) > len(hyp_words) * 0.3:
                    consistency_score += weight
                    supporting.append(item.get("description", item_text[:80]))
                elif self._is_contradictory(hyp_lower, item_text):
                    consistency_score -= weight
                    contradicting.append(item.get("description", item_text[:80]))

            # Normalize score
            if evidence:
                consistency_score = consistency_score / len(evidence)

            results.append(
                {
                    "hypothesis": hypothesis,
                    "consistency_score": round(consistency_score, 3),
                    "supporting_evidence": supporting,
                    "contradicting_evidence": contradicting,
                    "verdict": self._ach_verdict(consistency_score),
                }
            )

        # Sort by consistency score (highest first)
        results.sort(key=lambda r: r["consistency_score"], reverse=True)
        return results

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate_report(self, findings: dict) -> str:
        """Generate a structured Markdown report from analysis findings.

        Args:
            findings: Dict containing analysis results from any framework.
                      Expected keys: 'title', 'date', 'analyst',
                      'mitre_mapping', 'diamond', 'kill_chain', 'ach'.

        Returns:
            Markdown-formatted report string.
        """
        sections: list[str] = []

        # Header
        title = findings.get("title", "Intelligence Analysis Report")
        date = findings.get("date", "N/A")
        analyst = findings.get("analyst", "ARGUS Intelligence Module")

        sections.append(f"# {title}")
        sections.append(f"\n**Date:** {date}")
        sections.append(f"**Analyst:** {analyst}")
        sections.append(f"**Classification:** {findings.get('classification', 'TLP:WHITE')}")

        # Executive Summary
        if "summary" in findings:
            sections.append("\n## Executive Summary\n")
            sections.append(findings["summary"])

        # MITRE ATT&CK Mapping
        if "mitre_mapping" in findings:
            sections.append("\n## MITRE ATT&CK Mapping\n")
            sections.append(self._format_mitre_section(findings["mitre_mapping"]))

        # Diamond Model
        if "diamond" in findings:
            sections.append("\n## Diamond Model Analysis\n")
            sections.append(self._format_diamond_section(findings["diamond"]))

        # Kill Chain
        if "kill_chain" in findings:
            sections.append("\n## Cyber Kill Chain\n")
            sections.append(self._format_kill_chain_section(findings["kill_chain"]))

        # ACH
        if "ach" in findings:
            sections.append("\n## Analysis of Competing Hypotheses\n")
            sections.append(self._format_ach_section(findings["ach"]))

        # Recommendations
        if "recommendations" in findings:
            sections.append("\n## Recommendations\n")
            for rec in findings["recommendations"]:
                sections.append(f"- {rec}")

        # Footer
        sections.append("\n---")
        sections.append("*Generated by ARGUS Intelligence Framework Analyzer*")

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Private Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_text(item: dict) -> str:
        """Extract searchable text from an evidence item."""
        parts = []
        for key in ("description", "type", "name", "value", "summary"):
            if key in item and item[key]:
                parts.append(str(item[key]))
        return " ".join(parts)

    @staticmethod
    def _classify_adversary(description: str) -> str:
        """Classify adversary type from description."""
        desc_lower = description.lower()
        if any(w in desc_lower for w in ["apt", "nation", "state", "government"]):
            return "Nation-State / APT"
        if any(w in desc_lower for w in ["ransomware", "financial", "extortion"]):
            return "Cybercriminal"
        if any(w in desc_lower for w in ["hacktivist", "activist", "ideology"]):
            return "Hacktivist"
        if any(w in desc_lower for w in ["insider", "employee", "disgruntled"]):
            return "Insider Threat"
        return "Unknown"

    @staticmethod
    def _infer_motivation(description: str) -> str:
        """Infer adversary motivation from description."""
        desc_lower = description.lower()
        if any(w in desc_lower for w in ["espionage", "spy", "intelligence"]):
            return "Espionage"
        if any(w in desc_lower for w in ["financial", "ransom", "money", "profit"]):
            return "Financial Gain"
        if any(w in desc_lower for w in ["disruption", "destruction", "sabotage"]):
            return "Disruption"
        if any(w in desc_lower for w in ["ideology", "political", "message"]):
            return "Ideological"
        return "Unknown"

    @staticmethod
    def _extract_techniques_from_text(description: str) -> list[str]:
        """Extract mentioned techniques from text."""
        techniques: list[str] = []
        desc_lower = description.lower()
        technique_keywords = {
            "phishing": "Phishing",
            "spearphish": "Spearphishing",
            "ransomware": "Ransomware",
            "brute force": "Brute Force",
            "sql injection": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "ddos": "DDoS",
            "zero-day": "Zero-Day Exploit",
            "social engineering": "Social Engineering",
            "credential dumping": "Credential Dumping",
            "lateral movement": "Lateral Movement",
            "privilege escalation": "Privilege Escalation",
            "data exfiltration": "Data Exfiltration",
        }
        for keyword, technique in technique_keywords.items():
            if keyword in desc_lower:
                techniques.append(technique)
        return techniques

    @staticmethod
    def _assess_sophistication(description: str) -> str:
        """Assess adversary sophistication level."""
        desc_lower = description.lower()
        high_indicators = ["apt", "zero-day", "custom malware", "supply chain", "nation"]
        medium_indicators = ["ransomware", "phishing campaign", "toolkit", "c2"]

        if any(w in desc_lower for w in high_indicators):
            return "High"
        if any(w in desc_lower for w in medium_indicators):
            return "Medium"
        return "Low"

    @staticmethod
    def _classify_infrastructure(description: str) -> str:
        """Classify infrastructure type."""
        desc_lower = description.lower()
        if any(w in desc_lower for w in ["botnet", "compromised", "proxy"]):
            return "Compromised Infrastructure"
        if any(w in desc_lower for w in ["cloud", "aws", "azure", "vps"]):
            return "Cloud Infrastructure"
        if any(w in desc_lower for w in ["dedicated", "bulletproof", "owned"]):
            return "Dedicated Infrastructure"
        return "Unknown"

    @staticmethod
    def _identify_attack_surface(description: str) -> list[str]:
        """Identify attack surface from description."""
        surfaces: list[str] = []
        desc_lower = description.lower()
        surface_map = {
            "email": "Email",
            "web": "Web Application",
            "vpn": "VPN Gateway",
            "rdp": "Remote Desktop",
            "phishing": "Human (Phishing)",
            "usb": "Physical (USB)",
            "supply chain": "Supply Chain",
        }
        for keyword, surface in surface_map.items():
            if keyword in desc_lower:
                surfaces.append(surface)
        return surfaces if surfaces else ["Unknown"]

    @staticmethod
    def _kill_chain_assessment(highest_phase: int) -> str:
        """Generate assessment based on kill chain progress."""
        if highest_phase == 0:
            return "No intrusion activity detected"
        if highest_phase <= 2:
            return "Early-stage activity detected (pre-attack)"
        if highest_phase <= 4:
            return "Active intrusion in progress"
        if highest_phase <= 6:
            return "Advanced intrusion with C2 established"
        return "Full kill chain completed - objectives achieved"

    @staticmethod
    def _is_contradictory(hypothesis: str, evidence: str) -> bool:
        """Simple heuristic to detect potential contradiction."""
        contradiction_pairs = [
            ("insider", "external"),
            ("nation", "opportunist"),
            ("targeted", "opportunistic"),
            ("sophisticated", "script kiddie"),
        ]
        for term_a, term_b in contradiction_pairs:
            if (term_a in hypothesis and term_b in evidence) or (
                term_b in hypothesis and term_a in evidence
            ):
                return True
        return False

    @staticmethod
    def _ach_verdict(score: float) -> str:
        """Generate ACH verdict from consistency score."""
        if score > 0.5:
            return "Consistent with evidence"
        if score > 0.0:
            return "Partially consistent"
        if score == 0.0:
            return "Inconclusive"
        return "Likely contradicted"

    @staticmethod
    def _format_mitre_section(mapping: list[dict]) -> str:
        """Format MITRE ATT&CK mapping for report."""
        lines: list[str] = []
        for entry in mapping:
            for tech in entry.get("techniques", []):
                lines.append(
                    f"- **{tech['id']}** ({tech['name']}) - "
                    f"Tactic: {tech['tactic']} - "
                    f"Confidence: {tech['confidence']:.0%}"
                )
        return "\n".join(lines) if lines else "No techniques mapped."

    @staticmethod
    def _format_diamond_section(diamond: dict) -> str:
        """Format Diamond Model analysis for report."""
        lines: list[str] = []
        lines.append(f"### Adversary\n")
        lines.append(f"- **Identified:** {diamond['adversary']['identified']}")
        lines.append(f"- **Type:** {diamond['adversary']['type']}")
        lines.append(f"- **Motivation:** {diamond['adversary']['motivation']}")

        lines.append(f"\n### Capability\n")
        tools = diamond["capability"]["tools"]
        lines.append(f"- **Tools:** {', '.join(tools) if tools else 'Unknown'}")
        lines.append(
            f"- **Sophistication:** {diamond['capability']['sophistication']}"
        )

        lines.append(f"\n### Infrastructure\n")
        ips = diamond["infrastructure"]["ips"]
        domains = diamond["infrastructure"]["domains"]
        lines.append(f"- **IPs:** {', '.join(ips) if ips else 'Unknown'}")
        lines.append(
            f"- **Domains:** {', '.join(domains) if domains else 'Unknown'}"
        )

        lines.append(f"\n### Victim\n")
        lines.append(f"- **Target:** {diamond['victim']['identified']}")
        lines.append(f"- **Sector:** {diamond['victim']['sector']}")

        return "\n".join(lines)

    @staticmethod
    def _format_kill_chain_section(kill_chain_data: dict) -> str:
        """Format Kill Chain analysis for report."""
        lines: list[str] = []
        for phase in kill_chain_data["phases"]:
            status = "✅" if phase["active"] else "⬜"
            lines.append(f"{status} **{phase['phase']}** - {phase['description']}")
            if phase["matched_indicators"]:
                lines.append(
                    f"   - Indicators: {', '.join(phase['matched_indicators'])}"
                )

        lines.append(
            f"\n**Assessment:** {kill_chain_data['assessment']}"
        )
        return "\n".join(lines)

    @staticmethod
    def _format_ach_section(ach_results: list[dict]) -> str:
        """Format ACH results for report."""
        lines: list[str] = []
        for idx, result in enumerate(ach_results, 1):
            lines.append(
                f"### H{idx}: {result['hypothesis']}"
            )
            lines.append(
                f"- **Score:** {result['consistency_score']:.3f}"
            )
            lines.append(f"- **Verdict:** {result['verdict']}")

            if result["supporting_evidence"]:
                lines.append(f"- **Supporting:** {len(result['supporting_evidence'])} items")
            if result["contradicting_evidence"]:
                lines.append(
                    f"- **Contradicting:** {len(result['contradicting_evidence'])} items"
                )
            lines.append("")

        return "\n".join(lines)
