"""PDF report generator for VolatileAI forensic reports."""

import io
from datetime import datetime
from typing import List

from fpdf import FPDF


class ForensicReportPDF(FPDF):
    """Custom PDF class with forensic report styling."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)

    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(56, 189, 248)
        self.set_y(6)
        self.cell(0, 8, "VolatileAI - Memory Forensics Report", align="L")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, datetime.now().strftime("%Y-%m-%d %H:%M"), align="R")
        self.ln(16)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"Confidential | Page {self.page_no()}/{{nb}}", align="C")

    def add_title_page(self, report_type: str, org_name: str, analyst: str, case_no: str, scenario_name: str):
        self.add_page()
        self.ln(40)
        self.set_font("Helvetica", "B", 28)
        self.set_text_color(56, 189, 248)
        self.cell(0, 15, "VolatileAI", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 14)
        self.set_text_color(226, 232, 240)
        self.cell(0, 10, report_type, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(10)

        self.set_draw_color(56, 189, 248)
        self.line(60, self.get_y(), 150, self.get_y())
        self.ln(15)

        self.set_font("Helvetica", "", 11)
        self.set_text_color(148, 163, 184)
        details = [
            ("Organization", org_name or "N/A"),
            ("Analyst", analyst or "N/A"),
            ("Case Number", case_no or "N/A"),
            ("Scenario", scenario_name or "N/A"),
            ("Generated", datetime.now().strftime("%B %d, %Y at %H:%M")),
        ]
        for label, value in details:
            self.set_font("Helvetica", "B", 10)
            self.cell(60, 8, f"{label}:", align="R")
            self.set_font("Helvetica", "", 10)
            self.cell(0, 8, f"  {value}", new_x="LMARGIN", new_y="NEXT")

    def add_section_header(self, title: str):
        self.ln(5)
        self.set_fill_color(30, 41, 59)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(56, 189, 248)
        self.cell(0, 10, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def _safe(self, text: str) -> str:
        return text.encode("latin-1", errors="replace").decode("latin-1")

    def add_finding(self, title: str, description: str, risk_score: float,
                    category: str, techniques: List[str]):
        risk_level = "CRITICAL" if risk_score >= 8 else "HIGH" if risk_score >= 6 else "MEDIUM" if risk_score >= 4 else "LOW"
        color_map = {"CRITICAL": (239, 68, 68), "HIGH": (249, 115, 22), "MEDIUM": (234, 179, 8), "LOW": (34, 197, 94)}
        color = color_map.get(risk_level, (148, 163, 184))

        self.set_draw_color(*color)
        y_start = self.get_y()
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*color)
        self.cell(0, 7, self._safe(f"[{risk_level}] {risk_score:.1f}/10 - {title}"), new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(148, 163, 184)
        self.multi_cell(0, 5, self._safe(description[:300]))
        if techniques:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(56, 189, 248)
            self.cell(0, 5, f"MITRE: {', '.join(techniques[:5])}", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(5)

    def add_text(self, text, size: int = 10):
        if not isinstance(text, str):
            text = str(text)
        self.set_font("Helvetica", "", size)
        self.set_text_color(226, 232, 240)
        clean = text.replace("**", "").replace("*", "").replace("#", "").replace("`", "")
        clean = clean.encode("latin-1", errors="replace").decode("latin-1")
        self.multi_cell(0, 5, clean)
        self.ln(2)


class ReportGenerator:
    """Generates forensic PDF reports."""

    def _normalize_report_type(self, report_type: str) -> str:
        """Map UI labels and legacy aliases to canonical internal report types."""
        raw = (report_type or "").strip()
        key = raw.lower()
        aliases = {
            "executive summary": "Executive Summary",
            "executive summary report": "Executive Summary",
            "technical analysis": "Technical Analysis",
            "technical analysis report": "Technical Analysis",
            "ioc report": "IOC Report",
            "mitre att&ck report": "MITRE ATT&CK Report",
        }
        return aliases.get(key, raw)

    def generate(self, report_type: str, findings: list, plugin_results: dict,
                 evidence_info, org_name: str, analyst_name: str, case_number: str,
                 scenario_name: str, ai_engine=None, scenario_id: str = "") -> bytes:

        report_type = self._normalize_report_type(report_type)

        pdf = ForensicReportPDF()
        pdf.alias_nb_pages()

        pdf.add_title_page(report_type, org_name, analyst_name, case_number, scenario_name)

        if report_type == "Executive Summary":
            self._add_executive_summary(pdf, findings, ai_engine, scenario_id)
        elif report_type == "Technical Analysis":
            self._add_technical_analysis(pdf, findings, plugin_results, ai_engine, scenario_id)
        elif report_type == "IOC Report":
            self._add_ioc_report(pdf, findings)
        elif report_type == "MITRE ATT&CK Report":
            self._add_mitre_report(pdf, findings)

        buf = io.BytesIO()
        pdf.output(buf)
        return buf.getvalue()

    def _add_executive_summary(self, pdf: ForensicReportPDF, findings, ai_engine, scenario_id):
        pdf.add_page()
        pdf.add_section_header("Executive Summary")

        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            risk_summary[f.risk_level] += 1

        pdf.add_text(
            f"Total Findings: {len(findings)}\n"
            f"Critical: {risk_summary['critical']} | High: {risk_summary['high']} | "
            f"Medium: {risk_summary['medium']} | Low: {risk_summary['low']}"
        )

        if ai_engine:
            summary = ai_engine.get_auto_analysis(scenario_id)
            if summary and isinstance(summary, str):
                pdf.add_section_header("AI-Generated Assessment")
                pdf.add_text(summary)

        pdf.add_section_header("Top Critical Findings")
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True)[:10]:
            pdf.add_finding(f.title, f.description, f.risk_score, f.category, f.mitre_techniques)

        if ai_engine:
            recs = ai_engine.get_recommendations(scenario_id)
            if recs and isinstance(recs, str):
                pdf.add_section_header("Recommendations")
                pdf.add_text(recs)

    def _add_technical_analysis(self, pdf: ForensicReportPDF, findings, plugin_results, ai_engine, scenario_id):
        pdf.add_page()
        pdf.add_section_header("Technical Analysis")

        if ai_engine:
            narrative = ai_engine.get_attack_narrative(scenario_id)
            if narrative and isinstance(narrative, str):
                pdf.add_section_header("Attack Narrative")
                pdf.add_text(narrative)

        categories = {}
        for f in findings:
            categories.setdefault(f.category, []).append(f)

        for cat, cat_findings in categories.items():
            pdf.add_section_header(f"{cat.capitalize()} Analysis ({len(cat_findings)} findings)")
            for f in sorted(cat_findings, key=lambda x: x.risk_score, reverse=True):
                pdf.add_finding(f.title, f.description, f.risk_score, f.category, f.mitre_techniques)

    def _add_ioc_report(self, pdf: ForensicReportPDF, findings):
        pdf.add_page()
        pdf.add_section_header("Indicators of Compromise")

        ips, processes, techniques = set(), set(), set()
        for f in findings:
            for t in f.mitre_techniques:
                techniques.add(t)
            if f.category == "network":
                ip = str(f.evidence.get("ForeignAddr") or f.evidence.get("foreign_addr") or f.evidence.get("ip", ""))
                if ip and ip not in ("0.0.0.0", "::", "*", "-", "127.0.0.1"):
                    ips.add(ip)
            elif f.category == "process":
                processes.add(f.title)

        pdf.add_section_header("Suspicious IP Addresses")
        for ip in sorted(ips):
            pdf.add_text(f"  - {ip}")

        pdf.add_section_header("Suspicious Processes")
        for p in sorted(processes):
            pdf.add_text(f"  - {p}")

        pdf.add_section_header("MITRE ATT&CK Techniques")
        for t in sorted(techniques):
            pdf.add_text(f"  - {t}")

    def _add_mitre_report(self, pdf: ForensicReportPDF, findings):
        pdf.add_page()
        pdf.add_section_header("MITRE ATT&CK Mapping Report")

        from core.mitre_mapper import MitreMapper
        mapper = MitreMapper()
        detected = mapper.get_detected_techniques(findings)

        for tech in detected:
            if pdf.get_y() > 240:
                pdf.add_page()
            try:
                pdf.set_x(10)
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(56, 189, 248)
                pdf.cell(190, 8, pdf._safe(tech["technique_id"] + " - " + tech["name"]), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(148, 163, 184)
                pdf.cell(190, 5, pdf._safe("Tactic: " + tech["tactic"]), new_x="LMARGIN", new_y="NEXT")
                desc = tech["description"][:150].replace("\n", " ")
                pdf.multi_cell(190, 5, pdf._safe("Description: " + desc))
                detect = tech["detection"][:150].replace("\n", " ")
                pdf.multi_cell(190, 5, pdf._safe("Detection: " + detect))
                severity_str = "{:.1f}".format(tech["max_severity"])
                pdf.cell(190, 5, pdf._safe("Findings: " + str(tech["finding_count"]) + " | Max Severity: " + severity_str), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)
            except Exception:
                pdf.ln(3)
