"""
scripts/build_report.py
=======================
Builds the Word report  Roll#01_Roll#02_Roll#03_IS_Project.docx  from the
markdown files in docs/ + the evidence/ folder.

    python scripts/build_report.py --members "Name 1 (Roll#01)" "Name 2 (Roll#02)" "Name 3 (Roll#03)" \
                                   --out "21F-1234_21F-5678_21F-9012_IS_Project.docx"

Requires pandoc (https://pandoc.org/installing.html) on PATH.
After editing any docs/*.md file, simply run this again.
"""
import argparse
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SHOTS = ROOT / "evidence" / "screenshots"
# A real Word page break (pandoc ignores LaTeX \\newpage when writing .docx)
PAGEBREAK = '\n```{=openxml}\n<w:p><w:r><w:br w:type="page"/></w:r></w:p>\n```\n'

SCREENSHOT_CAPTIONS = {
    "01_login_page": "Login page",
    "02_registration_recovery_code": "Registration: one-time recovery code",
    "03_alice_dashboard": "Owner dashboard (file names decrypted for the owner only)",
    "04_document_detail_owner_acl": "Document details with access-control list (owner view)",
    "05_integrity_verified_ok": "Integrity verification: all checks pass",
    "06_upload_page": "Upload page",
    "07_bob_dashboard_shared_with_me": "bob's dashboard: documents shared with him",
    "08_bob_viewer_no_owner_controls": "Viewer sees no share/delete/update controls (S5)",
    "09_S1_S2_mallory_idor_denied_404": "S1/S2: mallory requests alice's document ID → 404",
    "10_S5_bob_admin_page_forbidden_403": "S5: normal user requests an admin page → 403",
    "11_S5_admin_cannot_read_documents_404": "S5: administrator cannot read user documents → 404",
    "12_S4_tampered_download_blocked_409": "S4: tampered document, download blocked → 409",
    "13_S4_verify_shows_integrity_failure": "S4: verification report shows the integrity failure",
    "14_S4_admin_integrity_scan_modified": "S4: admin storage scan flags MODIFIED blob",
    "15_S6_alice_revoked_bob_rekeyed": "S6: alice revokes bob; key generation increases (re-keyed)",
    "16_S6_bob_after_revocation_404": "S6: bob after revocation → 404",
    "17_admin_user_management": "Admin user management",
    "18_admin_audit_log_suspicious_activity": "Audit trail with suspicious-activity panel",
    "19_S7_audit_verify_intact": "S7: audit-log verification, intact",
    "20_S7_audit_tampering_detected": "S7: audit record modified via raw DB access → tampering detected",
}


def make_reference_docx(path: Path):
    """Pandoc's default template, restyled (Calibri body, blue headings, bordered tables)."""
    data = subprocess.run(["pandoc", "--print-default-data-file", "reference.docx"],
                          capture_output=True, check=True).stdout
    path.write_bytes(data)
    tmp = path.with_suffix(".dir")
    with zipfile.ZipFile(path) as z:
        z.extractall(tmp)
    styles = (tmp / "word" / "styles.xml").read_text(encoding="utf-8")
    # Body font
    styles = re.sub(r'<w:rFonts [^>]*/>', '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/>',
                    styles, count=1)
    # Heading colour -> dark blue
    styles = styles.replace('w:val="0F4761"', 'w:val="1F3D8F"').replace('w:val="4F81BD"', 'w:val="1F3D8F"') \
                   .replace('w:val="365F91"', 'w:val="1F3D8F"')
    (tmp / "word" / "styles.xml").write_text(styles, encoding="utf-8")
    path.unlink()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(tmp.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(tmp).as_posix())
    shutil.rmtree(tmp)


# Element order required by the WordprocessingML schema for <w:settings>
_SETTINGS_ORDER = """writeProtection view zoom removePersonalInformation removeDateAndTime doNotDisplayPageBoundaries
displayBackgroundShape printPostScriptOverText printFractionalCharacterWidth printFormsData embedTrueTypeFonts
embedSystemFonts saveSubsetFonts saveFormsData mirrorMargins alignBordersAndEdges bordersDoNotSurroundHeader
bordersDoNotSurroundFooter gutterAtTop hideSpellingErrors hideGrammaticalErrors activeWritingStyle proofState
formsDesign attachedTemplate linkStyles stylePaneFormatFilter stylePaneSortMethod documentType mailMerge
revisionView trackRevisions doNotTrackMoves doNotTrackFormatting documentProtection autoFormatOverride
styleLockTheme styleLockQFSet defaultTabStop autoHyphenation consecutiveHyphenLimit hyphenationZone
doNotHyphenateCaps showEnvelope summaryLength clickAndTypeStyle defaultTableStyle evenAndOddHeaders
bookFoldRevPrinting bookFoldPrinting bookFoldPrintingSheets drawingGridHorizontalSpacing drawingGridVerticalSpacing
displayHorizontalDrawingGridEvery displayVerticalDrawingGridEvery doNotUseMarginsForDrawingGridOrigin
drawingGridHorizontalOrigin drawingGridVerticalOrigin doNotShadeFormData noPunctuationKerning
characterSpacingControl printTwoOnOne strictFirstAndLastChars noLineBreaksAfter noLineBreaksBefore
savePreviewPicture doNotValidateAgainstSchema saveInvalidXml ignoreMixedContent alwaysShowPlaceholderText
doNotDemarcateInvalidXml saveXmlDataOnly useXSLTWhenSaving saveThroughXslt showXMLTags alwaysMergeEmptyNamespace
updateFields hdrShapeDefaults footnotePr endnotePr compat docVars rsids mathPr attachedSchema themeFontLang
clrSchemeMapping doNotIncludeSubdocsInStats doNotAutoCompressPictures forceUpgrade captions readModeInkLockDown
smartTagType schemaLibrary shapeDefaults doNotEmbedSmartTags decimalSymbol listSeparator""".split()


def _sort_settings(xml: str) -> str:
    """Re-order the children of <w:settings> into schema order (pandoc writes some out of order)."""
    from lxml import etree
    root = etree.fromstring(xml.encode("utf-8"))
    rank = {name: i for i, name in enumerate(_SETTINGS_ORDER)}
    children = list(root)
    for c in children:
        root.remove(c)
    children.sort(key=lambda c: rank.get(etree.QName(c).localname, len(rank)))
    for c in children:
        root.append(c)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True).decode("utf-8")


def add_table_borders(docx: Path):
    """Pandoc tables have no borders; add thin grey borders, a shaded header row and small font."""
    tmp = docx.with_suffix(".dir")
    with zipfile.ZipFile(docx) as z:
        z.extractall(tmp)
    doc = tmp / "word" / "document.xml"
    xml = doc.read_text(encoding="utf-8")
    borders = ('<w:tblBorders>' + "".join(
        f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="A6A6A6"/>'
        for s in ("top", "left", "bottom", "right", "insideH", "insideV")) + '</w:tblBorders>')
    # Add borders, then put <w:tblPr> children in schema order (pandoc writes <w:jc> after <w:tblLook>)
    tbl_order = ("tblStyle tblpPr tblOverlap bidiVisual tblStyleRowBandSize tblStyleColBandSize tblW jc "
                 "tblCellSpacing tblInd tblBorders shd tblLayout tblCellMar tblLook tblCaption tblDescription").split()
    child_re = re.compile(r'<w:(\w+)\b[^>]*?/>|<w:(\w+)\b[^>]*>.*?</w:\2>', re.S)

    def _add_borders(m):
        kids = [(c.group(1) or c.group(2), c.group(0)) for c in child_re.finditer(m.group(1))]
        if not any(name == "tblBorders" for name, _ in kids):
            kids.append(("tblBorders", borders))
        kids.sort(key=lambda k: tbl_order.index(k[0]) if k[0] in tbl_order else len(tbl_order))
        return '<w:tblPr>' + "".join(x for _, x in kids) + '</w:tblPr>'
    xml = re.sub(r'<w:tblPr>(.*?)</w:tblPr>', _add_borders, xml, flags=re.S)
    # shade header rows (pandoc marks them with <w:tblHeader/>)
    xml = re.sub(r'(<w:trPr><w:tblHeader ?/></w:trPr>)(.*?)(</w:tr>)',
                 lambda m: m.group(1) + m.group(2).replace('<w:tcPr>', '<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="DCE6F7"/>') + m.group(3),
                 xml, flags=re.S)
    # pStyle must be the first child of <w:pPr> (pandoc puts it after numPr in list items)
    xml = re.sub(r'<w:pPr>(<w:numPr>.*?</w:numPr>)(<w:pStyle [^>]*/>)', r'<w:pPr>\2\1', xml)
    doc.write_text(xml, encoding="utf-8")
    # numbering ids must be 8 hex digits
    num = tmp / "word" / "numbering.xml"
    if num.exists():
        nx = num.read_text(encoding="utf-8")
        nx = re.sub(r'(<w:nsid w:val=")([0-9A-Fa-f]+)(")', lambda m: m.group(1) + m.group(2).zfill(8)[-8:] + m.group(3), nx)
        num.write_text(nx, encoding="utf-8")
    # declare png/jpeg as defaults as well (pandoc only adds per-file overrides)
    ctf = tmp / "[Content_Types].xml"
    ct = ctf.read_text(encoding="utf-8")
    for ext, mime in (("png", "image/png"), ("jpeg", "image/jpeg"), ("jpg", "image/jpeg")):
        if f'Extension="{ext}"' not in ct:
            ct = ct.replace("<Default ", f'<Default Extension="{ext}" ContentType="{mime}" /><Default ', 1)
    ctf.write_text(ct, encoding="utf-8")
    # Ask Word to refresh the TOC field when the file is opened
    settings = tmp / "word" / "settings.xml"
    st = settings.read_text(encoding="utf-8")
    if "updateFields" not in st:
        st = st.replace("</w:settings>", '<w:updateFields w:val="true"/></w:settings>')
        st = _sort_settings(st)
        settings.write_text(st, encoding="utf-8")
    docx.unlink()
    with zipfile.ZipFile(docx, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(tmp.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(tmp).as_posix())
    shutil.rmtree(tmp)


def toc_xml() -> str:
    """Word TOC field. Pre-filled with the section titles so it is never empty;
    Word refreshes it (with page numbers) when the document is opened."""
    titles = ["Executive summary"]
    for md in sorted(DOCS.glob("[0-9][0-9]_*.md")):
        first = next(l for l in md.read_text(encoding="utf-8").splitlines() if l.startswith("# "))
        titles.append(first[2:].strip())
    titles += ["Appendix A: Demonstration screenshots", "Appendix B: Adversarial demonstration transcript",
               "Appendix C: Automated test results", "Appendix D: Setup and run instructions"]
    esc = lambda t: t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    paras = []
    for i, t in enumerate(titles):
        runs = ""
        if i == 0:
            runs += ('<w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r>'
                     '<w:r><w:instrText xml:space="preserve"> TOC \\o "1-2" \\h \\z \\u </w:instrText></w:r>'
                     '<w:r><w:fldChar w:fldCharType="separate"/></w:r>')
        runs += f'<w:r><w:t xml:space="preserve">{esc(t)}</w:t></w:r>'
        if i == len(titles) - 1:
            runs += '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        paras.append(f'<w:p><w:pPr><w:pStyle w:val="TOC1"/></w:pPr>{runs}</w:p>')
    return ("```{=openxml}\n<w:p><w:pPr><w:pStyle w:val=\"TOCHeading\"/></w:pPr><w:r><w:t>Table of Contents</w:t></w:r></w:p>"
            + "".join(paras) + "\n```")


def build_markdown(members) -> str:
    parts = []
    member_lines = "\n".join(f"| {m} |" for m in members)
    parts.append(f"""---
title: "Secure Document Management System (SecureDMS)"
subtitle: "CS3002 Information Security: Semester Project Report"
date: "{date.today().strftime('%d %B %Y')}"
---

**National University of Computer & Emerging Sciences, Chiniot-Faisalabad Campus**

| Group members |
|---|
{member_lines}

**Submission contents:** (1) this report; (2) ZIP archive / GitHub repository with the complete source code,
configuration, setup instructions (`README.md`, `GUIDE.md`), fictional test data and demonstration screenshots.

{PAGEBREAK}

{toc_xml()}

{PAGEBREAK}

> *"The objective is not to build the largest system. It is to build a defensible one."* Our goal was a
> small system in which every security decision can be explained, tested and defended.

## Executive summary

SecureDMS is a web-based document management system built with Python/Flask and the pyca/cryptography library.

- **Encryption at rest:** every document is encrypted at rest with its own AES-256-GCM key.
- **Key distribution:** that key is wrapped with the RSA-3072 public key of each user who is authorised to read the document.
- **Key protection:** users' private keys are encrypted with a key derived from their password (scrypt) and a separate server key-encryption key. As a result, neither a stolen database nor the administrator can read documents.
- **Access control:** a hybrid model combines RBAC for system functions, owner-controlled DAC (owner/editor/viewer) for documents, and expiry conditions. It is enforced on every operation in a single module.
- **Sharing and revocation:** sharing re-wraps the document key for the recipient, and revocation re-encrypts the document under a fresh key.
- **Integrity:** every version carries an AES-GCM tag bound to its document ID and an Ed25519 signature of its author.
- **Auditing:** all security-relevant events are written to an append-only, hash-chained, HMAC-protected audit log with an external anchor.

We tested the seven adversarial scenarios required by the manual against our own controlled instance; **all seven behave as designed** (33/33 automated tests pass). The limitations we found are discussed in each section.

**Report structure:**

| Section | Content |
|---|---|
| 1 | Security research and design (Part 1, all 25 questions) |
| 2–6 | Architecture, threat model, database/storage, cryptographic and access-control design (Part 5) |
| 7 | Security testing report (Part 3) |
| 8 | Design decision records (Part 4) |
| 9 | Demonstration plan |
| 10 | References |
| Appendices | A: screenshots; B: attack transcript; C: test results; D: setup |

{PAGEBREAK}
""")
    for md in sorted(DOCS.glob("[0-9][0-9]_*.md")):
        text = md.read_text(encoding="utf-8")
        # widen diagrams to page width
        text = re.sub(r'!\[([^\]]*)\]\((diagrams/[^)]+)\)', r'![\1](\2){width=6.3in}', text)
        text = re.sub(r'^\*Source: .*\*$', '', text, flags=re.M)
        parts.append(text + "\n\n" + PAGEBREAK)

    parts.append("# Appendix A: Demonstration screenshots\n\n"
                 "Captured automatically by `scripts/take_screenshots.py` from a running instance seeded with "
                 "fictional data.\n")
    for i, png in enumerate(sorted(SHOTS.glob("*.png")), 1):
        cap = SCREENSHOT_CAPTIONS.get(png.stem, png.stem)
        parts.append(f"\n![Figure A{i}: {cap}]({png.as_posix()}){{width=6.0in}}\n")
    parts.append(PAGEBREAK + "\n# Appendix B: Adversarial demonstration transcript\n\n"
                 "Output of `python scripts/attack_demos.py` (full file: `evidence/attack_demo_output.txt`).\n\n```text\n"
                 + (ROOT / "evidence" / "attack_demo_output.txt").read_text(encoding="utf-8") + "\n```\n")
    pytest_out = (ROOT / "evidence" / "pytest_output.txt").read_text(encoding="utf-8")
    lines = [l for l in pytest_out.splitlines() if "PASSED" in l or "FAILED" in l or " passed" in l]
    parts.append(PAGEBREAK + "\n# Appendix C: Automated test results\n\nOutput of `pytest -v`:\n\n```text\n"
                 + "\n".join(lines) + "\n```\n")
    guide = (ROOT / "GUIDE.md").read_text(encoding="utf-8")
    run_section = guide.split("## 1. How to run")[1].split("\n---")[0]
    parts.append(PAGEBREAK + "\n# Appendix D: Setup and run instructions\n" + run_section)
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--members", nargs="+",
                    default=["Member 1 Name (Roll#01)", "Member 2 Name (Roll#02)", "Member 3 Name (Roll#03)"])
    ap.add_argument("--out", default="Roll#01_Roll#02_Roll#03_IS_Project.docx")
    args = ap.parse_args()
    if shutil.which("pandoc") is None:
        raise SystemExit("pandoc not found - install it from https://pandoc.org/installing.html")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        md = td / "report.md"
        md.write_text(build_markdown(args.members), encoding="utf-8")
        ref = td / "ref.docx"
        make_reference_docx(ref)
        out = ROOT / args.out
        subprocess.run(["pandoc", str(md), "-o", str(out), 
                        f"--reference-doc={ref}", f"--resource-path={DOCS}:{ROOT}",
                        "-f", "markdown+pipe_tables+raw_tex"], check=True)
        add_table_borders(out)
    print(f"Report written to {out}")


if __name__ == "__main__":
    main()
