import hashlib
import sqlite3
import os
import shutil
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime

# ---------------- HASH FUNCTION ----------------
def generate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

# ---------------- DATABASE ----------------
def create_database():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        case_title TEXT,
        investigator TEXT,
        date_created TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        evidence_id TEXT PRIMARY KEY,
        case_id TEXT,
        filename TEXT,
        hash_value TEXT,
        date_added TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chain_of_custody (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT,
        action TEXT,
        performed_by TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

# ---------------- CREATE CASE ----------------
def create_case():
    case_id = input("Enter Case ID: ")
    case_title = input("Enter Case Title: ")
    investigator = input("Enter Investigator Name: ")
    date_created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO cases VALUES (?, ?, ?, ?)",
        (case_id, case_title, investigator, date_created)
    )

    conn.commit()
    conn.close()
    print("\n✅ Case created successfully.")

# ---------------- ADD EVIDENCE ----------------
def add_evidence():
    case_id = input("Enter Case ID: ")
    evidence_id = input("Enter Evidence ID: ")
    file_path = input("Enter full path of evidence file: ")
    investigator = input("Investigator Name: ")

    filename = os.path.basename(file_path)
    hash_value = generate_hash(file_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    shutil.copy(file_path, "evidence/")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
        (evidence_id, case_id, filename, hash_value, timestamp)
    )

    cursor.execute(
        "INSERT INTO chain_of_custody (evidence_id, action, performed_by, timestamp) VALUES (?, ?, ?, ?)",
        (evidence_id, "Collected", investigator, timestamp)
    )

    conn.commit()
    conn.close()

    print("\n✅ Evidence added and chain of custody logged.")




#---------------------Integrity Verification Function-------------------

def verify_evidence_integrity():
    evidence_id = input("Enter Evidence ID: ")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename, hash_value FROM evidence WHERE evidence_id = ?",
        (evidence_id,)
    )
    result = cursor.fetchone()
    conn.close()

    if not result:
        print("❌ Evidence not found.")
        return

    filename, stored_hash = result
    file_path = os.path.join("evidence", filename)

    current_hash = generate_hash(file_path)

    if current_hash == stored_hash:
        print("✅ Evidence integrity VERIFIED. No tampering detected.")
    else:
        print("❌ WARNING: Evidence integrity COMPROMISED!")


#-------------Sign Report--------------

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def sign_report(report_path):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    with open(report_path, "rb") as report:
        report_data = report.read()

    signature = private_key.sign(
        report_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = report_path + ".sig"
    with open(sig_path, "wb") as sig_file:
        sig_file.write(signature)

    print(f"✅ Report digitally signed: {sig_path}")


#-------------------PDF REPORT GENERATOR--------------------------
def generate_pdf_report(case_id, case_title, investigator, date_created, evidences):
    pdf_path = f"reports/forensic_report_{case_id}.pdf"

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "DIGITAL FORENSIC REPORT")
    y -= 40

    c.setFont("Helvetica", 11)
    c.drawString(50, y, f"Case ID      : {case_id}")
    y -= 20
    c.drawString(50, y, f"Case Title   : {case_title}")
    y -= 20
    c.drawString(50, y, f"Investigator : {investigator}")
    y -= 20
    c.drawString(50, y, f"Date Created : {date_created}")
    y -= 30

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "EVIDENCE DETAILS")
    y -= 20

    c.setFont("Helvetica", 10)

    if not evidences:
        c.drawString(50, y, "No evidence found for this case.")
    else:
        for e in evidences:
            if y < 100:  # New page if space ends
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 50

            c.drawString(50, y, f"Evidence ID : {e[0]}")
            y -= 15
            c.drawString(50, y, f"Filename    : {e[1]}")
            y -= 15
            c.drawString(50, y, f"SHA-256     : {e[2][:64]}")
            y -= 15
            c.drawString(50, y, f"Date Added  : {e[3]}")
            y -= 25

    c.showPage()
    c.save()

    print(f"✅ PDF forensic report generated: {pdf_path}")

    return pdf_path




#-------------------Report Generation Function-----------------

def generate_forensic_report():
    case_id = input("Enter Case ID for report: ")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Fetch case details
    cursor.execute(
        "SELECT case_title, investigator, date_created FROM cases WHERE case_id = ?",
        (case_id,)
    )
    case = cursor.fetchone()

    if not case:
        print("❌ Case not found.")
        conn.close()
        return

    case_title, investigator, date_created = case

    # Fetch evidence details
    cursor.execute(
        "SELECT evidence_id, filename, hash_value, date_added FROM evidence WHERE case_id = ?",
        (case_id,)
    )
    evidences = cursor.fetchall()

    conn.close()

    # TXT report
    report_path = f"reports/forensic_report_{case_id}.txt"
    with open(report_path, "w") as report:
        report.write("DIGITAL FORENSIC REPORT\n")
        report.write("=======================\n\n")
        report.write(f"Case ID        : {case_id}\n")
        report.write(f"Case Title     : {case_title}\n")
        report.write(f"Investigator   : {investigator}\n")
        report.write(f"Date Created   : {date_created}\n\n")

        report.write("EVIDENCE DETAILS:\n")
        report.write("-----------------\n")

        if not evidences:
            report.write("No evidence found for this case.\n")
        else:
            for e in evidences:
                report.write(f"Evidence ID : {e[0]}\n")
                report.write(f"Filename    : {e[1]}\n")
                report.write(f"SHA-256     : {e[2]}\n")
                report.write(f"Date Added  : {e[3]}\n")
                report.write("-------------------------\n")

    print(f"✅ Forensic report generated: {report_path}")

    # PDF report + signature
    pdf_path = generate_pdf_report(
        case_id,
        case_title,
        investigator,
        date_created,
        evidences
    )

    sign_report(pdf_path)



# ---------------- MAIN PROGRAM ----------------
create_database()

print("\n--- Cybercrime Evidence Management System ---")
print("1. Create New Case")
print("2. Generate Evidence Hash")
print("3. Add Evidence to Case")
print("4. Verify Evidence Integrity")
print("5. Generate Forensic Report")



choice = input("Enter your choice: ")

if choice == "1":
    create_case()
elif choice == "2":
    file_path = input("Enter full path of the evidence file: ")
    print("SHA-256 Hash:", generate_hash(file_path))
elif choice == "3":
    add_evidence()
elif choice == "4":
    verify_evidence_integrity()
elif choice == "5":
    generate_forensic_report()


else:
    print("❌ Invalid choice")
