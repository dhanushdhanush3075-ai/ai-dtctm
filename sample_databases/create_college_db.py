"""
Sample College Database Generator for AI-DTCTM Forensic Scanner Testing
Creates a realistic college database with intentional security vulnerabilities
for the forensic scanner to detect.
"""
import sqlite3
import os
import random
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "meenakshi_college_kknagar.db")

def create_database():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── TABLES ─────────────────────────────────────────────────────

    # 1. Students
    c.execute("""
        CREATE TABLE students (
            student_id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_number TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            dob TEXT,
            gender TEXT,
            department TEXT,
            year INTEGER,
            semester INTEGER,
            address TEXT,
            blood_group TEXT,
            guardian_name TEXT,
            guardian_phone TEXT,
            admission_date TEXT,
            status TEXT DEFAULT 'active'
        )
    """)

    # 2. Faculty
    c.execute("""
        CREATE TABLE faculty (
            faculty_id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            department TEXT,
            designation TEXT,
            qualification TEXT,
            salary REAL,
            join_date TEXT,
            password_hash TEXT,
            status TEXT DEFAULT 'active'
        )
    """)

    # 3. Courses
    c.execute("""
        CREATE TABLE courses (
            course_id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_code TEXT NOT NULL UNIQUE,
            course_name TEXT NOT NULL,
            department TEXT,
            credits INTEGER,
            semester INTEGER,
            faculty_id INTEGER,
            max_seats INTEGER DEFAULT 60,
            FOREIGN KEY (faculty_id) REFERENCES faculty(faculty_id)
        )
    """)

    # 4. Grades
    c.execute("""
        CREATE TABLE grades (
            grade_id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            course_id INTEGER,
            semester INTEGER,
            internal_marks REAL,
            external_marks REAL,
            total_marks REAL,
            grade TEXT,
            grade_point REAL,
            exam_date TEXT,
            FOREIGN KEY (student_id) REFERENCES students(student_id),
            FOREIGN KEY (course_id) REFERENCES courses(course_id)
        )
    """)

    # 5. Attendance
    c.execute("""
        CREATE TABLE attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            course_id INTEGER,
            date TEXT,
            status TEXT,
            marked_by INTEGER,
            FOREIGN KEY (student_id) REFERENCES students(student_id),
            FOREIGN KEY (course_id) REFERENCES courses(course_id)
        )
    """)

    # 6. Fees
    c.execute("""
        CREATE TABLE fees (
            fee_id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            semester INTEGER,
            tuition_fee REAL,
            lab_fee REAL,
            library_fee REAL,
            exam_fee REAL,
            total_fee REAL,
            paid_amount REAL,
            payment_date TEXT,
            payment_mode TEXT,
            receipt_number TEXT,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (student_id) REFERENCES students(student_id)
        )
    """)

    # 7. Library
    c.execute("""
        CREATE TABLE library_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            book_title TEXT,
            book_isbn TEXT,
            issue_date TEXT,
            due_date TEXT,
            return_date TEXT,
            fine_amount REAL DEFAULT 0,
            status TEXT DEFAULT 'issued',
            FOREIGN KEY (student_id) REFERENCES students(student_id)
        )
    """)

    # 8. Exam Schedule
    c.execute("""
        CREATE TABLE exam_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER,
            exam_type TEXT,
            exam_date TEXT,
            start_time TEXT,
            end_time TEXT,
            room_number TEXT,
            invigilator_id INTEGER,
            FOREIGN KEY (course_id) REFERENCES courses(course_id)
        )
    """)

    # 9. Audit Log (admin actions)
    c.execute("""
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT,
            user_id TEXT,
            action TEXT,
            target_table TEXT,
            target_id TEXT,
            old_value TEXT,
            new_value TEXT,
            ip_address TEXT,
            timestamp TEXT
        )
    """)

    # 10. Login credentials (INTENTIONAL VULNERABILITY - plaintext passwords)
    c.execute("""
        CREATE TABLE user_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            last_login TEXT,
            login_attempts INTEGER DEFAULT 0
        )
    """)

    # ── INSERT DATA ────────────────────────────────────────────────

    departments = ["Computer Science", "Electronics", "Mechanical", "Civil", "MBA", "BCA"]
    blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]

    first_names_m = ["Arun", "Karthik", "Vijay", "Surya", "Dhanush", "Praveen", "Rajesh", "Santhosh",
                     "Manikandan", "Gowtham", "Harish", "Dinesh", "Ganesh", "Naveen", "Ashok",
                     "Balaji", "Chandru", "Deepak", "Ezhil", "Hari", "Jayakumar", "Kumaran",
                     "Lokesh", "Mohan", "Nithish", "Pradeep", "Ravi", "Senthil", "Tamil", "Udhay"]
    first_names_f = ["Priya", "Divya", "Swetha", "Nandhini", "Kavitha", "Lakshmi", "Meena",
                     "Anitha", "Bhavani", "Chitra", "Deepika", "Gayathri", "Indhu", "Janani",
                     "Keerthana", "Lavanya", "Madhu", "Nisha", "Oviya", "Pooja", "Ramya",
                     "Saranya", "Thenmozhi", "Uma", "Vanitha", "Yamuna"]
    last_names = ["Kumar", "Raj", "Pandian", "Selvam", "Murugan", "Krishnan", "Rajan",
                  "Natarajan", "Subramanian", "Venkatesh", "Shanmugam", "Prakash",
                  "Sundaram", "Balasubramanian", "Kannan", "Mani", "Anand", "Devi",
                  "Lakshmi", "Sundari"]

    students_data = []
    for i in range(1, 151):  # 150 students
        dept = random.choice(departments)
        year = random.randint(1, 4)
        sem = year * 2 - random.randint(0, 1)
        gender = random.choice(["M", "F"])
        if gender == "M":
            fname = random.choice(first_names_m)
        else:
            fname = random.choice(first_names_f)
        lname = random.choice(last_names)
        name = f"{fname} {lname}"
        roll = f"MCC{2022 + (4-year)}{dept[:2].upper()}{i:03d}"
        dob = f"{random.randint(1999, 2005)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        email = f"{fname.lower()}.{lname.lower()}{random.randint(1,99)}@meenakshicollege.edu.in"
        phone = f"+91 {random.randint(70000,99999)}{random.randint(10000,99999)}"
        addr = f"{random.randint(1,200)}, {random.choice(['Anna Nagar','KK Nagar','T Nagar','Adyar','Velachery','Tambaram','Porur','Guindy'])}, Chennai - {random.choice(['600078','600024','600017','600020','600042','600045','600116','600032'])}"
        bg = random.choice(blood_groups)
        guardian = f"{random.choice(first_names_m)} {lname}"
        gphone = f"+91 {random.randint(70000,99999)}{random.randint(10000,99999)}"
        admit = f"{2022 + (4-year)}-07-{random.randint(1,30):02d}"

        students_data.append((roll, name, email, phone, dob, gender, dept, year, sem, addr, bg, guardian, gphone, admit, "active"))

    c.executemany("INSERT INTO students (roll_number,name,email,phone,dob,gender,department,year,semester,address,blood_group,guardian_name,guardian_phone,admission_date,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", students_data)

    # Faculty
    designations = ["Professor", "Associate Professor", "Assistant Professor", "HOD", "Lecturer"]
    qualifications = ["Ph.D", "M.Tech", "M.Sc", "MBA", "MCA", "M.Phil"]
    faculty_data = []
    for i in range(1, 31):  # 30 faculty
        dept = departments[(i-1) % len(departments)]
        fname = random.choice(first_names_m + first_names_f)
        lname = random.choice(last_names)
        name = f"Dr. {fname} {lname}" if random.random() > 0.4 else f"Prof. {fname} {lname}"
        emp_id = f"FAC{2015 + random.randint(0,8)}{i:03d}"
        email = f"{fname.lower()}.{lname.lower()}@meenakshicollege.edu.in"
        phone = f"+91 {random.randint(80000,99999)}{random.randint(10000,99999)}"
        desg = random.choice(designations)
        qual = random.choice(qualifications)
        salary = round(random.uniform(35000, 120000), 2)
        join_date = f"{random.randint(2015, 2023)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        # INTENTIONAL VULNERABILITY: Some have weak password hashes
        pw = random.choice(["5f4dcc3b5aa765d61d8327deb882cf99", "e10adc3949ba59abbe56e057f20f883e",
                           "d8578edf8458ce06fbc5bb76a58c5ca4", "sha256$salted$" + "a"*40,
                           "pbkdf2:sha256:150000$" + "b"*20])
        faculty_data.append((emp_id, name, email, phone, dept, desg, qual, salary, join_date, pw, "active"))

    c.executemany("INSERT INTO faculty (emp_id,name,email,phone,department,designation,qualification,salary,join_date,password_hash,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)", faculty_data)

    # Courses
    cs_courses = [("CS101","Data Structures",3), ("CS102","DBMS",4), ("CS103","Operating Systems",3),
                  ("CS104","Computer Networks",3), ("CS105","Software Engineering",3), ("CS106","Python Programming",4),
                  ("CS107","Machine Learning",4), ("CS108","Cyber Security",3), ("CS109","Cloud Computing",3),
                  ("CS110","Web Development",4)]
    ec_courses = [("EC101","Digital Electronics",3), ("EC102","Signal Processing",4), ("EC103","VLSI Design",3)]
    me_courses = [("ME101","Thermodynamics",3), ("ME102","Fluid Mechanics",4)]
    courses_data = []
    all_courses = cs_courses + ec_courses + me_courses
    for idx, (code, cname, credits) in enumerate(all_courses):
        dept = "Computer Science" if code.startswith("CS") else "Electronics" if code.startswith("EC") else "Mechanical"
        sem = random.randint(1, 8)
        fid = random.randint(1, 30)
        courses_data.append((code, cname, dept, credits, sem, fid, 60))
    c.executemany("INSERT INTO courses (course_code,course_name,department,credits,semester,faculty_id,max_seats) VALUES (?,?,?,?,?,?,?)", courses_data)

    # Grades
    grade_map = {"O": 10, "A+": 9, "A": 8, "B+": 7, "B": 6, "C": 5, "F": 0}
    grades_data = []
    for sid in range(1, 151):
        for cid in random.sample(range(1, len(all_courses)+1), min(5, len(all_courses))):
            sem = random.randint(1, 8)
            internal = round(random.uniform(15, 50), 1)
            external = round(random.uniform(20, 100), 1)
            total = round(internal + external, 1)
            if total >= 90: g, gp = "O", 10
            elif total >= 80: g, gp = "A+", 9
            elif total >= 70: g, gp = "A", 8
            elif total >= 60: g, gp = "B+", 7
            elif total >= 50: g, gp = "B", 6
            elif total >= 40: g, gp = "C", 5
            else: g, gp = "F", 0
            exam_date = f"2024-{random.choice(['04','11'])}-{random.randint(1,28):02d}"
            grades_data.append((sid, cid, sem, internal, external, total, g, gp, exam_date))
    c.executemany("INSERT INTO grades (student_id,course_id,semester,internal_marks,external_marks,total_marks,grade,grade_point,exam_date) VALUES (?,?,?,?,?,?,?,?,?)", grades_data)

    # Attendance (last 30 days)
    att_data = []
    for sid in random.sample(range(1, 151), 80):
        for day_offset in range(30):
            d = (datetime.date.today() - datetime.timedelta(days=day_offset)).isoformat()
            cid = random.randint(1, len(all_courses))
            status = random.choices(["present", "absent", "late"], weights=[80, 15, 5])[0]
            marked_by = random.randint(1, 30)
            att_data.append((sid, cid, d, status, marked_by))
    c.executemany("INSERT INTO attendance (student_id,course_id,date,status,marked_by) VALUES (?,?,?,?,?)", att_data)

    # Fees
    fees_data = []
    for sid in range(1, 151):
        for sem in range(1, random.randint(2, 5)):
            tuition = random.choice([45000, 55000, 65000, 75000])
            lab = random.choice([5000, 8000, 10000])
            lib = 2000
            exam = 3000
            total = tuition + lab + lib + exam
            paid = total if random.random() > 0.2 else round(total * random.uniform(0.3, 0.9))
            pdate = f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
            mode = random.choice(["Online", "Cash", "Cheque", "DD", "UPI"])
            receipt = f"RCP{2024}{sem}{sid:04d}"
            status = "paid" if paid >= total else "partial"
            fees_data.append((sid, sem, tuition, lab, lib, exam, total, paid, pdate, mode, receipt, status))
    c.executemany("INSERT INTO fees (student_id,semester,tuition_fee,lab_fee,library_fee,exam_fee,total_fee,paid_amount,payment_date,payment_mode,receipt_number,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", fees_data)

    # Library
    books = [
        ("Let Us C", "978-8183331630"), ("Data Structures using C", "978-0198099307"),
        ("Computer Networks", "978-9332518742"), ("Operating System Concepts", "978-1119800361"),
        ("Database System Concepts", "978-0078022159"), ("Python Crash Course", "978-1593279288"),
        ("Clean Code", "978-0132350884"), ("Introduction to Algorithms", "978-0262033848"),
        ("Artificial Intelligence", "978-0134610993"), ("Cyber Security Essentials", "978-1284183061"),
        ("Machine Learning", "978-1491962299"), ("Web Development with Django", "978-1484271575"),
    ]
    lib_data = []
    for sid in random.sample(range(1, 151), 60):
        book = random.choice(books)
        issue = (datetime.date.today() - datetime.timedelta(days=random.randint(1, 45))).isoformat()
        due = (datetime.date.today() + datetime.timedelta(days=random.randint(-10, 20))).isoformat()
        ret = None if random.random() > 0.5 else (datetime.date.today() - datetime.timedelta(days=random.randint(0, 5))).isoformat()
        fine = round(random.uniform(0, 50), 2) if ret and ret > due else 0
        status = "returned" if ret else "issued"
        lib_data.append((sid, book[0], book[1], issue, due, ret, fine, status))
    c.executemany("INSERT INTO library_records (student_id,book_title,book_isbn,issue_date,due_date,return_date,fine_amount,status) VALUES (?,?,?,?,?,?,?,?)", lib_data)

    # ── INTENTIONAL VULNERABILITIES (for scanner to detect) ──────

    # 1. PLAINTEXT PASSWORDS in user_credentials
    creds = [
        ("admin", "admin123", "admin", "2024-06-01 10:00:00", 0),
        ("principal", "meenakshi@2024", "admin", "2024-05-15 09:30:00", 0),
        ("hod_cs", "password123", "faculty", "2024-06-02 11:00:00", 0),
        ("student1", "123456", "student", "2024-06-03 08:00:00", 0),
        ("librarian", "library@123", "staff", "2024-06-01 09:00:00", 3),
        ("accounts", "fee2024#", "staff", "2024-05-20 10:30:00", 0),
        # SQL injection attempt in username
        ("' OR 1=1 --", "hacked", "admin", "2024-06-04 03:15:00", 15),
        ("admin' DROP TABLE--", "injectable", "admin", "2024-06-04 03:16:00", 22),
    ]
    c.executemany("INSERT INTO user_credentials (username,password,role,last_login,login_attempts) VALUES (?,?,?,?,?)", creds)

    # 2. Suspicious audit log entries
    audit_data = [
        ("admin", "ADM001", "LOGIN_SUCCESS", "user_credentials", "1", "", "", "192.168.1.100", "2024-06-01 10:00:00"),
        ("admin", "ADM001", "GRADE_MODIFIED", "grades", "45", "grade=B", "grade=A+", "192.168.1.100", "2024-06-02 23:45:00"),
        ("admin", "ADM001", "GRADE_MODIFIED", "grades", "112", "grade=C", "grade=O", "192.168.1.100", "2024-06-02 23:47:00"),
        ("unknown", "???", "BULK_EXPORT", "students", "ALL", "", "exported 150 records", "45.33.32.156", "2024-06-03 02:30:00"),
        ("admin", "ADM001", "FEE_WAIVER", "fees", "23", "paid=0", "paid=75000", "192.168.1.100", "2024-06-03 01:15:00"),
        ("system", "SYS", "BACKUP_FAILED", "database", "full", "", "disk full error", "127.0.0.1", "2024-06-03 03:00:00"),
        ("unknown", "???", "SQL_INJECTION_ATTEMPT", "user_credentials", "login", "", "' OR 1=1 --", "103.21.58.44", "2024-06-04 03:15:00"),
        ("unknown", "???", "BRUTE_FORCE", "user_credentials", "admin", "", "22 failed attempts", "185.220.101.34", "2024-06-04 03:20:00"),
        ("admin", "ADM001", "PASSWORD_RESET", "user_credentials", "5", "old_hash", "new_plaintext", "10.0.0.1", "2024-06-04 04:00:00"),
        ("admin", "ADM001", "DELETE_RECORD", "students", "148", "Ravi Kumar", "DELETED", "192.168.1.100", "2024-06-04 04:30:00"),
    ]
    c.executemany("INSERT INTO audit_log (user_type,user_id,action,target_table,target_id,old_value,new_value,ip_address,timestamp) VALUES (?,?,?,?,?,?,?,?,?)", audit_data)

    # 3. XSS attempt in student name
    c.execute("INSERT INTO students (roll_number,name,email,phone,dob,gender,department,year,semester,address,blood_group,guardian_name,guardian_phone,admission_date,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
              ("MCCXSS001", "<script>alert('XSS')</script>", "xss@test.com", "0000000000", "2000-01-01", "M", "Computer Science", 1, 1, "<img src=x onerror=alert(1)>", "O+", "Test", "0000000000", "2024-01-01", "active"))

    conn.commit()

    # Print summary
    tables = c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    print(f"\n{'='*60}")
    print(f"  MEENAKSHI COLLEGE KK NAGAR - Sample Database Created")
    print(f"{'='*60}")
    for t in tables:
        tname = t[0]
        count = c.execute(f"SELECT COUNT(*) FROM {tname}").fetchone()[0]
        cols = len(c.execute(f"PRAGMA table_info({tname})").fetchall())
        print(f"  {tname:25s} {cols:2d} cols  {count:6,d} rows")
    print(f"{'='*60}")
    print(f"  Saved to: {DB_PATH}")
    print(f"  Hidden vulnerabilities: SQL injection, XSS, plaintext passwords,")
    print(f"  suspicious grade changes, bulk export, brute force attempts")
    print(f"{'='*60}\n")

    conn.close()

if __name__ == "__main__":
    create_database()
