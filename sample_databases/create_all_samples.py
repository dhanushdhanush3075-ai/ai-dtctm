"""
Create 7 sample databases for AI-DTCTM Forensic Scanner testing.
4 UNSAFE (with vulnerabilities) + 3 SAFE (clean)
"""
import sqlite3, os, random, datetime

DIR = os.path.dirname(__file__)

def _create(name, setup_fn):
    path = os.path.join(DIR, name)
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    setup_fn(conn)
    conn.commit()
    rows = conn.execute("SELECT SUM(cnt) FROM (SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table')").fetchone()[0]
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    total_rows = 0
    for t in tables:
        total_rows += conn.execute(f"SELECT COUNT(*) FROM [{t[0]}]").fetchone()[0]
    conn.close()
    tag = "[UNSAFE]" if "unsafe" in name or "vuln" in name or "attack" in name else "[SAFE]  "
    print(f"  {tag} {name:45s} {len(tables)} tables  {total_rows:,} rows")

# ═══════════════════════════════════════════════════════════════
# 1. SAFE — E-Commerce Store (clean)
# ═══════════════════════════════════════════════════════════════
def safe_ecommerce(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT, stock INTEGER)")
    c.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, city TEXT, joined TEXT)")
    c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, product_id INTEGER, qty INTEGER, total REAL, order_date TEXT, status TEXT)")

    products = [("Laptop Dell Inspiron", 45999, "Electronics", 25), ("Samsung Galaxy S24", 69999, "Mobile", 40),
                ("Nike Air Max", 8999, "Footwear", 100), ("Boat Headphones", 1499, "Audio", 200),
                ("HP Printer", 12999, "Electronics", 15), ("Coding Book Python", 599, "Books", 300)]
    for p in products:
        c.execute("INSERT INTO products (name,price,category,stock) VALUES (?,?,?,?)", p)

    for i in range(50):
        c.execute("INSERT INTO customers (name,email,city,joined) VALUES (?,?,?,?)",
                  (f"Customer {i+1}", f"cust{i+1}@gmail.com", random.choice(["Chennai","Mumbai","Delhi","Bangalore"]),
                   f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}"))

    for i in range(120):
        c.execute("INSERT INTO orders (customer_id,product_id,qty,total,order_date,status) VALUES (?,?,?,?,?,?)",
                  (random.randint(1,50), random.randint(1,6), random.randint(1,3),
                   round(random.uniform(500,70000),2), f"2024-{random.randint(1,6):02d}-{random.randint(1,28):02d}",
                   random.choice(["delivered","shipped","processing","cancelled"])))

# ═══════════════════════════════════════════════════════════════
# 2. UNSAFE — Hospital with data leaks
# ═══════════════════════════════════════════════════════════════
def unsafe_hospital(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, phone TEXT, diagnosis TEXT, blood_group TEXT, address TEXT)")
    c.execute("CREATE TABLE doctors (id INTEGER PRIMARY KEY, name TEXT, dept TEXT, email TEXT, password TEXT)")
    c.execute("CREATE TABLE prescriptions (id INTEGER PRIMARY KEY, patient_id INTEGER, doctor_id INTEGER, medicine TEXT, dosage TEXT, notes TEXT)")
    c.execute("CREATE TABLE billing (id INTEGER PRIMARY KEY, patient_id INTEGER, amount REAL, payment_mode TEXT, credit_card_number TEXT, cvv TEXT)")
    c.execute("CREATE TABLE admin_log (id INTEGER PRIMARY KEY, action TEXT, user TEXT, ip TEXT, timestamp TEXT)")

    for i in range(80):
        c.execute("INSERT INTO patients VALUES (?,?,?,?,?,?,?)",
                  (i+1, f"Patient {i+1}", random.randint(5,85), f"+91 {random.randint(7000000000,9999999999)}",
                   random.choice(["Fever","Diabetes","Fracture","Surgery","BP","Cardiac"]),
                   random.choice(["A+","B+","O+","AB+"]), f"{random.randint(1,200)} Street, Chennai"))

    # VULNERABILITY: Plaintext passwords
    docs = [("Dr. Ramesh", "Cardiology", "ramesh@hospital.com", "password123"),
            ("Dr. Priya", "Neurology", "priya@hospital.com", "admin123"),
            ("Dr. Kumar", "Orthopedics", "kumar@hospital.com", "doctor@2024"),
            ("Dr. Meena", "Pediatrics", "meena@hospital.com", "letmein")]
    for d in docs:
        c.execute("INSERT INTO doctors (name,dept,email,password) VALUES (?,?,?,?)", d)

    for i in range(100):
        c.execute("INSERT INTO prescriptions (patient_id,doctor_id,medicine,dosage,notes) VALUES (?,?,?,?,?)",
                  (random.randint(1,80), random.randint(1,4), random.choice(["Paracetamol","Amoxicillin","Insulin","Aspirin"]),
                   random.choice(["500mg","250mg","100mg"]), "Take after food"))

    # VULNERABILITY: Credit card numbers stored in plaintext
    for i in range(40):
        cc = f"4{random.randint(100,999)} {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
        c.execute("INSERT INTO billing (patient_id,amount,payment_mode,credit_card_number,cvv) VALUES (?,?,?,?,?)",
                  (random.randint(1,80), round(random.uniform(500,50000),2), "Credit Card", cc, str(random.randint(100,999))))

    # VULNERABILITY: Suspicious admin activity
    c.execute("INSERT INTO admin_log VALUES (?,?,?,?,?)", (1, "BULK_EXPORT", "unknown", "185.220.101.34", "2024-06-04 02:30:00"))
    c.execute("INSERT INTO admin_log VALUES (?,?,?,?,?)", (2, "BRUTE_FORCE", "attacker", "103.21.58.44", "2024-06-04 03:15:00"))
    c.execute("INSERT INTO admin_log VALUES (?,?,?,?,?)", (3, "SQL_INJECTION_ATTEMPT", "' OR 1=1 --", "91.92.120.50", "2024-06-04 03:20:00"))

# ═══════════════════════════════════════════════════════════════
# 3. SAFE — School Library (clean)
# ═══════════════════════════════════════════════════════════════
def safe_library(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE books (id INTEGER PRIMARY KEY, title TEXT, author TEXT, isbn TEXT, category TEXT, copies INTEGER)")
    c.execute("CREATE TABLE members (id INTEGER PRIMARY KEY, name TEXT, class TEXT, section TEXT, join_date TEXT)")
    c.execute("CREATE TABLE borrow_log (id INTEGER PRIMARY KEY, member_id INTEGER, book_id INTEGER, borrow_date TEXT, return_date TEXT, status TEXT)")

    books = [("Let Us C", "Yashavant Kanetkar", "978-8183331630", "Programming", 5),
             ("Data Structures", "Reema Thareja", "978-0198099307", "CS", 3),
             ("Physics NCERT", "NCERT", "978-8174506", "Science", 10),
             ("Chemistry Lab Manual", "Lab Guide", "978-817450", "Science", 8),
             ("English Grammar", "Wren Martin", "978-935-2530", "English", 12)]
    for b in books:
        c.execute("INSERT INTO books (title,author,isbn,category,copies) VALUES (?,?,?,?,?)", b)

    for i in range(60):
        c.execute("INSERT INTO members (name,class,section,join_date) VALUES (?,?,?,?)",
                  (f"Student {i+1}", f"{random.randint(6,12)}", random.choice(["A","B","C"]),
                   f"2024-{random.randint(1,6):02d}-{random.randint(1,28):02d}"))

    for i in range(150):
        bd = f"2024-{random.randint(1,6):02d}-{random.randint(1,28):02d}"
        rd = f"2024-{random.randint(1,6):02d}-{random.randint(1,28):02d}" if random.random() > 0.3 else None
        c.execute("INSERT INTO borrow_log (member_id,book_id,borrow_date,return_date,status) VALUES (?,?,?,?,?)",
                  (random.randint(1,60), random.randint(1,5), bd, rd, "returned" if rd else "issued"))

# ═══════════════════════════════════════════════════════════════
# 4. UNSAFE — Banking with SQL injection + leaked data
# ═══════════════════════════════════════════════════════════════
def unsafe_banking(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, holder TEXT, account_number TEXT, balance REAL, account_type TEXT, branch TEXT)")
    c.execute("CREATE TABLE transactions (id INTEGER PRIMARY KEY, from_acc INTEGER, to_acc INTEGER, amount REAL, type TEXT, timestamp TEXT, notes TEXT)")
    c.execute("CREATE TABLE login_attempts (id INTEGER PRIMARY KEY, username TEXT, password TEXT, ip TEXT, status TEXT, timestamp TEXT)")
    c.execute("CREATE TABLE sensitive_data (id INTEGER PRIMARY KEY, customer_id INTEGER, ssn TEXT, bank_account TEXT, routing_number TEXT)")

    for i in range(30):
        c.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?)",
                  (i+1, f"Account Holder {i+1}", f"ACC{random.randint(100000,999999)}",
                   round(random.uniform(1000,500000),2), random.choice(["Savings","Current"]),
                   random.choice(["Chennai Main","KK Nagar","T Nagar"])))

    for i in range(200):
        c.execute("INSERT INTO transactions (from_acc,to_acc,amount,type,timestamp,notes) VALUES (?,?,?,?,?,?)",
                  (random.randint(1,30), random.randint(1,30), round(random.uniform(100,50000),2),
                   random.choice(["NEFT","UPI","IMPS","Cash"]),
                   f"2024-{random.randint(1,6):02d}-{random.randint(1,28):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:00",
                   "Transfer"))

    # VULNERABILITY: SQL injection in login attempts
    attacks = [
        ("admin", "password123", "192.168.1.1", "success", "2024-06-01 10:00:00"),
        ("' OR 1=1 --", "hacked", "185.220.101.34", "blocked", "2024-06-04 03:15:00"),
        ("admin' DROP TABLE accounts--", "injectable", "103.21.58.44", "blocked", "2024-06-04 03:16:00"),
        ("root", "123456", "91.92.120.50", "failed", "2024-06-04 03:17:00"),
        ("admin", "admin123", "45.33.32.156", "failed", "2024-06-04 03:18:00"),
        ("admin", "qwerty", "194.26.135.100", "failed", "2024-06-04 03:19:00"),
    ]
    for a in attacks:
        c.execute("INSERT INTO login_attempts (username,password,ip,status,timestamp) VALUES (?,?,?,?,?)", a)

    # VULNERABILITY: PII stored without encryption
    for i in range(10):
        c.execute("INSERT INTO sensitive_data (customer_id,ssn,bank_account,routing_number) VALUES (?,?,?,?)",
                  (random.randint(1,30), f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",
                   f"ACC{random.randint(100000,999999)}", f"{random.randint(100000000,999999999)}"))

# ═══════════════════════════════════════════════════════════════
# 5. SAFE — Restaurant Management (clean)
# ═══════════════════════════════════════════════════════════════
def safe_restaurant(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE menu (id INTEGER PRIMARY KEY, item TEXT, category TEXT, price REAL, available INTEGER)")
    c.execute("CREATE TABLE staff (id INTEGER PRIMARY KEY, name TEXT, role TEXT, phone TEXT, shift TEXT)")
    c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, table_no INTEGER, items TEXT, total REAL, order_time TEXT, status TEXT)")

    items = [("Chicken Biryani","Main Course",250,1),("Paneer Butter Masala","Main Course",180,1),
             ("Masala Dosa","South Indian",80,1),("Filter Coffee","Beverages",40,1),
             ("Gulab Jamun","Dessert",60,1),("Naan","Bread",30,1),("Tandoori Chicken","Starter",320,1)]
    for it in items:
        c.execute("INSERT INTO menu (item,category,price,available) VALUES (?,?,?,?)", it)

    for i in range(15):
        c.execute("INSERT INTO staff (name,role,phone,shift) VALUES (?,?,?,?)",
                  (f"Staff {i+1}", random.choice(["Chef","Waiter","Manager","Cashier"]),
                   f"+91 {random.randint(7000000000,9999999999)}", random.choice(["Morning","Evening","Night"])))

    for i in range(200):
        c.execute("INSERT INTO orders (table_no,items,total,order_time,status) VALUES (?,?,?,?,?)",
                  (random.randint(1,20), random.choice(["Biryani x2","Dosa x3","Coffee x4","Naan + Paneer"]),
                   round(random.uniform(80,800),2),
                   f"2024-{random.randint(1,6):02d}-{random.randint(1,28):02d} {random.randint(10,22):02d}:{random.randint(0,59):02d}",
                   random.choice(["served","preparing","cancelled"])))

# ═══════════════════════════════════════════════════════════════
# 6. UNSAFE — Student Portal with XSS + weak auth
# ═══════════════════════════════════════════════════════════════
def unsafe_student_portal(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)")
    c.execute("CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT, posted_at TEXT)")
    c.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, post_id INTEGER, user_id INTEGER, comment TEXT, created_at TEXT)")
    c.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, from_id INTEGER, to_id INTEGER, message TEXT, sent_at TEXT)")

    # VULNERABILITY: Plaintext passwords
    users = [("admin", "admin123", "admin", "admin@portal.edu"),
             ("student1", "password", "student", "s1@portal.edu"),
             ("teacher1", "123456", "teacher", "t1@portal.edu"),
             ("hacker", "' OR 1=1 --", "student", "hack@test.com")]
    for u in users:
        c.execute("INSERT INTO users (username,password,role,email) VALUES (?,?,?,?)", u)

    # VULNERABILITY: XSS in posts and comments
    posts = [
        (1, "Welcome to Portal", "Hello students, welcome!", "2024-06-01"),
        (2, "Exam Schedule", "Exams start from June 15", "2024-06-02"),
        (3, "<script>document.cookie</script>", "<img src=x onerror=alert('XSS')>", "2024-06-03"),
        (4, "Normal Post", "This is a regular post about campus life", "2024-06-04"),
    ]
    for p in posts:
        c.execute("INSERT INTO posts (user_id,title,content,posted_at) VALUES (?,?,?,?)", p)

    comments = [
        (1, 1, "Great portal!", "2024-06-01"),
        (2, 2, "Thanks for the info", "2024-06-02"),
        (3, 3, "<script>alert('XSS in comment')</script>", "2024-06-03"),
        (1, 4, "onclick=alert(1)", "2024-06-04"),
    ]
    for cm in comments:
        c.execute("INSERT INTO comments (post_id,user_id,comment,created_at) VALUES (?,?,?,?)", cm)

    # VULNERABILITY: Suspicious messages
    c.execute("INSERT INTO messages (from_id,to_id,message,sent_at) VALUES (?,?,?,?)",
              (4, 1, "' OR 1=1 -- trying to bypass auth", "2024-06-03 03:00:00"))
    c.execute("INSERT INTO messages (from_id,to_id,message,sent_at) VALUES (?,?,?,?)",
              (4, 1, "UNION SELECT * FROM users WHERE role='admin'", "2024-06-03 03:01:00"))

# ═══════════════════════════════════════════════════════════════
# 7. UNSAFE — Company HR with leaked salaries
# ═══════════════════════════════════════════════════════════════
def unsafe_hr_system(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, dept TEXT, designation TEXT, salary REAL, pan_card TEXT, phone TEXT)")
    c.execute("CREATE TABLE payroll (id INTEGER PRIMARY KEY, emp_id INTEGER, month TEXT, basic REAL, hra REAL, deductions REAL, net_pay REAL, bank_account TEXT)")
    c.execute("CREATE TABLE access_log (id INTEGER PRIMARY KEY, emp_id TEXT, action TEXT, resource TEXT, ip TEXT, timestamp TEXT)")
    c.execute("CREATE TABLE credentials (id INTEGER PRIMARY KEY, emp_id INTEGER, username TEXT, password TEXT, last_login TEXT)")

    for i in range(45):
        c.execute("INSERT INTO employees VALUES (?,?,?,?,?,?,?)",
                  (i+1, f"Employee {i+1}", random.choice(["IT","HR","Finance","Marketing","Sales"]),
                   random.choice(["Manager","Senior Dev","Junior Dev","Analyst","Executive"]),
                   round(random.uniform(25000,150000),2), f"ABCDE{random.randint(1000,9999)}F",
                   f"+91 {random.randint(7000000000,9999999999)}"))

    for i in range(45):
        for m in ["Jan","Feb","Mar","Apr","May","Jun"]:
            basic = round(random.uniform(20000,100000),2)
            hra = round(basic * 0.4, 2)
            ded = round(basic * 0.12, 2)
            c.execute("INSERT INTO payroll (emp_id,month,basic,hra,deductions,net_pay,bank_account) VALUES (?,?,?,?,?,?,?)",
                      (i+1, m, basic, hra, ded, round(basic+hra-ded,2), f"ACC{random.randint(100000,999999)}"))

    # VULNERABILITY: Plaintext passwords + weak
    creds = [("admin", "admin", "password123"), ("hr_manager", "hr_mgr", "letmein"),
             ("ceo", "boss", "master"), ("it_admin", "root", "qwerty")]
    for emp_id, uname, pw in creds:
        c.execute("INSERT INTO credentials (emp_id,username,password,last_login) VALUES (?,?,?,?)",
                  (random.randint(1,45), uname, pw, "2024-06-04"))

    # VULNERABILITY: Unauthorized access + data export
    logs = [("unknown", "BULK_EXPORT", "payroll", "185.220.101.34", "2024-06-04 02:00:00"),
            ("unknown", "BRUTE_FORCE", "credentials", "103.21.58.44", "2024-06-04 02:15:00"),
            ("admin", "DELETE_RECORD", "employees", "10.0.0.1", "2024-06-04 03:00:00")]
    for l in logs:
        c.execute("INSERT INTO access_log (emp_id,action,resource,ip,timestamp) VALUES (?,?,?,?,?)", l)


# ═══════════════════════════════════════════════════════════════
# CREATE ALL
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n{'='*65}")
    print(f"  AI-DTCTM — Creating 7 Sample Databases")
    print(f"{'='*65}")
    _create("safe_01_ecommerce_store.db", safe_ecommerce)
    _create("unsafe_02_hospital_records.db", unsafe_hospital)
    _create("safe_03_school_library.db", safe_library)
    _create("unsafe_04_banking_system.db", unsafe_banking)
    _create("safe_05_restaurant_management.db", safe_restaurant)
    _create("unsafe_06_student_portal_xss.db", unsafe_student_portal)
    _create("unsafe_07_hr_system_leaked.db", unsafe_hr_system)
    print(f"{'='*65}")
    print(f"  [SAFE]   = Clean database (should show 0 findings)")
    print(f"  [UNSAFE] = Has vulnerabilities (scanner should detect them)")
    print(f"{'='*65}\n")
