import pandas as pd
import streamlit as st
from io import StringIO, BytesIO
import re, itertools

# ---- Email list ingestion helpers ----
EMAIL_REGEX = re.compile(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', re.IGNORECASE)

def extract_emails_from_dataframe(df: pd.DataFrame) -> set:
    """
    Scan all columns, extract anything that looks like an email address.
    Handles cells with multiple emails separated by comma/semicolon/space.
    Returns a set of normalized (lowercase, trimmed) emails.
    """
    emails = set()
    for col in df.columns:
        series = df[col].dropna().astype(str)
        for cell in series:
            # Split on common delimiters first to reduce false positives
            fragments = re.split(r'[;,\\s]+', cell)
            for frag in fragments:
                for match in EMAIL_REGEX.findall(frag):
                    emails.add(match.strip().lower())
    return emails

def summarize_email_file(name: str, emails: set) -> str:
    return f"{name}: {len(emails)} emails"

# ---- Category classification setup ----
# Mapping of category name -> list of keyword/phrase substrings (all matched case-insensitively)
CATEGORY_KEYWORDS = {
    "Tax return": [
        "2021 tax return", "2022 personal tax return", "2022 tax return",
        "2023 business return", "2023 personal return", "2023 tax return",
        "2023 tax return with equity", "2024 business return", "2024 personal return",
        "amended return", "business and individual returns", "business return",
        "canada return", "canadian business return", "canadian tax return",
        "canadian tax return amendment", "estate return", "partnership return - form 1065",
        "partnership return", "personal return", "personal tax return with self employment activity",
        "return with equity", "tax return 2020", "tax return base fee",
        "tax return review", "tax return with self-employment activity", "trust return"
    ],
    "Consultation": [
        "1 hour consultation", "20 min consultation", "30 min consultation",
        "40 min consultation", "numerical analysis + a verbal consultation",
        "tax planning", "settlement planning", "consultation"
    ],
    "Audit": [
        "audit"
    ],
    "CSS": [
        "cost segregation study", "withholdings analysis"
    ],
    "Bookkeeping & cleanup": [
        "annual bookkeeping", "bookkeeping cleanup"
    ],
    "Payroll service": [
        "payroll service"
    ],
    "Entity formation & restructuring": [
        "dissolution", "entity dissolution", "entity formation", "s corp conversion"
    ],
    "Letters": [
        "cpa letter", "notarizing cpa letter", "poa + irs diagnostic call", "poa", "irs diagnostic call"
    ],
    "Review services": [
        "2022 review", "financial review", "review", "tax return review"
    ],
    "Sales tax": [
        "sales tax returns", "sales tax return"
    ],
    "Projections": [
        "trial return", "projection", "numerical analysis"
    ],
    "Compliance & filings": [
        "annual reports", "biennial filing", "biennial report", "ein", "fbar filing",
        "fbar for foreign bank account", "fbar/fincen 114 and irs form 8938",
        "foreign account disclosure (fbar/fincen 114 and irs form 8938)", "foreign account disclosure",
        "form 3520", "form 568", "form 843 fica tax refund petition", "form d-30",
        "franchise report", "installment agreement", "irs appeal", "representation"
    ]
}

# Precompute lowercase keyword mapping for speed
LOWER_KEYWORDS = {cat: [k.lower() for k in kws] for cat, kws in CATEGORY_KEYWORDS.items()}

def normalize_desc(text: str) -> str:
    if not isinstance(text, str):
        return ""
    t = text.lower()
    # unify separators
    t = t.replace('&', ' and ')
    t = re.sub(r'[-_/]', ' ', t)
    # drop punctuation except spaces and alphanum
    t = re.sub(r'[^a-z0-9 ]+', ' ', t)
    # collapse spaces
    t = re.sub(r'\s+', ' ', t).strip()
    return t

def categorize_description(text: str) -> str:
    """
    More robust categorizer:
    1. Exact / phrase substring match (normalized) using provided keyword lists.
    2. Heuristic token rules (eg any 'tax' + 'return' becomes Tax return).
    3. Avoid duplicates, return comma separated categories.
    """
    norm = normalize_desc(text)
    if not norm:
        return ""
    hits = set()

    # 1. phrase matches (normalized)
    for cat, kw_list in LOWER_KEYWORDS.items():
        for kw in kw_list:
            kw_norm = normalize_desc(kw)
            if kw_norm and kw_norm in norm:
                hits.add(cat)
                break

    tokens = set(norm.split())

    # 2. heuristic rules
    if {'tax', 'return'} & tokens and 'return' in tokens:
        hits.add("Tax return")
    if any(tok.startswith('consult') for tok in tokens) or 'planning' in tokens:
        hits.add("Consultation")
    if 'audit' in tokens:
        hits.add("Audit")
    if {'segregation','study'} & tokens or {'withholdings','analysis'} & tokens:
        hits.add("CSS")
    if 'bookkeeping' in tokens or 'cleanup' in tokens:
        hits.add("Bookkeeping & cleanup")
    if 'payroll' in tokens:
        hits.add("Payroll service")
    if 'dissolution' in tokens or (tokens & {'formation','conversion'}):
        hits.add("Entity formation & restructuring")
    if 'letter' in tokens or 'poa' in tokens or {'diagnostic','call'} <= tokens:
        hits.add("Letters")
    if 'review' in tokens:
        hits.add("Review services")
    if 'sales' in tokens and 'tax' in tokens:
        hits.add("Sales tax")
    if 'projection' in tokens or 'trial' in tokens or {'numerical','analysis'} <= tokens:
        hits.add("Projections")
    compliance_markers = {'annual','biennial','ein','fbar','form','franchise','installment','appeal','representation','disclosure'}
    if compliance_markers & tokens:
        hits.add("Compliance & filings")

    if not hits:
        return ""
    return ", ".join(sorted(hits))

st.set_page_config(page_title="Transaction Matcher", layout="wide")

st.title("Transaction Matcher")

st.markdown(
    """
Upload a **transaction file** (CSV or Excel) and one or more **email lists** (CSV or Excel).  
The app will show all matching transactions and totals per email. Then you can download the results as CSV.
"""
)

trans_file = st.file_uploader("Transaction file", type=["csv", "xlsx"])
list_files = st.file_uploader("Email list file(s)", type=["csv", "xlsx"], accept_multiple_files=True)
debug = st.checkbox("Show debug details", value=False)

def read_file(file):
    """Read CSV or Excel into a DataFrame"""
    if file.name.lower().endswith('.csv'):
        return pd.read_csv(file)
    else:
        return pd.read_excel(file)

if trans_file and list_files:
    # Read transactions
    try:
        trans_df = read_file(trans_file)
    except Exception as e:
        st.error(f"Could not read transaction file: {e}")
        st.stop()

    # --- Column selection UI (manual override for robustness) ---
    all_cols = list(trans_df.columns)

    email_guess = [c for c in all_cols if 'email' in c.lower()] or all_cols
    email_col = st.selectbox("Select transaction email column", email_guess, index=0)

    amount_guess = [c for c in all_cols if any(x in c.lower() for x in ['amount','total','charge','price','value'])]
    amount_guess = amount_guess or all_cols
    amount_col = st.selectbox("Select amount column", amount_guess, index=0)

    desc_guess = [c for c in all_cols if any(x in c.lower() for x in ['description','desc','detail','memo','product','item','invoice','service','notes','note'])]
    description_col = st.selectbox(
        "Select description column (for category detection)",
        ['(none)'] + desc_guess if desc_guess else ['(none)'] + all_cols,
        index=1 if desc_guess else 0
    )
    if description_col == '(none)':
        description_col = None

    # Gather emails from list files (robust parsing of any column)
    email_set = set()
    per_file_counts = []
    for lf in list_files:
        try:
            df_list = read_file(lf)
        except Exception as e:
            st.error(f"Could not read list file {lf.name}: {e}")
            st.stop()
        found = extract_emails_from_dataframe(df_list)
        email_set.update(found)
        per_file_counts.append(summarize_email_file(lf.name, found))

    if debug:
        st.caption("Email list ingestion debug")
        st.write(per_file_counts)
        st.write("Total unique emails loaded:", len(email_set))
        # Show a sample
        st.write(list(itertools.islice(email_set, 20)))

    # Normalize transaction emails
    trans_df[email_col] = trans_df[email_col].astype(str).str.strip().str.lower()

    if debug:
        st.caption("Transaction email column sample")
        st.write(trans_df[email_col].head(20).tolist())

    # Filter matches
    matched_df = trans_df[trans_df[email_col].isin(email_set)].copy()

    # Categorize before debug stats if we have a description column
    if description_col:
        matched_df['Category'] = matched_df[description_col].apply(categorize_description)
    else:
        matched_df['Category'] = ""

    if debug:
        st.write("Matched rows:", len(matched_df))
        if description_col:
            st.caption("Sample classification (first 15 descriptions)")
            sample_class = matched_df[[description_col,'Category']].head(15)
            st.write(sample_class)

    if matched_df.empty:
        st.warning("No transactions found for the provided email list(s).")
    else:
        totals = matched_df.groupby(email_col)[amount_col].sum()
        matched_df['TotalForPerson'] = matched_df[email_col].map(totals)

        st.subheader("Totals per person")
        st.write(totals.reset_index().rename(columns={email_col: 'Email', amount_col: 'Total'}))

        st.subheader("Matched transactions")
        st.dataframe(matched_df)

        csv_bytes = matched_df.to_csv(index=False).encode('utf-8')
        if debug:
            st.write("CSV size (bytes):", len(csv_bytes), "Row count (including header):", csv_bytes.count(b'\n'))
        st.download_button(
            label="Download CSV",
            data=csv_bytes,
            file_name="matched_transactions.csv",
            mime="text/csv"
        )

        unmatched_emails = sorted(email_set - set(matched_df[email_col]))
        if unmatched_emails:
            st.info(f"Emails with no transactions: {', '.join(unmatched_emails)}")

else:
    st.info("Please upload a transaction file and at least one email list file.")
