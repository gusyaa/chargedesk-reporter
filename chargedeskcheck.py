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

def categorize_description(text: str) -> str:
    """
    Return comma-separated list of categories whose keyword substrings appear in the description.
    If none match, return empty string.
    """
    if not isinstance(text, str):
        return ""
    desc = text.strip().lower()
    if not desc:
        return ""
    hits = []
    for cat, kw_list in LOWER_KEYWORDS.items():
        for kw in kw_list:
            if kw in desc:
                hits.append(cat)
                break  # avoid duplicate category if multiple keywords match
    # If multiple categories detected (e.g. 'tax return review'), include all unique
    return ", ".join(sorted(set(hits)))

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

    # Guess email column
    email_cols = [c for c in trans_df.columns if 'email' in c.lower()]
    if not email_cols:
        st.error("No column containing 'email' found in transaction file.")
        st.stop()
    email_col = email_cols[0]

    # Guess amount column
    amount_cols = [c for c in trans_df.columns if 'amount' in c.lower() or 'total' in c.lower()]
    if not amount_cols:
        st.error("No column containing 'amount' or 'total' found in transaction file.")
        st.stop()
    amount_col = amount_cols[0]

    # Guess description column (for categorization). Try likely names.
    desc_candidate_cols = [c for c in trans_df.columns if any(tok in c.lower() for tok in ["description", "desc", "detail", "memo", "product", "item", "invoice", "service"])]
    description_col = None
    if desc_candidate_cols:
        # If multiple, let user pick
        if len(desc_candidate_cols) > 1:
            description_col = st.selectbox("Select description column for categorization", desc_candidate_cols, index=0)
        else:
            description_col = desc_candidate_cols[0]
    else:
        st.info("No description-like column detected. Category column will be blank.")

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

    if debug:
        st.write("Matched rows:", len(matched_df))

    if matched_df.empty:
        st.warning("No transactions found for the provided email list(s).")
    else:
        # Add category column based on description if available
        if 'description_col' in locals() and description_col:
            matched_df['Category'] = matched_df[description_col].apply(categorize_description)
        else:
            matched_df['Category'] = ""

        totals = matched_df.groupby(email_col)[amount_col].sum()
        matched_df['TotalForPerson'] = matched_df[email_col].map(totals)

        st.subheader("Totals per person")
        st.write(totals.reset_index().rename(columns={email_col: 'Email', amount_col: 'Total'}))

        st.subheader("Matched transactions")
        st.dataframe(matched_df)

        csv_bytes = matched_df.to_csv(index=False).encode('utf-8')
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
