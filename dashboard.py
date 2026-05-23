import streamlit as st
import pandas as pd
import plotly.express as px
import os
import re
import time

# ==========================================
# CONFIGURATION & PATHS
# ==========================================
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "alerts.log")

st.set_page_config(
    page_title="Project Cerberus | Mission Control",
    page_icon="🐺",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# PREMIUM CYBER THEME (CSS)
# ==========================================
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; color: #e0e0e0; }
    [data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace; color: #00d4ff !important; }
    [data-testid="stMetricLabel"] { font-size: 1.1rem; font-weight: bold; color: #8b949e; }
    div.stMetric { background-color: #161b22; border-radius: 10px; padding: 15px; border: 1px solid #30363d; }
    .stDataFrame { border: 1px solid #30363d; border-radius: 5px; }
    </style>
    """, unsafe_allow_html=True)

# ==========================================
# ADVANCED LOG PARSER
# ==========================================
def parse_logs():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()
    
    try:
        with open(LOG_FILE, "r") as f:
            content = f.read()
    except Exception as e:
        st.error(f"Error reading log file: {e}")
        return pd.DataFrame()
    
    entries = content.split("-----------------------------------------")
    log_data = []
    
    for entry in entries:
        if not entry.strip():
            continue
        
        try:
            # 1. Standard Fields Extraction
            timestamp_match = re.search(r"\[(.*?)\]", entry)
            user_match      = re.search(r"User\s+:\s+(.*)", entry)
            action_match    = re.search(r"Action\s+:\s+(.*)", entry)
            file_match      = re.search(r"File\s+:\s+(.*)", entry)
            severity_match  = re.search(r"Severity\s+:\s+(.*)", entry)
            score_match     = re.search(r"Risk Score:\s+(\d+)", entry)
            
            # 2. IP Extraction (Matches 'from X' inside 'Remote Details')
            ip_match = re.search(r"Remote Details:.*?(?:from\s+IP:|from|Devices:)\s+([a-fA-F0-9.:]+)", entry)
            ip_addr = ip_match.group(1).strip() if ip_match else "Local"
            
            # If all standard fields exist, append to data
            if all([timestamp_match, user_match, action_match, file_match, severity_match, score_match]):
                log_data.append({
                    "Timestamp": pd.to_datetime(timestamp_match.group(1)),
                    "User": user_match.group(1).strip(),
                    "Action": action_match.group(1).strip(),
                    "Target File": file_match.group(1).strip(),
                    "Source IP": ip_addr,
                    "Severity": severity_match.group(1).strip(),
                    "Risk Score": int(score_match.group(1))
                })
        except Exception:
            continue
            
    return pd.DataFrame(log_data)

# ==========================================
# DASHBOARD UI COMPONENTS
# ==========================================
def main():
    colA, colB = st.columns([1, 15])
    with colA:
        logo_path = os.path.join(os.path.dirname(__file__), "cerberus_logo.png")
        if os.path.exists(logo_path):
            st.image(logo_path, width=60)
    with colB:
        st.title("Project Cerberus : Mission Control")
    st.markdown(f"**Target System:** `LOCALHOST` | **Log Source:** `{LOG_FILE}`")
    
    df = parse_logs()

    if df.empty:
        st.warning("📡 No logs detected in alerts.log. Trigger some honeyfile activity!")
        if st.button("Manual Refresh"):
            st.rerun()
        return

    # --- TOP ROW: KPI METRICS ---
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Hits", len(df))
    with m2:
        criticals = len(df[df['Severity'] == 'CRITICAL'])
        st.metric("Critical Alerts", criticals, delta=f"{criticals} High Risk", delta_color="inverse")
    with m3:
        unique_ips = df[df['Source IP'] != 'Local']['Source IP'].nunique()
        st.metric("Remote Attackers", unique_ips)
    with m4:
        active_files = df['Target File'].nunique()
        st.metric("Breached Files", active_files)

    st.markdown("---")

    # --- MIDDLE ROW: ANALYTICS ---
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        st.subheader("🔥 Threat Timeline")
        fig_line = px.scatter(df, x="Timestamp", y="Risk Score", color="Severity",
                            size="Risk Score", hover_data=["Action", "Source IP", "Target File"],
                            template="plotly_dark",
                            color_discrete_map={'CRITICAL': '#ff4b4b', 'HIGH': '#ffa500', 'LOW': '#00d4ff'})
        fig_line.update_traces(mode='lines+markers')
        st.plotly_chart(fig_line, use_container_width=True)

    with col2:
        st.subheader("🌐 Top Sources")
        ip_counts = df[df['Source IP'] != 'Local']['Source IP'].value_counts().reset_index()
        if not ip_counts.empty:
            fig_bar = px.bar(ip_counts, x='count', y='Source IP', orientation='h', 
                             template="plotly_dark", color_discrete_sequence=['#00d4ff'])
            fig_bar.update_layout(yaxis_title=None, xaxis_title="Hits")
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No remote SMB activity.")

    with col3:
        st.subheader("📁 Targeted Files")
        file_counts = df['Target File'].value_counts().reset_index()
        if not file_counts.empty:
            fig_pie = px.pie(file_counts, values='count', names='Target File', hole=0.4, 
                             template="plotly_dark", color_discrete_sequence=px.colors.qualitative.Set2)
            fig_pie.update_layout(showlegend=False)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No files targeted yet.")

    # --- BOTTOM ROW: LIVE DATA TABLE ---
    st.subheader("📜 Forensic Log Explorer")
    
    # Filters
    f1, f2 = st.columns(2)
    with f1:
        severity_filter = st.multiselect("Filter Severity:", ["CRITICAL", "HIGH", "LOW"], default=["CRITICAL", "HIGH", "LOW"])
    with f2:
        file_filter = st.multiselect("Filter File:", df['Target File'].unique(), default=df['Target File'].unique())
    
    # Apply filters and sort
    filtered_df = df[(df['Severity'].isin(severity_filter)) & (df['Target File'].isin(file_filter))]
    display_df = filtered_df.sort_values(by="Timestamp", ascending=False)
    
    # Reorder columns for readability
    display_df = display_df[['Timestamp', 'Severity', 'Target File', 'Action', 'Source IP', 'User', 'Risk Score']]

    # Render table
    st.dataframe(
        display_df.style.map(
            lambda x: 'color: #ff4b4b; font-weight: bold' if x == 'CRITICAL' else 
                      'color: #ffa500' if x == 'HIGH' else '', 
            subset=['Severity']
        ),
        use_container_width=True,
        height=450
    )

    # --- AUTO-REFRESH ---
    time.sleep(5)
    st.rerun()

if __name__ == "__main__":
    main()