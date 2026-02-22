import streamlit as st
import pandas as pd
import plotly.express as px
from io import BytesIO
import datetime

# 1. Page Configuration
st.set_page_config(page_title="Security Report", layout="wide")

# 2. "Classy" Corporate Styling
st.markdown("""
    <style>
    .stApp { background-color: #F8F9FA; color: #212529; }
    .nav-bar {
        background-color: #87CEEB;
        padding: 15px;
        border-radius: 5px;
        color: white;
        text-align: center;
        margin-bottom: 25px;
    }
    div.stMetric { 
        background-color: #FFFFFF; 
        border-left: 5px solid #1B2631; /* Subtle classy accent */
        border-top: 1px solid #DEE2E6;
        border-right: 1px solid #DEE2E6;
        border-bottom: 1px solid #DEE2E6;
        padding: 20px; 
        border-radius: 4px;
    }
    h1, h2, h3 { color: #1B2631 !important; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }
    .hr-text { border: 0; border-top: 2px solid #1B2631; display: block; margin: 20px 0; }
    </style>
    """, unsafe_allow_html=True)

st.markdown('<div class="nav-bar"><h1>SECURITY INCIDENT DASHBOARD</h1></div>', unsafe_allow_html=True)

# 3. Data Loading
@st.cache_data
def load_data():
    try:
        df = pd.read_csv("dataset2_threat_detection.csv")
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except:
        return None

df = load_data()

if df is not None:
    # --- DYNAMIC HORIZONTAL FILTERS ---
    st.write("### 🔍 Filter Intelligence")
    f1, f2, f3, f4 = st.columns([1, 1, 1, 1.5])
    
    with f1:
        severity_choice = st.multiselect("Severity Level", options=df['severity'].unique(), default=df['severity'].unique())
    with f2:
        system_choice = st.selectbox("Affected System", options=["All Systems"] + list(df['affected_system'].unique()))
    with f3:
        status_choice = st.radio("Resolution", ["All", "Resolved", "Pending"], horizontal=True)
    with f4:
        # DYNAMIC SEARCH BAR
        search_query = st.text_input("Quick Search (IP, Host, or Threat)", placeholder="e.g. 192.168...")

    # --- FILTERING LOGIC ---
    filt_df = df[df['severity'].isin(severity_choice)]
    if system_choice != "All Systems":
        filt_df = filt_df[filt_df['affected_system'] == system_choice]
    if status_choice == "Resolved":
        filt_df = filt_df[filt_df['is_resolved'] == True]
    elif status_choice == "Pending":
        filt_df = filt_df[filt_df['is_resolved'] == False]
    
    # Apply search filter across multiple columns
    if search_query:
        filt_df = filt_df[filt_df.apply(lambda row: search_query.lower() in str(row).lower(), axis=1)]

    st.markdown('<hr class="hr-text">', unsafe_allow_html=True)

    # --- KPI SECTION (With Dynamic Deltas) ---
    k1, k2, k3, k4 = st.columns(4)
    
    # Calculate Dynamic Delta (Current view vs Total Average)
    avg_count = len(df) / len(df['date'].unique()) if len(df['date'].unique()) > 0 else 0
    current_count = len(filt_df)
    
    k1.metric("Selected Events", current_count, delta=f"{current_count - int(avg_count)} vs Avg")
    k2.metric("Critical Points", len(filt_df[filt_df['severity'] == 'Critical']))
    k3.metric("Avg Confidence", f"{filt_df['confidence_score'].mean():.1f}%")
    k4.metric("Avg Mitigation", f"{filt_df['response_time_minutes'].mean():.1f}m")

    # --- DYNAMIC CHARTS ---
    st.write("## 📊 Statistical Analysis")
    c1, c2 = st.columns([1, 1])

    with c1:
        st.write("### Incident Distribution")
        fig_pie = px.pie(filt_df, names='threat_type', hole=0.4,
                         color_discrete_sequence=px.colors.qualitative.Bold)
        fig_pie.update_layout(showlegend=True, legend=dict(orientation="h", y=-0.1))
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        st.write("### Threat Timeline")
        # Dynamic Grouping
        line_data = filt_df.groupby('hour').size().reset_index(name='Volume')
        fig_line = px.area(line_data, x='hour', y='Volume', 
                           color_discrete_sequence=['#1B2631'])
        fig_line.update_layout(xaxis_title="Hour of Day", yaxis_title="Number of Incidents")
        st.plotly_chart(fig_line, use_container_width=True)

    # --- EXPORT & TABLE SECTION ---
    st.write("## 📑 Detailed Audit Log")
    
    # DYNAMIC EXPORT BUTTON
    csv = filt_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Download Filtered Report (CSV)",
        data=csv,
        file_name='security_audit_export.csv',
        mime='text/csv',
    )
    
    # Display table with dynamic coloring
    st.dataframe(filt_df.style.set_properties(**{'background-color': '#ffffff', 'color': '#212529'})
                 .highlight_max(subset=['confidence_score'], color='#D1F2EB'), 
                 use_container_width=True)

    # --- SUMMARY SECTION ---
    st.markdown('<hr class="hr-text">', unsafe_allow_html=True)
    st.write("### 📝 Conclusion & Recommendations")
    
    # Dynamic conclusion text based on data
    if len(filt_df) > 0:
        top_threat = filt_df['threat_type'].value_counts().idxmax()
        st.info(f"**Automated Summary:** The primary threat vector currently identified is **{top_threat}**. We recommend immediate audit of logs associated with this activity.")
    else:
        st.warning("No incidents match the selected filters. System appears clear.")

else:
    st.error("Please ensure 'security_logs.csv' is in the current directory.")

# Get the current year automatically
current_year = datetime.date.today().year

# Footer with dynamic year
st.markdown(f"""
    <center>
        <small>Prepared by: Kameni Jessica | Masters of Technology | {current_year}</small>
    </center>
    """, unsafe_allow_html=True)