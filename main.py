import streamlit as st
from datetime import datetime

# Import detection functions
from detector import scan_text

# Import masking functions
from masker import (
    mask_sensitive_data,
    mask_email,
    mask_phone,
    mask_aadhaar,
    mask_pan,
    mask_password
)


# ============================================
#              LEAKLOCK APPLICATION
# ============================================

st.set_page_config(
    page_title="LeakLock - Data Protection",
    page_icon="🔐",
    layout="wide"
)


# ============================================
#                    HEADER
# ============================================

st.title("🔐 LEAKLOCK")

st.subheader("Detect. Protect. Prevent Leaks.")

st.write(
    "Sensitive Information Detection "
    "and Data Protection System"
)

st.divider()


# ============================================
#                SESSION VARIABLES
# ============================================

if "results" not in st.session_state:
    st.session_state.results = None

if "protected_text" not in st.session_state:
    st.session_state.protected_text = ""

if "report_text" not in st.session_state:
    st.session_state.report_text = ""

if "scanned_file" not in st.session_state:
    st.session_state.scanned_file = "Manual Text Input"


# ============================================
#                     SIDEBAR
# ============================================

st.sidebar.title("LEAKLOCK MENU")

st.sidebar.write("Available Features")

st.sidebar.markdown("""
- Email Detection
- Phone Detection
- Aadhaar Detection
- PAN Detection
- Password Detection
- Individual Masking
- Automatic Text Masking
- File Scanning
- Security Report Generation
""")


# ============================================
#                APPLICATION TABS
# ============================================

tab1, tab2 = st.tabs([
    "🔍 Scan & Protect",
    "🛡️ Individual Masking"
])


# ============================================
# TAB 1: SCANNING AND PROTECTION
# ============================================

with tab1:

    st.header("Sensitive Information Scanner")

    st.write(
        "Enter text manually or upload a TXT file "
        "to find sensitive information."
    )


    # ========================================
    # FILE UPLOAD
    # ========================================

    uploaded_file = st.file_uploader(
        "Upload a Text File",
        type=["txt"]
    )

    uploaded_text = None

    if uploaded_file is not None:

        try:

            uploaded_text = uploaded_file.getvalue().decode("utf-8")

            st.success("File uploaded successfully!")

        except UnicodeDecodeError:

            st.error(
                "Unable to read this file. "
                "Please upload a UTF-8 text file."
            )


    # ========================================
    # TEXT INPUT
    # ========================================

    if uploaded_text is not None:
        default_text = uploaded_text

    else:
        default_text = ""

    input_text = st.text_area(
        "Enter Text to Scan",
        value=default_text,
        height=200,
        placeholder="Enter your sample information here..."
    )


    # ========================================
    # SCAN AND MASK BUTTON
    # ========================================

    if st.button("🔍 SCAN & MASK", use_container_width=True):

        if not input_text.strip():

            st.warning("Please enter text or upload a file.")

        else:

            # Find sensitive information
            results = scan_text(input_text)

            # Hide the detected sensitive information
            protected_text = mask_sensitive_data(input_text)

            # Save the results
            st.session_state.results = results

            st.session_state.protected_text = protected_text

            st.session_state.report_text = ""

            if uploaded_file is not None:
                st.session_state.scanned_file = uploaded_file.name

            else:
                st.session_state.scanned_file = "Manual Text Input"

            st.success("Scanning completed successfully!")


    # ========================================
    # DISPLAY SCAN RESULTS
    # ========================================

    if st.session_state.results is not None:

        results = st.session_state.results

        st.divider()

        st.subheader("📊 Detection Results")

        # Count all detected information
        total = sum(len(data) for data in results.values())

        categories_found = sum(
            1 for data in results.values() if data
        )

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Detected", total)

        col2.metric("Categories Found", categories_found)

        col3.metric(
            "Security Status",
            "Risk Found" if total > 0 else "No Matches"
        )


        # ====================================
        # CATEGORY-WISE RESULTS
        # ====================================

        st.markdown("### Category-wise Detection")

        columns = st.columns(5)

        for index, (category, data) in enumerate(results.items()):

            columns[index].metric(
                category,
                len(data)
            )


        # ====================================
        # SECURITY STATUS
        # ====================================

        if total > 0:

            st.error("⚠️ Sensitive Information Found!")

        else:

            st.success("✅ No Matching Sensitive Information Found.")


        # ====================================
        # AUTOMATIC MASKING OUTPUT
        # ====================================

        st.divider()

        st.subheader("🛡️ Automatically Masked Text")

        st.code(
            st.session_state.protected_text,
            language="text"
        )


        # ====================================
        # DOWNLOAD PROTECTED FILE
        # ====================================

        st.download_button(
            label="⬇️ Download Protected File",
            data=st.session_state.protected_text,
            file_name="protected_output.txt",
            mime="text/plain",
            use_container_width=True
        )


        # ====================================
        # GENERATE SECURITY REPORT
        # ====================================

        if st.button("📄 GENERATE SECURITY REPORT", use_container_width=True):

            report = []

            report.append("========== LEAKLOCK SECURITY REPORT ==========")

            report.append("Project Name: LEAKLOCK")

            report.append(
                "Purpose: Sensitive Information Detection and Data Protection"
            )

            report.append(
                "Date and Time: "
                + datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            )

            report.append(
                "Scanned File: " + st.session_state.scanned_file
            )

            report.append("\n========== DETECTION RESULTS ==========\n")

            for category, data in results.items():

                report.append(
                    f"{category}: {len(data)} detected"
                )

            report.append("\n========== FINAL SECURITY RESULT ==========")

            report.append(f"Total Sensitive Information: {total}")

            if total > 0:

                report.append("Security Status: SENSITIVE DATA FOUND")

            else:

                report.append("Security Status: NO MATCHING DATA FOUND")

            report.append(
                "\nOriginal sensitive values are not included in this report."
            )

            report.append("\n========== END OF REPORT ==========")

            # Convert the report into text
            st.session_state.report_text = "\n".join(report)

            st.success("Security report generated successfully!")


        # ====================================
        # DOWNLOAD SECURITY REPORT
        # ====================================

        if st.session_state.report_text:

            st.download_button(
                label="⬇️ Download Security Report",
                data=st.session_state.report_text,
                file_name="report.txt",
                mime="text/plain",
                use_container_width=True
            )


# ============================================
# TAB 2: INDIVIDUAL MASKING
# ============================================

with tab2:

    st.header("Individual Data Masking")

    st.write(
        "Choose an information type and enter a value "
        "to mask it individually."
    )


    # ========================================
    # SELECT INFORMATION TYPE
    # ========================================

    category = st.selectbox(
        "Select Information Type",
        [
            "Email",
            "Phone",
            "Aadhaar",
            "PAN",
            "Password"
        ]
    )


    # ========================================
    # ENTER VALUE
    # ========================================

    value = st.text_input(
        "Enter Value to Mask",
        type="password" if category == "Password" else "default"
    )


    # ========================================
    # MASK INDIVIDUAL DATA
    # ========================================

    if st.button("🛡️ MASK INDIVIDUAL DATA", use_container_width=True):

        if not value.strip():

            st.warning("Please enter a value.")

        else:

            try:

                if category == "Email":

                    masked_value = mask_email(value)

                elif category == "Phone":

                    masked_value = mask_phone(value)

                elif category == "Aadhaar":

                    masked_value = mask_aadhaar(value)

                elif category == "PAN":

                    masked_value = mask_pan(value)

                elif category == "Password":

                    masked_value = mask_password(value)

                st.success("Data masked successfully!")

                st.write("### Protected Result")

                st.code(masked_value)

            except ValueError:

                st.error(
                    "Invalid format. Please check your input."
                )


# ============================================
#                    FOOTER
# ============================================

st.divider()

st.caption(
    "LEAKLOCK | Sensitive Information Detection & Data Protection System"
)

st.caption(
    "Developed using Python and Streamlit."
)
