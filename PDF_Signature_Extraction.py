from tkinter import messagebox, filedialog, Tk, StringVar, Label, Button
import os
from datetime import datetime
import PyPDF2
import csv
from PyPDF2 import PdfReader
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs7

# PDF Certificate Extractor
# ------------------------
# A GUI application that extracts digital certificate information from signed PDF files
# and exports the data to CSV format.

# Created by: helpdesk8675

# Features:
# - GUI interface for selecting input/output folders
# - Processes multiple PDF files in batch
# - Extracts digital signature and certificate information
# - Exports certificate data to CSV format
# - Progress tracking and status updates
# - Error handling and user feedback

# Requirements:
# - Python 3.x
# - tkinter
# - PyPDF2
# - cryptography

# Usage:
# 1. Select input folder containing signed PDF files
# 2. Choose output folder for CSV export
# 3. Click "Process Files" to begin extraction
# 4. Results will be saved as 'pdf_signatures_[timestamp].csv'

def browse_input_button():
    global input_folder_path
    filename = filedialog.askdirectory(
        title="Select Input Folder containing PDFs",
        initialdir=os.getcwd()
    )
    if filename:
        input_folder_path.set(filename)

def browse_output_button():
    global output_folder_path
    filename = filedialog.askdirectory(title="Select Output Folder for CSV")
    output_folder_path.set(filename)

def extract_certificate_info(pdf_path):
    """Extract certificate information from PDF signatures."""
    extracted_info = []
    try:
        # Open the PDF file
        reader = PdfReader(pdf_path)
        print(f"Opened PDF: {pdf_path}")
        
        for page_number, page in enumerate(reader.pages, start=1):
            print(f"Checking page {page_number} for annotations...")
            if '/Annots' in page:
                annotations = page['/Annots']
                for annotation_ref in annotations:
                    annotation = annotation_ref.get_object()
                    print(f"Found annotation: {annotation}")
                    
                    # Check if it's a signature widget
                    if annotation.get('/Subtype') == '/Widget' and annotation.get('/FT') == '/Sig':
                        print("Found signature widget.")
                        sig_field = annotation.get('/V')
                        if sig_field:
                            sig_dict = sig_field.get_object()
                            print(f"Signature dictionary: {sig_dict}")

                            # Convert the signature dictionary to a dictionary format for CSV
                            sig_info = {key: str(value) for key, value in sig_dict.items()}
                            extracted_info.append(sig_info)
                        else:
                            print("No signature dictionary found in annotation.")
            else:
                print("No annotations found on this page.")

    except Exception as e:
        print(f"Error extracting certificate info from {pdf_path}: {e}")
    
    return extracted_info


def parse_pkcs7(contents_data):
    """Parse a PKCS#7 signature and extract certificates."""
    try:
        pkcs7_data = pkcs7.load_der_pkcs7_signed_data(contents_data)
        certificates = pkcs7_data.certificates
        if certificates:
            for cert in certificates:
                print(f"Found certificate: {cert.subject.rfc4514_string()}")
                return cert  # Return the first certificate
    except Exception as e:
        print(f"Error parsing PKCS#7 data: {e}")
    return None

# Add progress bar
from tkinter.ttk import Progressbar

def process_files():
    input_dir = input_folder_path.get()
    output_dir = output_folder_path.get()
    
    # Input validation
    if not input_dir or not output_dir:
        messagebox.showerror("Error", "Please select both input and output directories")
        return
    
    if not os.path.exists(input_dir):
        messagebox.showerror("Error", "Input directory does not exist")
        return

    # Add status label for feedback
    status_label = Label(root, text="Processing...")
    status_label.grid(row=3, column=1)
    root.update()

    try:
        # Prepare output CSV file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_path = os.path.join(output_dir, f'pdf_signatures_{timestamp}.csv')

        # Initialize fieldnames set and rows buffer
        fieldnames = set()
        rows = []

        # Process each PDF file in the input directory
        for root_dir, _, files in os.walk(input_dir):
            for file in files:
                if file.lower().endswith('.pdf'):
                    pdf_path = os.path.join(root_dir, file)
                    print(f"Processing: {pdf_path}")

                    # Extract certificate info
                    signatures = extract_certificate_info(pdf_path)

                    for signature in signatures:
                        # Add the PDF filename to the signature data
                        signature['PDF_File'] = file
                        print("Signature to write:", signature)  # Debugging output

                        # Update fieldnames set
                        fieldnames.update(signature.keys())
                        rows.append(signature)

        # Write all rows to the CSV file with updated headers
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sorted(fieldnames))
            writer.writeheader()

            for row in rows:
                # Ensure all rows have the same fields (pad with None for missing fields)
                writer.writerow({key: row.get(key, None) for key in fieldnames})

        print(f"Processing complete. Results saved to: {csv_path}")
        messagebox.showinfo("Success", f"Processing complete. Results saved to: {csv_path}")

    except Exception as e:
        print(f"Error: {str(e)}")  # Debugging output
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        status_label.destroy()





# Create the main window
root = Tk()
root.title("PDF Certificate Extractor")
root.geometry("600x200")  # Set window size to 600x200 pixels

# Create StringVars for folder paths
input_folder_path = StringVar()
output_folder_path = StringVar()

# Create and arrange GUI elements with padding and wider labels
Label(root, text="Input Folder:", font=('Arial', 10)).grid(row=0, column=0, padx=10, pady=20)
Label(root, textvariable=input_folder_path, width=50, anchor='w').grid(row=0, column=1, padx=10)
Button(root, text="Browse Input", width=15, command=browse_input_button).grid(row=0, column=2, padx=10)

Label(root, text="Output Folder:", font=('Arial', 10)).grid(row=1, column=0, padx=10, pady=20)
Label(root, textvariable=output_folder_path, width=50, anchor='w').grid(row=1, column=1, padx=10)
Button(root, text="Browse Output", width=15, command=browse_output_button).grid(row=1, column=2, padx=10)

Button(root, text="Process Files", width=20, height=2, command=process_files).grid(row=2, column=1, pady=20)



root.mainloop()
