import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import csv
from datetime import datetime
import sys
from asn1crypto import cms
from dateutil.parser import parse
from pypdf import PdfReader

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

# Usage:
# 1. Select input folder containing signed PDF files
# 2. Choose output folder and file name for the CSV output.
# 3. Click "Process Files" to begin extraction
class AttrClass:
    """Abstract helper class"""
    def __init__(self, data, cls_name=None):
        self._data = data
        self._cls_name = cls_name

    def __getattr__(self, name):
        try:
            value = self._data[name]
        except KeyError:
            value = None
        else:
            if isinstance(value, dict):
                return AttrClass(value, cls_name=name.capitalize() or self._cls_name)
        return value

    def __values_for_str__(self):
        return [
            (k, v) for k, v in self._data.items()
            if isinstance(v, (str, int, datetime))  # Fixed datetime reference
        ]

    def __str__(self):
        values = ", ".join([
            f"{k}={v}" for k, v in self.__values_for_str__()
        ])
        return f"{self._cls_name or self.__class__.__name__}({values})"

    def __repr__(self):
        return f"<{self}>"

class Signature(AttrClass):
    @property
    def signer_name(self):
        return (
            self._data.get('signer_name') or
            getattr(self.certificate.subject, 'common_name', '')
        )

class Subject(AttrClass):
    pass

class Certificate(AttrClass):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subject = Subject(self._data['subject'])

    def __values_for_str__(self):
        return (
            super().__values_for_str__() +
            [('common_name', self.subject.common_name)]
        )

def parse_pkcs7_signatures(signature_data: bytes):
    try:
        content_info = cms.ContentInfo.load(signature_data).native
        if content_info['content_type'] != 'signed_data':
            return []  # Return empty list instead of None
        content = content_info['content']
        certificates = content['certificates']
        signer_infos = content['signer_infos']
        
        for signer_info in signer_infos:
            try:
                sid = signer_info['sid']
                digest_algorithm = signer_info['digest_algorithm']['algorithm']
                signature_algorithm = signer_info['signature_algorithm']['algorithm']
                signature_bytes = signer_info['signature']
                
                # Handle potential missing signed_attrs
                signed_attrs = {}
                if 'signed_attrs' in signer_info:
                    signed_attrs = {
                        sa['type']: sa['values'][0] 
                        for sa in signer_info['signed_attrs']
                        if 'type' in sa and 'values' in sa and sa['values']
                    }
                
                # Find matching certificate
                matching_cert = None
                for cert in certificates:
                    cert = cert['tbs_certificate']
                    if (
                        sid['serial_number'] == cert['serial_number'] and
                        sid['issuer'] == cert['issuer']
                    ):
                        matching_cert = cert
                        break
                
                if matching_cert is None:
                    continue  # Skip this signature if no matching certificate found
                
                yield dict(
                    sid=sid,
                    certificate=Certificate(matching_cert),
                    digest_algorithm=digest_algorithm,
                    signature_algorithm=signature_algorithm,
                    signature_bytes=signature_bytes,
                    signer_info=signer_info,
                    **signed_attrs,
                )
            except (KeyError, TypeError, ValueError) as e:
                continue  # Skip problematic signatures
    except Exception as e:
        return []  # Return empty list on any parsing error

def get_pdf_signatures(filename):
    try:
        reader = PdfReader(filename)
        fields = reader.get_fields()
        
        if fields is None:  # Handle PDFs without form fields
            return []
        
        signature_field_values = []
        for field in fields.values():
            try:
                if field is not None and hasattr(field, 'field_type') and field.field_type == '/Sig':
                    if hasattr(field, 'value') and field.value is not None:
                        signature_field_values.append(field.value)
            except AttributeError:
                continue
        
        for v in signature_field_values:
            try:
                if '/Type' not in v:
                    continue
                    
                v_type = v['/Type']
                if v_type not in ('/Sig', '/DocTimeStamp'):
                    continue
                
                is_timestamp = v_type == '/DocTimeStamp'
                
                # Handle signing time
                signing_time = None
                try:
                    if '/M' in v:
                        time_str = v['/M'][2:].strip("'").replace("'", ":")
                        signing_time = parse(time_str)
                except (ValueError, TypeError):
                    pass
                
                if '/Contents' not in v:
                    continue
                    
                raw_signature_data = v['/Contents']
                
                for attrdict in parse_pkcs7_signatures(raw_signature_data):
                    if attrdict:
                        try:
                            attrdict.update(dict(
                                type='timestamp' if is_timestamp else 'signature',
                                signer_name=v.get('/Name'),
                                signer_contact_info=v.get('/ContactInfo'),
                                signer_location=v.get('/Location'),
                                signing_time=signing_time or attrdict.get('signing_time'),
                                signature_type=v.get('/SubFilter', [''])[1:],
                                signature_handler=v.get('/Filter', [''])[1:],
                                raw=raw_signature_data,
                            ))
                            yield Signature(attrdict)
                        except (KeyError, TypeError, ValueError):
                            continue
            except (KeyError, TypeError, ValueError):
                continue
    except Exception as e:
        return []

class SignatureExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Signature Extractor")
        self.root.geometry("800x700")  # Increased height for additional progress bar
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input folder selection
        ttk.Label(main_frame, text="Input Folder:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_path, width=60).grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_input).grid(row=0, column=2)
        
        # Output file selection
        ttk.Label(main_frame, text="Output File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_path, width=60).grid(row=1, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=1, column=2)
        
        # Overall progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="5")
        progress_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Overall progress
        ttk.Label(progress_frame, text="Overall Progress:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.overall_progress_var = tk.DoubleVar()
        self.overall_progress = ttk.Progressbar(
            progress_frame, 
            length=300, 
            variable=self.overall_progress_var, 
            mode='determinate'
        )
        self.overall_progress.grid(row=0, column=1, padx=5)
        self.overall_progress_label = ttk.Label(progress_frame, text="0%")
        self.overall_progress_label.grid(row=0, column=2, padx=5)
        
        # Current file progress
        ttk.Label(progress_frame, text="Current File:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.file_progress_var = tk.DoubleVar()
        self.file_progress = ttk.Progressbar(
            progress_frame, 
            length=300, 
            variable=self.file_progress_var, 
            mode='determinate'
        )
        self.file_progress.grid(row=1, column=1, padx=5)
        self.file_progress_label = ttk.Label(progress_frame, text="0%")
        self.file_progress_label.grid(row=1, column=2, padx=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(progress_frame, textvariable=self.status_var, wraplength=400)
        self.status_label.grid(row=2, column=0, columnspan=3, pady=5)
        
        # Process button
        ttk.Button(main_frame, text="Process PDFs", command=self.process_pdfs).grid(
            row=3, column=0, columnspan=3, pady=10)
        
        # Results text area with label
        ttk.Label(main_frame, text="Processing Log:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.results_text = tk.Text(main_frame, height=20, width=80)
        self.results_text.grid(row=5, column=0, columnspan=3, pady=5)
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        scrollbar.grid(row=5, column=3, sticky=(tk.N, tk.S))
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        progress_frame.columnconfigure(1, weight=1)

    def update_progress(self, file_progress, overall_progress):
        self.file_progress_var.set(file_progress)
        self.overall_progress_var.set(overall_progress)
        self.file_progress_label.config(text=f"{file_progress:.1f}%")
        self.overall_progress_label.config(text=f"{overall_progress:.1f}%")
        self.root.update_idletasks()

    def browse_input(self):
        folder = filedialog.askdirectory()
        if folder:
            self.input_path.set(folder)

    def browse_output(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file:
            self.output_path.set(file)

    def process_pdfs(self):
        input_folder = self.input_path.get()
        output_file = self.output_path.get()
        
        if not input_folder or not output_file:
            messagebox.showerror("Error", "Please select both input folder and output file")
            return
        
        try:
            # Reset progress bars
            self.update_progress(0, 0)
            self.results_text.delete(1.0, tk.END)
            
            # Get list of all PDF files
            pdf_files = []
            self.status_var.set("Scanning for PDF files...")
            for root, _, files in os.walk(input_folder):
                for file in files:
                    if file.lower().endswith('.pdf'):
                        pdf_files.append(os.path.join(root, file))
            
            if not pdf_files:
                messagebox.showwarning("Warning", "No PDF files found in the selected folder")
                self.status_var.set("No PDF files found")
                return
            
            # Process PDFs and write to CSV
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["File", "Type", "Signature", "Signer", "Signing Time",
                               "Certificate", "Not Before", "Not After",
                               "Issuer", "Subject", "Common Name", "Serial Number"])
                
                total_files = len(pdf_files)
                for i, pdf_file in enumerate(pdf_files, 1):
                    try:
                        file_name = os.path.basename(pdf_file)
                        self.status_var.set(f"Processing: {file_name}")
                        
                        # Update overall progress
                        overall_progress = (i - 1) / total_files * 100
                        self.update_progress(0, overall_progress)
                        
                        # Process signatures
                        signatures = list(get_pdf_signatures(pdf_file))
                        total_signatures = len(signatures) or 1
                        
                        for sig_idx, signature in enumerate(signatures):
                            # Update file progress
                            file_progress = (sig_idx + 1) / total_signatures * 100
                            self.update_progress(file_progress, overall_progress)
                            
                            certificate = signature.certificate
                            subject = certificate.subject
                            writer.writerow([
                                pdf_file,
                                signature.type,
                                signature,
                                signature.signer_name,
                                signature.signing_time,
                                certificate,
                                certificate.validity.not_before,
                                certificate.validity.not_after,
                                certificate.issuer,
                                subject,
                                subject.common_name,
                                subject.serial_number,
                            ])
                            
                            # Update results text
                            self.results_text.insert(tk.END, 
                                f"Processed: {file_name} - Found signature from {signature.signer_name}\n")
                            self.results_text.see(tk.END)
                        
                        if not signatures:
                            self.results_text.insert(tk.END, 
                                f"Processed: {file_name} - No signatures found\n")
                            self.results_text.see(tk.END)
                            
                    except Exception as e:
                        self.results_text.insert(tk.END, 
                            f"Error processing {file_name}: {str(e)}\n")
                        self.results_text.see(tk.END)
            
            # Update final progress
            self.update_progress(100, 100)
            self.status_var.set("Processing complete!")
            messagebox.showinfo("Success", "PDF processing completed successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error occurred during processing")
        
        finally:
            # Ensure progress bars are either full or reset
            if self.status_var.get() == "Processing complete!":
                self.update_progress(100, 100)
            else:
                self.update_progress(0, 0)


if __name__ == "__main__":
    root = tk.Tk()
    app = SignatureExtractorGUI(root)
    root.mainloop()
