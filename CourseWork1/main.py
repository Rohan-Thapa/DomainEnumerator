from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter.filedialog import asksaveasfile
import requests
from bs4 import BeautifulSoup           # If you don't have it, install using `pip install beautifulsoup4`
import socket
import webbrowser
import whois                            # If you don't have it, install using `pip install python-whois`
from cryptography.fernet import Fernet  # If you don't have it, install using `pip install cryptography`
import os
import ssl
import certifi
import nvdlib                           # If you don't have it, install using `pip install nvdlib`


def secretkey_file():
    '''Generate or obtain secrete key and store it in the file for permanent usage'''
    key_file = os.getcwd()+"\enckey.key"
    if os.path.isfile(key_file):
        with open('enckey.key', 'rb') as seckey:
            key = seckey.read()
    else:
        key = Fernet.generate_key()
        with open('enckey.key', 'wb') as seckey:
            seckey.write(key)
    return key


def encrypt_file(data):
    '''Encrypting the output generated and returning the encrypted output'''
    key = secretkey_file()
    fernet = Fernet(key)
    enc_data = fernet.encrypt(data.encode('utf-8'))
    return enc_data


def decrypt_file(data):
    '''Decrypting the encrypted cipher text and returning the plain text.'''
    key = secretkey_file()
    fernet = Fernet(key)
    dec_data = fernet.decrypt(data)
    return dec_data


def check_reg(name):
    '''It is checking whether the given domain name is registered in the `whois` database'''
    try:
        whois.whois(name)
        return True
    except:
        return False


def is_valid(domain):
    '''It is checking whether the given domain is valid and provide IP for the given domain'''
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def web_enum(domain):
    '''It is performing the web enumeration, and producing the result in text-area region'''
    global server
    try:
        response = requests.get(f"http://{domain}")
        soup = BeautifulSoup(response.text, 'html.parser')

        server = response.headers.get('Server')

        info.config(text=f"Status code: {response.status_code}\nServer: {response.headers.get('Server')}")
        text_area.config(state=NORMAL)
        text_area.delete(1.0, END)
        text_area.insert(END, f"{'-'*20} Searching the domain `{domain}` {'-'*20}\n")

        # For the links in the given domain
        text_area.insert(END, "[+] Links present in the domain:\n\n")
        if soup.find_all('a') == []:
            text_area.insert(END, "--> None, there is no link in the webpage code of the domain.\n")
        for link in soup.find_all('a'):
            text_area.insert(END, link.get('href')+"\n")
        a = '-'*80

        # For the SSL Certificate Information
        text_area.insert(END, f"\n\n{a}\n\n[+] SSL Information on the given domain\n\n")
        # context = ssl.create_default_context()   # this is just for testing purpose as a default context creation
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(certifi.where())
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        key_values = []
        for items in cert:
            key_values.append(items)
        for values in key_values:
            text_area.insert(END, f"{values} : {cert[values]}\n")

        # For `whois` database information about the domain
        note = "Note: There might be 'None' given to all the key values if `whois` database is not properly maintained of the given domain."
        text_area.insert(END, f"\n\n{a}\n\n[+] Full Detials of the domain from Whois database:\n({note})\n\n")
        if check_reg(domain):
            domain_info = whois.whois(domain)
            for key, value in domain_info.items():
                text_area.insert(END, f"{key} : {value}\n")
        else:
            text_area.insert(END, "The domain is not registered in `whois` database!\n")
            messagebox.showerror("Error!", "The given domain is not registered in `whois` database!")
        text_area.config(state=DISABLED)
    
    except requests.exceptions.RequestException as e:
        server = ""
        messagebox.showerror("Error!", e)


def scan():
    '''The functionality after clicking the `Scan` button in the window'''
    global default_filename
    domain = domain_name.get()
    default_filename = domain.replace('.', '-')
    if is_valid(domain):
        web_enum(domain)
        text1 = Label(root, text="Open the domain in Browser", cursor="hand2", fg="#66CCFF")
        text1.grid(row=3, column=1)
        text1.bind('<Button-1>', lambda event: webbrowser.open(domain, new=2))
        save_btn.config(state=NORMAL)
        search_entry.config(state=NORMAL)
        search_btn.config(state=NORMAL)
        test_btn.config(state=NORMAL)
        search_entry.delete(0, END)
    else:
        messagebox.showerror("Error!", "The domain given was not a valid domain name.")


def search():
    '''Perform search operation in the obtained output'''
    global search_content
    text_area.tag_remove('found', '1.0', END)
    search_text = search_content.get()   # Grabs the text from the entry box
    if search_text:
        idx = '1.0'
        while 1:
            idx = text_area.search(search_text, idx, nocase=1, stopindex=END)  # using default search method of tkinter
            if not idx: break
            lastidx = '%s+%dc' % (idx, len(search_text))
            text_area.tag_add('found', idx, lastidx)
            idx = lastidx
            text_area.see(idx)  # Once found, the scrollbar automatically scrolls to the text
        text_area.tag_config('found', foreground='red', background='yellow')
    # search_text.focus_set()   # produced an error as AttributeError: 'str' object has no attribute 'focus_set'


def save_data():
    '''Saving the obtained output file as a text file in both encrypted and plain text'''
    save_as = asksaveasfile(initialfile = f'{default_filename}.txt',
            defaultextension=".txt",filetypes=[("All Files","*.*"),("Text Documents","*.txt")])
    if save_as is None:
        return    # if user click `Cancel` button of the dialog box
    contents = encrypt_file(text_area.get(1.0, END)).decode('utf-8')
    save_as.write(contents)
    save_as.close()

    # Converting above encrypted file also in plain text file.
    # this could be done just by obtaining the values in text widget but this is to prove the concept that the encrypted data can be decrypted.
    with open(f'./datas/{default_filename}-plaintext.txt', 'w') as plainfile:
        with open(f'./datas/{default_filename}.txt', 'r') as content:
            datas = content.read()
        data = decrypt_file(datas.encode('utf-8'))
        plainfile.write(str(data.decode('utf-8')))


def search_cve(vendor, product):
    '''Requesting GET Request to the API of CVE and receving the information about the vendor and product'''
    response = requests.get(f"https://cvepremium.circl.lu/api/search/{vendor}/{product}")
    cve_list = []
    if response.status_code == 200:
        cves = response.json()["results"]
        for cve in cves:
            cve_list.append(cve["id"])
    else:
        messagebox.showerror("Error", "There is the invalid Vendor or Product was given in the request.")
    return cve_list


def test():
    '''Getting the domain and providing information about it through Wikipedia search and displaying three lines'''
    testing = Toplevel(root)

    full_domain = default_filename.replace('-', '.')

    testing.title(f"Scanning the server of `{full_domain}`")
    testing.iconbitmap("./img/testing.ico")
    testing.geometry("650x500+650+300")
    testing.resizable(0, 0)

    Label(testing, text=f"Scanning the server of\n`http://{full_domain}`\nas {server}\n").grid(row=0, column=0)

    frame = ttk.Frame(testing, width=60, height=30)
    frame.grid(row=1, column=0, padx=3)

    wiki_info = Text(frame)
    wiki_info.pack(fill=BOTH)
    wiki_info.insert(END, "Remember, this service will only search the vendor/product rather than version."\
        " As the version might be hidden of the service. So verify the CVE through the versions of the product.\n\n")

    try:
        if '/' in server:
            hey = server.split('/')
            vendor = hey[0]
            if vendor == 'nginx':
                product = 'njs'
            # version = hey[1].split(' (')[0]
        else:
            vendor = server
            product = server
        cves = search_cve(vendor, product)
        if cves == []:
            wiki_info.insert(END, "WOW! We couldn't find any CVEs in the server vendor/product."\
                "Either it is GWS or AWS whose CVE are harder to get.\n")
        else:
            for cve in cves:
                cve_result = nvdlib.searchCVE(cveId=cve)[0]
                wiki_info.insert(END, f"[+] Found the CVE id `{cve}` in your vendor/product.\n\n")
                try:
                    severity = cve_result.v31severity
                    score = str(cve_result.v31score)
                    description = cve_result.descriptions[0].value
                    vector = cve_result.v31vector
                except:
                    severity = cve_result.v2severity
                    score = str(cve_result.v2score)
                    description = cve_result.descriptions[0].value
                    vector = cve_result.v2vector
                wiki_info.insert(END, f"Severity: {severity}\nScore: {score}\n")
                wiki_info.insert(END, f"Description of the CVE: {description}\n\n")
                wiki_info.insert(END, f"Vector of the CVE: {vector}\n\n{'-'*80}\n\n")
    except:
        wiki_info.insert(END, "Something went wrong while working with the CVEs of the given product.")
        messagebox.showerror("Oops!", "Seems like something went wrong in the process")

    wiki_info.config(state=DISABLED)

    ttk.Button(testing, text="Quit", command=testing.destroy).grid(row=2, column=0, pady=7)

    testing.mainloop()


if __name__ == '__main__':
    global info, text_area, save_btn, search_entry, search_btn, test_btn
    root = Tk()
    
    root.title("WebEnumeration - A Domain Name Scanner")
    root.iconbitmap("./img/search.ico")
    root.geometry("660x615+400+100")
    root.resizable(0, 0)

    domain_name = StringVar()
    search_content = StringVar()
    domain_name.set("schoolworkspro.com")
    search_content.set("Search here...")
    
    Label(root, text="Welcome to Domain Scanner (Web-Enumeration)", font=('Roboto', 20)).grid(row=0, column=0, columnspan=3, padx=12, pady=10)

    Label(root, text="Enter the domain name").grid(row=1, column=0, pady=12, padx=5)
    domain_entry = ttk.Entry(root, width=40, textvariable=domain_name)
    domain_entry.grid(row=1, column=1, pady=12)
    domain_entry.bind('<Return>', lambda event: scan())

    ttk.Button(root, text="Scan", command=scan).grid(row=2, column=1)

    info = Label(root, text="", fg="green")
    info.grid(row=3, column=0, pady=5)

    labelframe = ttk.LabelFrame(root, text="Result of the Content", width=600, height=300)
    labelframe.grid(row=4, column=0, columnspan=3, padx=5)

    frame = ttk.Frame(root, width=600, height=15)
    frame.grid(row=5, column=0, columnspan=3, padx=5)

    text_area = Text(labelframe, state=DISABLED)
    text_area.pack(fill="both")

    Label(frame, text="What to do with the result?\t->").grid(row=0, column=0, pady=3)
    
    save_btn = ttk.Button(frame, text="Save", command=save_data, state=DISABLED)
    save_btn.grid(row=0, column=1, padx=10, pady=3)
    
    test_btn = ttk.Button(frame, text="ServerScan", command=test, state=DISABLED)
    test_btn.grid(row=0, column=2, padx=10, pady=3)
    
    search_entry = ttk.Entry(frame, width=20, textvariable=search_content, state=DISABLED)
    search_entry.grid(row=0, column=3, padx=10, pady=3)
    search_entry.bind('<Return>', lambda event: search())
    
    search_btn = ttk.Button(frame, text="Search", command=search, state=DISABLED)
    search_btn.grid(row=0, column=4, padx=10, pady=3)
    
    root.mainloop()
