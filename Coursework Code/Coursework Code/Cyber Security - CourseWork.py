from tkinter import Tk     
from tkinter.filedialog import askopenfilename
import re
import time

class PCAP:
    def __init__(self):
        # Dictionary to store extracted information
        self.dictionary = {}

        # Lists containing packet capture attributes for display
        self.list1 = ['Global Header', 'Magic Number', 'Endianness', 'Major Version', 'Minor Version', 'Snap Length', 'Data Link']
        self.list2 = ['Capture Time (seconds)', 'Capture Time (GMT)', 'Frame Length', 'Destination MAC Address', 'Source MAC Address', 'Source IP Address', 'Destination IP Address', 'Hostname', 'Port Number']
        
        # Start main function
        self.Main()
         
    def Extracting(self, filename):
        """Extract relevant data from the PCAP file."""

        #Opening the selected file in read-only within the binary format
        openf = open(filename, "rb")

        # Read the global header (first 24 bytes of the PCAP file)
        global_header = openf.read(24)
        
        # Extract the magic number (first 4 bytes) to determine endianness
        magic_number = global_header[0:4]
        
        # Determine the byte order (endianness) based on magic number
        if magic_number == b'\xd4\xc3\xb2\xa1':
            endianness = 'little'
        elif magic_number == b'\xa1\xb2\xc3\xd4':
            endianness = 'big'
        else:
            print('The magic number is invalid')
        
        # Read packet header (16 bytes) and packet data
        data1 = openf.read(16)
        data2 = openf.read(int.from_bytes(data1[8:12],byteorder=endianness))

        # Extract relevant fields from the packet header
        capTime = int.from_bytes(data1[0:4], byteorder=endianness) # Capture timestamp
        fcapTime = time.gmtime(capTime) # Convert timestamp to GMT
        lenFrame = int.from_bytes(data1[8:12], byteorder=endianness) # Frame length

        # Extract MAC and IP addresses from packet data
        dMAC = data2[0:6]
        sMAC = data2[6:12]
        dIP = data2[30:34]
        sIP = data2[26:30]
        
        # Extract hostname if available
        hostname_block = data2[35:]
        sample = hostname_block.decode("utf-8",errors="ignore")
        # Searches for any strings matching the hostname syntax
        mypattern=re.compile(r"[A-Za-z0-9-]+")
        hostname = mypattern.findall(sample)
        hostname1 = hostname[len(hostname)-1]

        # Extract port number
        port = openf.read(int.from_bytes(data1[8:12],byteorder=endianness))[23]
        
        #Close the file for efficient file management hygiene
        openf.close()
        # Store extracted global header information
        self.task1 = {
            'Global Header': global_header,
            'Magic Number': magic_number.hex(),
            'Endianness': endianness,
            'Major Version': int.from_bytes(global_header[4:6],endianness),
            'Minor Version': int.from_bytes(global_header[6:8],endianness),
            'Snap Length': int.from_bytes(global_header[16:20],endianness),
            'Data Link': int.from_bytes(global_header[20:24],endianness)
        }
        
        # Store extracted packet details
        self.task2 = {
            'Capture Time (seconds)': capTime,
            "Capture Time (GMT)": time.strftime("%Y-%m-%d %H:%M:%S", fcapTime),
            "Frame Length":lenFrame,
            "Destination MAC Address":":".join(f"{byte:02X}" for byte in dMAC),
            "Source MAC Address":":".join(f"{byte:02X}" for byte in sMAC),
            "Source IP Address":".".join(f"{byte:0}"for byte in sIP),
            "Destination IP Address":".".join(f"{byte:0}"for byte in dIP),
            "Hostname":hostname1,
            "Port Number":port
        }
        

    def Display(self):
        """Display the extracted PCAP information."""
        print("-------------------------------")
        print("             Task 1            ")
        print("-------------------------------")

        for self.list1 in self.list1:
            print(self.list1, ': ', self.task1[self.list1])

        print("-------------------------------")
        print("             Task 2            ")
        print("-------------------------------")

        for self.list2 in self.list2:
            print(self.list2, ': ', self.task2[self.list2])
    
    def FindTop(self, filename):
        # Create a pattern to search for the "Host" section (where domains used will be listed)
        mypattern=re.compile(r"Host:[\w\.\s]*\.top")

        # Open the file in binary read mode
        openf = open(filename,"rb")
        # Read the first 24 bytes (global header)
        data = openf.read(24)
        while True:
        # Read the next 16 bytes (packet header)
            data1 = openf.read(16)
            if len(data1) < 16:
                break
            # Determine the included length of the frame
            incl_len = int.from_bytes(data1[8:12],byteorder="little")
            # Read the frame data
            data2 = openf.read(incl_len)
            if len(data2) < incl_len:
                break
            # Decode packet data to extract text information
            sample = data2.decode("utf-8",errors="ignore")
            found = mypattern.findall(sample)
            # If a domain is found, print it and exit the loop
            if found != []:
                print("-------------------------------")
                print("             Task 3            ")
                print("-------------------------------")
                # Prints out the domain name that ends with the extension of ".top"
                print(found[0])
                break
            else:
                continue
    
    def Domains(self,filename):
        """Identify potentially harmful domains from the PCAP file."""

        # List to store all found domains
        all = []
        # List to store safe domains
        safe =[]

        # Regular expression to find hostnames in the PCAP file
        mypattern=re.compile(r"Host:\s*([a-zA-Z0-9.-]+)")
        # Open the PCAP file in binary read mode
        openf = open(filename,"rb")
        # Open the file containing the top 1 million visited websites
        open2 = open(r".\top-1m.csv","r")

        # Creats infitie loop
        openf.read(24)
        while True:
            data1 = openf.read(16)
            if len(data1) < 16:
                break
            # Get the included length of the frame
            incl_len = int.from_bytes(data1[8:12],byteorder="little")
            # Read the packet data
            data2 = openf.read(incl_len)
            if len(data2) < incl_len:
                break
            # Decode the packet data
            sample = data2.decode("utf-8",errors="ignore")
            found = mypattern.findall(sample)
            # If not already assigned into a safety category, each visited host should.
            if found != []:
                for domain in found:
                    if domain not in all:
                        all.append(domain)
                        print("Checking websites... ["+str(len(all))+"]")
                    # Check if the domain is among the top 1 million visited sites
                    open2.seek(0)
                    for name in open2:
                        if len(domain.split(".")) > 2:
                            formatted = ".".join(domain.split(".")[-2:])
                        if formatted in name:
                            if domain not in safe:
                                safe.append(domain)
                            break
            else:
                continue
        # Remove safe domains from the list of all found domains
        for object in safe:
            all.remove(object)
        print("Potentially harmfull visited websites:",)
        if len(all) > 0:
            for item in all:
                print(item)
        else:
            print("No harmful websites detected")


    def SearchEngine(self, filename):
        '''Extract search engine queries from the PCAP file.'''
        # Pattern to search for Referer field containing URLs
        mypattern = re.compile(r"Referer:\s*(https?://[^\r\n]+)")
        # Open the PCAP file in binary mode
        openf = open(filename,"rb")

        # Open the list of search engines
        open2 = open(r".\SearchEngines.txt","r")
        search_pattern = [line.strip().lower() for line in open2]
        # Compile a regex pattern for detecting search engine queries
        search_pattern = re.compile(r"https?://(?:www\.)?(?:"+"|".join(search_pattern)+r")\.[/a-zA-Z0-9.-]+/.+")
        openf.read(24)
        while True:
            # Read next packet header (16 bytes)
            data1 = openf.read(16)
            if len(data1) < 16:
                break
            # Determine the length of the packet
            incl_len = int.from_bytes(data1[8:12],byteorder="little")
            # Read the packet data
            data2 = openf.read(incl_len)
            if len(data2) < incl_len:
                break
            
            # Decode packet data
            sample = data2.decode("utf-8",errors="ignore")
            found = mypattern.findall(sample)

            # If a search engine referer URL is found
            if found != []:
                for finding in found:
                    specific = search_pattern.findall(finding)
                    try:
                        # Extract the search engine domain
                        engine_find = re.compile(r"https?://(?:www\.)?([a-zA-Z0-9.-]+)")
                        engine = engine_find.findall(specific[0])
                        print("-------------------------------")
                        print("             Task 4            ")
                        print("-------------------------------")
                        print("Search engine:", engine[0])
                        # Extract search keywords from query parameters
                        keyword_find = re.compile(r"q=([^&]+)")
                        keywords = keyword_find.findall(specific[0])
                        sep_keywords = str(keywords[0]).split("+")
                        print("Keywords:",",".join(sep_keywords))
                        return
                    except IndexError:
                        continue
            else:
                continue

    def Cookies(self,filename):
        """Extract and store cookies from the PCAP file."""
        # Displaying a header for the task
        print("-------------------------------")
        print("          Task 5 Cookies       ")
        print("-------------------------------")
        # List to store extracted cookies
        cookies = [] 
        # Regex pattern to find 'Cookie' headers
        mypattern = re.compile(r"Cookie:\s*([^\r\n]+)")
        # Open the PCAP file in binary read mode
        openf = open(filename,"rb")
        # Read and decode the entire file content
        sample = (openf.read()).decode("utf-8",errors="ignore")
        # Find all cookie headers in the file
        cookie = mypattern.findall(sample)
        # Split the first found cookie header into individual cookies using ";" as a separator
        sep = str(cookie[0]).split(";")
        # Process each cookie found
        for item in sep: 
            # Split cookie into key-value pair (only at the first "=" sign)
            components = item.strip().split("=",1)
            # Ensure valid key-value format
            if len(components) == 2: 
                cookies.append(components)
        # List to store cookies of interest
        writing = []
        # Define useful cookies of interest
        useful = ["MUIDB", "MUID","SRCHUID","SRCHUSR"]
        # Filter and store only cookies that are in the 'useful' list
        for category,value in cookies:
            if category in useful:
                writing.append(f"{category}:{value}")
        # Open a file to store extracted cookies in append mode
        storage = open("Cookies.txt","a")
        # Write extracted cookies to the file and print them
        for i in writing:
            # Display the cookie
            print(i)
            # Write cookie to the file
            storage.write(i+"\n")
        # Close the storage file
        storage.close()

    def PCAP(self, filename):
        '''Verification for the PCAP file'''
        # Extract the actual file name from the full path
        file_name = filename.split('/')[-1] if '/' in filename else filename.split('\\')[-1]
        # Check if the file name ends with '.pcap' (case insensitive) using regex
        return bool(re.search(r'\.pcap$', file_name, re.IGNORECASE))

                    
    def Main(self):
        '''Compiles all '''
        Tk().withdraw() 
        filename = askopenfilename() 
        
        # Check if the selected file is a valid PCAP file
        if self.PCAP(filename):
            try:
                # Process the PCAP file using multiple extraction and display functions
                self.Extracting(filename) # Extract data from the file
                self.Display() # Display extracted information
                self.FindTop(filename) # Extract domain names
                self.SearchEngine(filename) # Analyze search engine activity
                # Print a header before extracting domains
                print("-------------------------------")
                print("          Task 5 Domains       ")
                print("-------------------------------")
                # Extract domain-related information
                self.Domains(filename)
                # Extract and store cookies
                self.Cookies(filename)
            except:
                # Handle errors if the file does not exist or does not meet requirements
                print("The file that you have selected either does not exist or does not meet the requirements")

# Call the PCAP class
PCAP()