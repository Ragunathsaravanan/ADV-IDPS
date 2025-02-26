import os
import re
import requests
import subprocess
from stem import Signal
from stem.control import Controller
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from textblob import TextBlob
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from threading import Thread
import pandas as pd


# ---- Main Scraper Class ----
class WebScraper:
    def __init__(self, base_url, tor_path, update_callback):
        self.base_url = base_url
        self.tor_path = tor_path
        self.update_callback = update_callback
        self.is_scraping = True
        self.visited_urls = set()
        self.collected_data = []  # Store the collected data here
        self.session = None
        self._start_tor_service()

        if ".onion" in self.base_url:
            self.session = self._get_tor_session()
        else:
            self.session = requests.Session()

    def _start_tor_service(self):
        """ Start the Tor service using the specified tor.exe path. """
        if self.tor_path:
            try:
                # Start Tor service in the background
                self.tor_process = subprocess.Popen([self.tor_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.update_callback("Tor service started.", 0)
            except Exception as e:
                self.update_callback(f"Error starting Tor: {e}", 0)
                self.tor_process = None
        else:
            self.update_callback("Tor path not provided.", 0)
            self.tor_process = None

    def _get_tor_session(self):
        """ Set up a requests session to route traffic through Tor (SOCKS5 proxy). """
        session = requests.Session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        return session

    def _get_new_identity(self):
        """ Signal Tor to use a new identity (for IP change). """
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)

    def scrape(self):
        """ Start scraping process. """
        self.visited_urls.add(self.base_url)
        self.update_callback(f"Starting to crawl {self.base_url}", 0)
        self._crawl(self.base_url)

    def stop_scraping(self):
        """ Stop scraping. """
        self.is_scraping = False

    def _crawl(self, url):
        """ Recursively crawl the website and collect data. """
        if not self.is_scraping:
            return

        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract content
            content = soup.get_text()
            self._extract_data(content, url, soup)

            # Extract links
            links = self._extract_links(soup)
            for link in links:
                if link not in self.visited_urls:
                    self.visited_urls.add(link)
                    self.update_callback(f"Crawling {link}", len(self.visited_urls))
                    self._crawl(link)

        except requests.exceptions.RequestException as e:
            self.update_callback(f"Request failed for {url}: {e}", len(self.visited_urls))
        except Exception as e:
            self.update_callback(f"Error: {e}", len(self.visited_urls))

    def _extract_links(self, soup):
        """ Extract valid links from the page (excluding non-HTML files like images, PDFs). """
        links = []
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            # Eliminate links to images, PDFs, and other non-HTML files
            if any(href.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.rar']):
                continue
            full_url = urljoin(self.base_url, href)
            links.append(full_url)
        return links

    def _extract_data(self, content, url, soup):
        """ Extract emails, headings, meta description, and links from the page content. """
        # Extract emails using regex
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)

        # Extract headings (H1, H2, H3)
        headings = {
            "H1": [h1.get_text().strip() for h1 in soup.find_all('h1')],
            "H2": [h2.get_text().strip() for h2 in soup.find_all('h2')],
            "H3": [h3.get_text().strip() for h3 in soup.find_all('h3')]
        }

        # Extract Meta Description and Keywords
        meta_description = soup.find("meta", attrs={"name": "description"})
        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
        description = meta_description["content"] if meta_description else "N/A"
        keywords = meta_keywords["content"] if meta_keywords else "N/A"

        # Extract Links (internal and external)
        links = [a['href'] for a in soup.find_all('a', href=True)]

        # Sentiment Analysis (optional)
        sentiment_score = self.analyze_sentiment(content)

        # Save extracted data to internal collection
        self.collected_data.append({
            "URL": url,
            "Emails": emails,
            "Headings (H1)": headings["H1"],
            "Headings (H2)": headings["H2"],
            "Headings (H3)": headings["H3"],
            "Meta Description": description,
            "Meta Keywords": keywords,
            "Links": links,
            "Sentiment Score": sentiment_score
        })

    def analyze_sentiment(self, content):
        """ Simple sentiment analysis using TextBlob. """
        blob = TextBlob(content)
        return blob.sentiment.polarity  # Sentiment score (-1 to 1)

    def get_collected_data(self):
        """ Return collected data. """
        return self.collected_data


# ---- Helper function to save data to Excel ---
def save_to_excel(data, filename="output/results.xlsx"):
    """ Save data to Excel file. """
    # Create directory if it doesn't exist
    output_dir = os.path.dirname(filename)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Check if file exists and append data, or create a new file
    if data:  # Ensure there is data to write
        df = pd.DataFrame(data)
        df.to_excel(filename, index=False)
        print(f"Data saved to {filename}")
    else:
        print("No data to save")


# ---- Main GUI Application ----
class ScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Scraper")

        # Configure the layout of the window
        self.frame = tk.Frame(root, padx=20, pady=20)
        self.frame.pack(padx=10, pady=10)

        self.url_label = tk.Label(self.frame, text="Enter URL:", font=("Arial", 12))
        self.url_label.grid(row=0, column=0, pady=5)

        self.url_entry = tk.Entry(self.frame, width=50, font=("Arial", 12))
        self.url_entry.grid(row=0, column=1, pady=5)

        # Tor Executable Path Button
        self.tor_button = tk.Button(self.frame, text="Select Tor Executable", font=("Arial", 12),
                                    command=self.select_tor_executable)
        self.tor_button.grid(row=1, column=0, pady=10)

        self.tor_path_label = tk.Label(self.frame, text="No Tor executable selected", font=("Arial", 10), fg="red")
        self.tor_path_label.grid(row=1, column=1, pady=5)

        # Scrape Button
        self.scrape_button = tk.Button(self.frame, text="Start Scraping", font=("Arial", 12),
                                       command=self.start_scraping)
        self.scrape_button.grid(row=2, column=0, pady=10, padx=5)

        # Stop Button
        self.stop_button = tk.Button(self.frame, text="Stop Scraping", font=("Arial", 12), command=self.stop_scraping,
                                     state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, pady=10, padx=5)

        # Export Button
        self.export_button = tk.Button(self.frame, text="Export to Excel", font=("Arial", 12),
                                       command=self.export_to_excel, state=tk.DISABLED)
        self.export_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self.frame, orient="horizontal", length=300, mode="determinate")
        self.progress.grid(row=4, column=0, columnspan=2, pady=10)

        # Output Text Box
        self.output_text = tk.Text(self.frame, height=10, width=70, wrap=tk.WORD, font=("Arial", 10))
        self.output_text.grid(row=5, column=0, columnspan=2, pady=10)
        self.output_text.config(state=tk.DISABLED)

        self.tor_path = None

    def select_tor_executable(self):
        """ Let the user select the Tor executable file. """
        tor_path = filedialog.askopenfilename(title="Select tor.exe",
                                              filetypes=(("Executable Files", "*.exe"), ("All Files", "*.*")))
        if tor_path:
            self.tor_path = tor_path
            self.tor_path_label.config(text=f"Selected: {os.path.basename(tor_path)}", fg="green")

    def update_output(self, text, progress):
        """ Update the GUI with the current progress. """
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"{text}\n")
        self.output_text.yview(tk.END)
        self.output_text.config(state=tk.DISABLED)

        # Update the progress bar
        self.progress['value'] = progress

    def start_scraping(self):
        """ Start scraping when the button is clicked. """
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a valid URL.")
            return
        if not self.tor_path:
            messagebox.showerror("Error", "Please select a Tor executable.")
            return

        self.base_url = url
        self.scraper = WebScraper(url, self.tor_path, self.update_output)

        # Disable start button and enable stop button
        self.scrape_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.is_scraping = True
        thread = Thread(target=self.scraper.scrape)
        thread.start()

    def stop_scraping(self):
        """ Stop the scraping process. """
        if self.scraper:
            self.scraper.stop_scraping()
        self.scrape_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        # Enable export button once scraping is stopped
        self.export_button.config(state=tk.NORMAL)

    def export_to_excel(self):
        """ Export the data to Excel when the button is clicked. """
        if self.scraper:
            data = self.scraper.get_collected_data()
            if data:
                save_to_excel(data)
                messagebox.showinfo("Success", "Data exported to Excel successfully.")
            else:
                messagebox.showerror("Error", "No data to export.")
        else:
            messagebox.showerror("Error", "No data to export.")


# ---- Main Entry Point ----
def darkwebscraper():
    root = tk.Tk()
    # root.iconbitmap('app.ico')
    app = ScraperApp(root)
    root.mainloop()
