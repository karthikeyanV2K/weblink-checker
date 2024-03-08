from flask import Flask, render_template, request
from datetime import datetime
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import re
import ssl
import whois

app = Flask(__name__, template_folder='temp')

# Function to capture full-page website screenshot
def capture_screenshot(url):
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    driver.get(url)
    # Adjust the window size to capture the entire page
    driver.set_window_size(1920, driver.execute_script("return document.body.scrollHeight"))
    screenshot_path = f"temp/{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
    driver.save_screenshot(screenshot_path)
    driver.quit()
    return screenshot_path

# Function to fetch hosting date
def get_hosting_date(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            return w.creation_date
    except:
        pass
    return "Unknown"

# Function to extract website information
def extract_website_info(url):
    website_info = {}
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            website_info['Title'] = soup.title.text.strip()
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                website_info['Description'] = meta_desc['content']
            else:
                website_info['Description'] = "Description not found"
    except Exception as e:
        website_info['Error'] = str(e)
    return website_info

# Function to check for suspicious website features
def check_suspicious(url):
    suspicious_features = []

    try:
        # Fetch the HTML content of the given URL
        response = requests.get(url)
        if response.status_code == 200:
            html_content = response.text

            # Parse HTML content using BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')

            # Check for Suspicious URLs
            suspicious_urls = re.findall(r'(http|ftp|https)://[\w-]+(\.[\w-]+)+([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?', html_content)
            if suspicious_urls:
                suspicious_features.append("Suspicious URLs detected")

            # Check for Poor Website Design and User Experience
            if not soup.find_all('header') or not soup.find_all('footer'):
                suspicious_features.append("Poor Website Design and User Experience detected")

            # Check for Unusual Domain Names
            domain = url.split('//')[-1].split('/')[0]
            if '-' in domain:
                suspicious_features.append("Unusual Domain Names detected")

            # Check for Unrealistic Discounts and Deals
            prices = soup.find_all('span', class_='price')
            for price in prices:
                original_price = price.find_previous_sibling('span', class_='original-price')
                if original_price:
                    discount = (float(original_price.text.strip('$')) - float(price.text.strip('$'))) / float(original_price.text.strip('$')) * 100
                    if discount > 90:  # Assuming anything above 90% discount is unrealistic
                        suspicious_features.append("Unrealistic Discounts and Deals detected")
                        break  # Only need to detect once

            # Check for Absence of Customer Reviews
            if not soup.find_all(class_="customer-review"):
                suspicious_features.append("Absence of Customer Reviews detected")

            # Check for Insecure Payment Methods
            forms = soup.find_all('form')
            for form in forms:
                action_url = form.get('action')
                if action_url and action_url.startswith('http://'):
                    suspicious_features.append("Insecure Payment Methods detected")
                    break  # Only need to detect once

            # Check for Trust Seals and Certifications
            if soup.find_all(class_="trust-seal"):
                suspicious_features.append("Trust Seals and Certifications detected")

            # Check for SSL certificate (HTTPS)
            if url.startswith("https://"):
                suspicious_features.append("Website is using HTTPS protocol")

                # Check SSL certificate
                cert = ssl.get_server_certificate((url.split('//')[1].split('/')[0], 443))
                x509 = ssl.PEM_cert_to_DER_cert(cert)

                try:
                    issuer = x509.get_issuer()
                    issuer_name = issuer.commonName.decode()
                except AttributeError:
                    issuer_name = "Unknown"

                try:
                    subject = x509.get_subject()
                    subject_name = subject.commonName.decode()
                except AttributeError:
                    subject_name = "Unknown"

                try:
                    expiration_date = x509.get_notAfter().decode('ascii')
                    expiration_date = datetime.strptime(expiration_date, "%Y%m%d%H%M%SZ")
                except AttributeError:
                    expiration_date = "Unknown"

                suspicious_features.append("SSL certificate details:")
                suspicious_features.append("- Issuer: " + issuer_name)
                suspicious_features.append("- Subject: " + subject_name)
                suspicious_features.append("- Expiration Date: " + str(expiration_date))

    except Exception as e:
        suspicious_features.append("An error occurred: " + str(e))

    return suspicious_features

# Route for the homepage
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        website_url = request.form['website_url']

        # Analyze the website and gather information
        screenshot_path = capture_screenshot(website_url)
        hosting_date = get_hosting_date(website_url)
        website_info = extract_website_info(website_url)
        suspicious_features = check_suspicious(website_url)

        return render_template('report.html', website_url=website_url, screenshot_path=screenshot_path,
                               hosting_date=hosting_date, website_info=website_info,
                               suspicious_features=suspicious_features)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=9000)
