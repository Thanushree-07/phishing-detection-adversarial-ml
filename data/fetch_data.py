import pandas as pd
import urllib.request
import zipfile
import io
print("fetching the tranco beningn list...")
url="https://tranco-list.eu/top-1m.csv.zip"
response=urllib.request.urlopen(url)
zip_data=zipfile.ZipFile(io.BytesIO(response.read()))
zip_data.extractall("tranco_data")

benign_df = pd.read_csv("tranco_data/top-1m.csv", names=["rank", "domain"])
benign_df.head(10000).to_csv("benign_urls.csv", index=False)
print(f"Saved {len(benign_df.head(10000))} benign URLs to benign_urls.csv")

print("Fetching OpenPhish feed...")
url = "https://openphish.com/feed.txt"
response = urllib.request.urlopen(url)
phishing_urls = response.read().decode('utf-8').splitlines()

phishing_df = pd.DataFrame(phishing_urls, columns=["url"])
phishing_df.to_csv("phishing_urls.csv", index=False)
print(f"Saved {len(phishing_df)} phishing URLs to phishing_urls.csv")

print("\nDone. Check the data/ folder for benign_urls.csv and phishing_urls.csv")