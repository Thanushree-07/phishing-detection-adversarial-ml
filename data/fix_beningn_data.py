import pandas as pd

# Load the dataset with realistic legitimate URLs (has paths, not just bare domains)
df = pd.read_csv("https://raw.githubusercontent.com/Trieuh2/ml-url-phishing-classifier/main/datasets/raw_dataset.csv")

# Keep only legitimate URLs
legit_df = df[df["status"] == "legitimate"][["url"]].copy()
legit_df["label"] = 0

# Load your existing phishing URLs (keep these, they're fine)
phishing_df = pd.read_csv("phishing_urls.csv")
phishing_df["label"] = 1
phishing_df = phishing_df[["url", "label"]]

# Combine: new realistic benign URLs + your existing phishing URLs
combined_df = pd.concat([legit_df, phishing_df], ignore_index=True)
combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

combined_df.to_csv("combined_dataset.csv", index=False)
print(f"New dataset: {len(combined_df)} rows")
print(f"Phishing: {(combined_df['label']==1).sum()}, Legitimate: {(combined_df['label']==0).sum()}")