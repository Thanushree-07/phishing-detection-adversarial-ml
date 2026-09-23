import pandas as pd
beningn_df=pd.read_csv("benign_urls.csv")
phishing_df=pd.read_csv("phishing_urls.csv")

beningn_df["url"]="http://"+beningn_df["domain"]
beningn_df["label"]=0

phishing_df["label"]=1

beningn_clean=beningn_df[["url","label"]]
phishing_clean=phishing_df[["url","label"]]

combined_df=pd.concat([beningn_clean,phishing_clean],ignore_index=True)

combined_df=combined_df.sample(frac=1,random_state=42).reset_index(drop=True)

combined_df.to_csv("combined_dataset.csv",index=False)

print(f"Total rows: {len(combined_df)}")
print(f"Phishing: {(combined_df['label']==1).sum()}")
print(f"Legitimate: {(combined_df['label']==0).sum()}")
print("\nSample rows:")
print(combined_df.head())