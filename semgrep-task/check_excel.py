import pandas as pd

df = pd.read_excel('Golang_Review.xlsx')
print(f"Total findings: {len(df)}")
print(f"\nColumns: {list(df.columns)}")
print(f"\nAll data:")
for i, row in df.iterrows():
    print(f"\n=== Finding {i+1} ===")
    print(f"Rule ID: {row['Rule ID']}")
    print(f"Severity: {row['Severity']}")
    print(f"Line: {row['Line']}")
    print(f"File: {row['File']}")
    print(f"Message: {row['Message']}") 
