import re
from collections import defaultdict

# "threads.txt" dosyasını okuyoruz
with open("threads.txt", "r") as f:
    lines = f.readlines()

# Her bir voter'a hangi adminlerin "sign task started" dediğini tutacağız
approvals = defaultdict(set)

# Düzenli ifade (regex) ile satırlardan Voter X - Admin Y bilgisini çekelim
pattern = re.compile(r"BlindSign: Voter\s+(\d+)\s*-\s*Admin\s+(\d+)\s*sign task started")

for line in lines:
    match = pattern.search(line)
    if match:
        voter_id = int(match.group(1))
        admin_id = int(match.group(2))
        approvals[voter_id].add(admin_id)

# Kaç voter ve admin olduğunu anlamak için en büyük değerleri tespit edelim
max_voter = max(approvals.keys())
max_admin = 0 if not approvals else max(max(admins) for admins in approvals.values())

# Başlık: Admin 1'den Admin N'e
admin_list = list(range(1, max_admin + 1))

# ASCII tablosu başlığı
header = ["Voter"] + [f"Admin {a}" for a in admin_list]
print(" | ".join(header))

# Her voter için satır oluştur
for voter_id in range(1, max_voter + 1):
    # approvals[voter_id] içinde hangi adminler var, varsa 'Yes' yoksa ' - '
    row = [str(voter_id)]
    for a in admin_list:
        if a in approvals[voter_id]:
            row.append("Yes") 
        else:
            row.append("-")
    print(" | ".join(row))
