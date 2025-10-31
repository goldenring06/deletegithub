# deletegithub

🔎 Git Deleted File Recovery & Secret Extraction

This project automates recovering deleted files from a Git repository and scans them for secrets such as API keys, tokens, credentials, etc.

🧠 How it Works (Algorithm)
Step	Action	Description
1️⃣	Clone Repository	Clone target repository locally.
2️⃣	Extract All Git Objects	Traverse .git/objects to reconstruct deleted or historical files.
3️⃣	Restore Files	Convert Git object blobs back to readable source files.
4️⃣	Save Recovered Files	Store extracted files into a separate directory for analysis.
5️⃣	Scan for Secrets	Run secret-detection commands/tools (grep regex, truffleHog, or custom logic).
6️⃣	Output Results	Print or save found secrets with file paths.
📦 Usage
./recover_deleted_files.sh <repo_url> <output_folder>


Example:

./recover_deleted_files.sh https://github.com/example/project.git recovered/

📁 Output

✅ Restored deleted files

🔐 Found secrets (API keys, tokens, passwords)

📜 Logs of recovered objects
