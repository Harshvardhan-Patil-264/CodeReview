# GitHub Integration - Quick Start Guide

## ✅ New Feature: GitHub Repository Support

Your code review tool now supports **GitHub repository URLs** in addition to local folders!

## 🚀 Usage

### Option 1: Local Folder (Original)
```bash
python auto-review.py "D:\MyProject\code"
```

### Option 2: GitHub Repository (NEW!)
```bash
python auto-review.py https://github.com/username/repository
```

## 📝 Supported GitHub URL Formats

All these formats work:
- `https://github.com/username/repo`
- `https://github.com/username/repo.git`
- `git@github.com:username/repo.git`
- `github.com/username/repo`

## 🔧 How It Works

1. **Detects GitHub URL** - Automatically recognizes GitHub links
2. **Clones Repository** - Downloads code to temporary folder
3. **Runs Analysis** - Performs complete code review
4. **Generates Report** - Creates Excel report as usual
5. **Cleanup** - Automatically deletes temporary files

## 📋 Requirements

**Git must be installed:**
```bash
# Check if Git is installed
git --version

# If not installed, download from:
# https://git-scm.com/downloads
```

## 💡 Examples

### Analyze Your Own Repository
```bash
python auto-review.py https://github.com/Harshvardhan-Patil-264/CodeReview
```

### Analyze Any Public Repository
```bash
python auto-review.py https://github.com/facebook/react
python auto-review.py https://github.com/microsoft/vscode
python auto-review.py https://github.com/nodejs/node
```

## 🎯 Features

✅ **Automatic Detection** - Recognizes GitHub URLs vs local paths
✅ **Temporary Storage** - Clones to temp folder, auto-cleanup
✅ **Same Analysis** - Identical code review as local folders
✅ **Repository Info** - Shows repo owner and name
✅ **Error Handling** - Clear error messages if clone fails

## ⚠️ Notes

- **Public Repositories Only** - Private repos require authentication (coming soon)
- **Clone Timeout** - 5 minutes maximum for large repositories
- **Disk Space** - Ensure sufficient space for cloning
- **Network Required** - Internet connection needed for cloning

## 🔒 Private Repository Support (Future)

To analyze private repositories, you'll need to:
1. Generate a GitHub Personal Access Token
2. Add it to `.env` file
3. Use authenticated clone URLs

## 🐛 Troubleshooting

### Error: "Git is not installed"
**Solution:** Install Git from https://git-scm.com/downloads

### Error: "Repository cloning timed out"
**Solution:** Repository is too large. Try cloning manually first.

### Error: "Failed to clone repository"
**Solution:** Check if the repository URL is correct and public.

## 📊 Example Output

```
🔄 Cloning repository from https://github.com/username/repo.git...
✅ Repository cloned to: C:\Users\...\Temp\code_review_xyz123

📦 Analyzing GitHub Repository: username/repo
🔗 URL: https://github.com/username/repo

🚀 Initializing security engine... Please wait.
🔍 Scanning document: app.js...
✨ Created new report: app_Review.xlsx

✅ All documents scanned successfully.
🧹 Cleaned up temporary directory
```

## 🎉 Benefits

- **No Manual Cloning** - Just paste the GitHub URL
- **Quick Analysis** - Analyze any public repo instantly
- **Clean Workspace** - No leftover files
- **Same Quality** - Identical analysis as local folders

---

**Ready to try it?** Just paste any GitHub repository URL! 🚀
