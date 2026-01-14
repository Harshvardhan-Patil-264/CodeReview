"""
GitHub Repository Handler
Clones GitHub repositories for code review and cleanup after analysis
"""

import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse
import re


class GitHubHandler:
    def __init__(self):
        self.temp_dir = None
        
    def is_github_url(self, input_path: str) -> bool:
        """
        Check if the input is a GitHub URL
        
        Args:
            input_path: User input (folder path or GitHub URL)
            
        Returns:
            True if it's a GitHub URL, False otherwise
        """
        github_patterns = [
            r'https://github\.com/[\w-]+/[\w.-]+',
            r'git@github\.com:[\w-]+/[\w.-]+\.git',
            r'github\.com/[\w-]+/[\w.-]+'
        ]
        
        for pattern in github_patterns:
            if re.match(pattern, input_path):
                return True
        return False
    
    def clone_repository(self, github_url: str) -> str:
        """
        Clone a GitHub repository to a temporary directory
        
        Args:
            github_url: GitHub repository URL
            
        Returns:
            Path to the cloned repository
            
        Raises:
            Exception: If cloning fails
        """
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix='code_review_')
        
        # Normalize GitHub URL
        if not github_url.startswith('http') and not github_url.startswith('git@'):
            github_url = f'https://{github_url}'
        
        if not github_url.endswith('.git') and github_url.startswith('https://'):
            github_url = f'{github_url}.git'
        
        print(f"[*] Cloning repository from {github_url}...")
        
        try:
            # Clone the repository
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', github_url, self.temp_dir],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            
            print(f"[SUCCESS] Repository cloned to: {self.temp_dir}")
            return self.temp_dir
            
        except subprocess.TimeoutExpired:
            self.cleanup()
            raise Exception("Repository cloning timed out (5 minutes)")
        except FileNotFoundError:
            self.cleanup()
            raise Exception("Git is not installed. Please install Git first.")
        except Exception as e:
            self.cleanup()
            raise Exception(f"Failed to clone repository: {str(e)}")
    
    def get_repo_info(self, github_url: str) -> dict:
        """
        Extract repository information from GitHub URL
        
        Args:
            github_url: GitHub repository URL
            
        Returns:
            Dictionary with owner, repo name, and full name
        """
        # Clean URL
        url = github_url.replace('.git', '').replace('git@github.com:', 'https://github.com/')
        
        # Parse URL
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 2:
            owner = path_parts[0]
            repo = path_parts[1]
            return {
                'owner': owner,
                'repo': repo,
                'full_name': f'{owner}/{repo}',
                'url': f'https://github.com/{owner}/{repo}'
            }
        else:
            raise ValueError("Invalid GitHub URL format")
    
    def cleanup(self):
        """
        Remove the temporary cloned repository
        Handles Windows file permission issues
        """
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                # Windows-specific: Handle read-only files in .git folder
                def handle_remove_readonly(func, path, exc):
                    """Error handler for Windows readonly files"""
                    import stat
                    if not os.access(path, os.W_OK):
                        # Change the file to be writable
                        os.chmod(path, stat.S_IWUSR | stat.S_IREAD)
                        func(path)
                    else:
                        raise
                
                shutil.rmtree(self.temp_dir, onerror=handle_remove_readonly)
                print(f"[CLEANUP] Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                print(f"[WARNING] Failed to cleanup {self.temp_dir}: {e}")
            finally:
                self.temp_dir = None


def process_input(user_input: str) -> tuple:
    """
    Process user input (folder path or GitHub URL)
    
    Args:
        user_input: User input (local path or GitHub URL)
        
    Returns:
        Tuple of (path_to_analyze, is_github, repo_info, handler)
    """
    handler = GitHubHandler()
    
    # Check if it's a GitHub URL
    if handler.is_github_url(user_input):
        try:
            # Get repository info
            repo_info = handler.get_repo_info(user_input)
            
            # Clone repository
            cloned_path = handler.clone_repository(user_input)
            
            return cloned_path, True, repo_info, handler
            
        except Exception as e:
            print(f"[ERROR] {e}")
            return None, False, None, None
    else:
        # It's a local folder path
        if os.path.exists(user_input):
            return user_input, False, None, None
        else:
            print(f"[ERROR] Path does not exist: {user_input}")
            return None, False, None, None


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python github_handler.py <github_url_or_folder_path>")
        sys.exit(1)
    
    user_input = sys.argv[1]
    
    # Process input
    path, is_github, repo_info, handler = process_input(user_input)
    
    if path:
        print(f"\n[PATH] Path to analyze: {path}")
        
        if is_github:
            print(f"[REPO] Repository: {repo_info['full_name']}")
            print(f"[URL] URL: {repo_info['url']}")
        
        # Your code review logic here
        # ...
        
        # Cleanup if it was a GitHub repo
        if is_github and handler:
            handler.cleanup()
    else:
        print("[ERROR] Failed to process input")
        sys.exit(1)
