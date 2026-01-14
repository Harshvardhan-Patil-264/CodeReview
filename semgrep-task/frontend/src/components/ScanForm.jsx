import React, { useState } from 'react';

function ScanForm({ onScanComplete, isScanning }) {
    const [scanType, setScanType] = useState('github');
    const [githubUrl, setGithubUrl] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setSelectedFile(file);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();

        if (scanType === 'github') {
            if (!githubUrl.trim()) {
                alert('Please enter a GitHub URL');
                return;
            }
            onScanComplete({ type: 'github', url: githubUrl.trim() });
        } else {
            if (!selectedFile) {
                alert('Please select a ZIP file');
                return;
            }
            onScanComplete({ type: 'upload', file: selectedFile });
        }
    };

    return (
        <div className="card">
            <h2>New Scan</h2>

            <form onSubmit={handleSubmit}>
                <div className="radio-group">
                    <label>
                        <input
                            type="radio"
                            value="github"
                            checked={scanType === 'github'}
                            onChange={(e) => setScanType(e.target.value)}
                            disabled={isScanning}
                        />
                        GitHub Repository
                    </label>
                    <label>
                        <input
                            type="radio"
                            value="upload"
                            checked={scanType === 'upload'}
                            onChange={(e) => setScanType(e.target.value)}
                            disabled={isScanning}
                        />
                        Upload ZIP
                    </label>
                </div>

                {scanType === 'github' ? (
                    <div className="form-group">
                        <label htmlFor="githubUrl">GitHub Repository URL</label>
                        <input
                            type="text"
                            id="githubUrl"
                            placeholder="https://github.com/username/repository"
                            value={githubUrl}
                            onChange={(e) => setGithubUrl(e.target.value)}
                            disabled={isScanning}
                        />
                    </div>
                ) : (
                    <div className="form-group">
                        <label htmlFor="fileUpload">Upload ZIP File (Max 50MB)</label>
                        <label htmlFor="fileUpload" className="file-input-label">
                            Choose File
                        </label>
                        <input
                            type="file"
                            id="fileUpload"
                            accept=".zip"
                            onChange={handleFileChange}
                            disabled={isScanning}
                        />
                        {selectedFile && (
                            <div className="file-selected">
                                ✓ Selected: {selectedFile.name} ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                            </div>
                        )}
                    </div>
                )}

                <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={isScanning}
                >
                    {isScanning ? 'Scanning...' : 'Start Scan'}
                </button>
            </form>
        </div>
    );
}

export default ScanForm;
