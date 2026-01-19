import React from 'react';
import { downloadReport } from '../services/apiService';

function ScanHistory({ scans, onRefresh }) {
    const handleDownload = async (scanId, reportIndex, reportPath) => {
        try {
            await downloadReport(scanId, reportIndex, reportPath);
        } catch (error) {
            alert('Failed to download report: ' + (error.response?.data?.error?.message || error.message));
        }
    };

    if (!scans || scans.length === 0) {
        return (
            <div className="card">
                <h2>Scan History</h2>
                <div className="empty-state">
                    <p>No scans yet. Start a new scan above.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="card">
            <h2>Scan History ({scans.length})</h2>
            <ul className="scan-list">
                {scans.map((scan) => (
                    <li key={scan.id} className="scan-item">
                        <div className="scan-info">
                            <div className="scan-id">ID: {scan.id}</div>
                            <div className="scan-input">{scan.input}</div>
                            <div className="scan-meta">
                                {new Date(scan.createdAt).toLocaleString()}
                                {scan.duration && ` • ${(scan.duration / 1000).toFixed(1)}s`}
                                {scan.reportCount > 0 && ` • ${scan.reportCount} report(s)`}
                            </div>
                        </div>
                        <div>
                            <span className={`status-badge status-${scan.status}`}>
                                {scan.status.toUpperCase()}
                            </span>
                            {scan.status === 'completed' && scan.reportPaths && scan.reportPaths.length > 0 && (
                                <div style={{ marginTop: '8px' }}>
                                    {scan.reportPaths.map((reportPath, index) => (
                                        <button
                                            key={index}
                                            className="btn btn-secondary"
                                            style={{ marginLeft: index === 0 ? '0' : '8px', marginTop: '4px' }}
                                            onClick={() => handleDownload(scan.id, index, reportPath)}
                                            title={reportPath}
                                        >
                                            {reportPath.length > 25 ? `${reportPath.substring(0, 22)}...` : reportPath}
                                        </button>
                                    ))}
                                </div>
                            )}
                        </div>
                    </li>
                ))}
            </ul>
        </div>
    );
}

export default ScanHistory;
