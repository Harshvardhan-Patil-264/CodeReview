import React from 'react';

function ProgressIndicator({ isScanning, message }) {
    if (!isScanning) return null;

    return (
        <div className="card">
            <div className="alert alert-info">
                <strong>Scanning in progress...</strong>
                <br />
                {message || 'Analyzing code and generating report. This may take a few minutes.'}
            </div>
            <div className="progress-bar">
                <div className="progress-bar-fill"></div>
            </div>
        </div>
    );
}

export default ProgressIndicator;
