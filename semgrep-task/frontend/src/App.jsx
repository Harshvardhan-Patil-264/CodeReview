import React, { useState, useEffect } from 'react';
import ScanForm from './components/ScanForm';
import ProgressIndicator from './components/ProgressIndicator';
import ScanHistory from './components/ScanHistory';
import RuleGenerator from './components/RuleGenerator';
import { createScan, getScans } from './services/apiService';

function App() {
    const [isScanning, setIsScanning] = useState(false);
    const [scans, setScans] = useState([]);
    const [message, setMessage] = useState(null);
    const [activeTab, setActiveTab] = useState('scan'); // 'scan' or 'rules'

    // Load scan history on mount
    useEffect(() => {
        loadScans();
    }, []);

    const loadScans = async () => {
        try {
            const response = await getScans();
            setScans(response.scans || []);
        } catch (error) {
            console.error('Failed to load scans:', error);
        }
    };

    const handleScanSubmit = async (scanData) => {
        setIsScanning(true);
        setMessage(null);

        try {
            const result = await createScan(scanData);

            setMessage({
                type: 'success',
                text: `Scan completed successfully! Report: ${result.reportPath}`
            });

            // Refresh scan history
            await loadScans();

        } catch (error) {
            console.error('Scan failed:', error);

            const errorMessage = error.response?.data?.error?.message || error.message || 'Scan failed';
            setMessage({
                type: 'error',
                text: `Scan failed: ${errorMessage}`
            });
        } finally {
            setIsScanning(false);
        }
    };

    return (
        <>
            <header>
                <div className="container">
                    <h1>Code Review Platform</h1>
                    <p style={{ marginTop: '8px', opacity: 0.9 }}>
                        Static code analysis for Python, Java, JavaScript, and Go
                    </p>
                </div>
            </header>

            <div className="container">
                {/* Tab Navigation */}
                <div className="tab-navigation">
                    <button
                        className={`tab-button ${activeTab === 'scan' ? 'active' : ''}`}
                        onClick={() => setActiveTab('scan')}
                    >
                        🔍 Code Scanner
                    </button>
                    <button
                        className={`tab-button ${activeTab === 'rules' ? 'active' : ''}`}
                        onClick={() => setActiveTab('rules')}
                    >
                        ⚙️ Rule Generator
                    </button>
                </div>

                {message && (
                    <div className={`alert alert-${message.type}`}>
                        {message.text}
                    </div>
                )}

                {/* Scan Tab Content */}
                {activeTab === 'scan' && (
                    <>
                        <ScanForm onScanComplete={handleScanSubmit} isScanning={isScanning} />
                        <ProgressIndicator isScanning={isScanning} />
                        <ScanHistory scans={scans} onRefresh={loadScans} />
                    </>
                )}

                {/* Rules Tab Content */}
                {activeTab === 'rules' && (
                    <RuleGenerator />
                )}
            </div>
        </>
    );
}

export default App;
