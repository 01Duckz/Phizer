import { useState } from 'react';
import './index.css';

function App() {
  const [viewState, setViewState] = useState('upload'); // 'upload' | 'scanning' | 'ready' | 'results'
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [showInfoModal, setShowInfoModal] = useState(false);

  const handleFileUpload = async (event) => {
    event.preventDefault();
    const file = event.target.fileInput.files[0];
    if (!file) return;

    setViewState('scanning');
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/index', { method: 'POST', body: formData });
      if (!response.ok) throw new Error('Failed to scan file');
      
      const data = await response.json();
      setReport(data);
      setViewState('ready'); 
    } catch (err) {
      setError(err.message);
      setViewState('upload'); 
    }
  };

  // Safely extract values
  const auth = report?.security_checks?.authentication || {};
  const metadata = report?.metadata || {};
  const evidenceList = report?.security_checks?.evidence || [];
  const urlList = report?.urls || [];
  const isSpoofed = report?.security_checks?.spoofing_flagged;

  return (
    <div className={`app-wrapper ${viewState !== 'results' ? 'home-bg' : 'results-bg'}`}>
      <div className="container py-5" style={{ maxWidth: '900px' }}>
        
        {/* VIEW 1: UPLOAD & SCANNING STATE (With Pixel Art Background) */}
        {viewState !== 'results' && (
          <div className="bento-card main-scanner-card p-4 mx-auto text-center mt-5">
            <div className="bento-pill dark-pill mx-auto mb-3" style={{ width: 'fit-content' }}>
              PHIZER OS v1.0
            </div>
            
            <h1 className="bento-header mb-4">Email Scanner</h1>
            
            {viewState === 'upload' && (
              <form onSubmit={handleFileUpload}>
                <div className="mb-4">
                  <input type="file" name="fileInput" className="bento-input form-control" accept=".eml" required />
                </div>
                <button type="submit" className="bento-btn w-100">
                  <span className="btn-icon">▷</span> ANALYZE .EML
                </button>
              </form>
            )}

            {viewState === 'scanning' && (
              <div className="py-4">
                <div className="digital-text mb-2">SCANNING...</div>
                <div className="bento-progress-bar">
                  <div className="bento-progress-fill"></div>
                </div>
              </div>
            )}

            {viewState === 'ready' && (
              <div className="py-3">
                <div className="bento-pill dark-pill mx-auto mb-4" style={{ fontSize: '1.2rem', width: 'fit-content' }}>
                  ✓ COMPLETE
                </div>
                <button onClick={() => setViewState('results')} className="bento-btn w-100">
                  VIEW REPORT <span className="btn-icon">▷</span>
                </button>
              </div>
            )}

            {error && <div className="bento-card dark-card mt-3 p-2">{error}</div>}
          </div>
        )}

        {/* VIEW 2: BENTO RESULTS DASHBOARD */}
        {viewState === 'results' && report && (
          <div className="results-dashboard">
            
            {/* TOP WIDGET BAR */}
            <div className="d-flex justify-content-between align-items-center mb-4 gap-3">
              <button onClick={() => setViewState('upload')} className="bento-btn bento-btn-sm">
                ← Back
              </button>
              <div className="bento-card digital-clock-widget px-4 py-2 m-0 text-center flex-grow-1">
                <span className="digital-text large-digital">ANALYSIS REPORT</span>
              </div>
              <button onClick={() => setShowInfoModal(true)} className="bento-btn bento-btn-icon">
                ?
              </button>
            </div>

            {/* BENTO GRID */}
            <div className="row g-4">
              
              {/* STATUS WIDGET (DARK CARD) */}
              <div className="col-md-5">
                <div className="bento-card dark-card h-100 p-4 text-center d-flex flex-column justify-content-center">
                  <div className="handwriting-text mb-2">Security Status</div>
                  {isSpoofed ? (
                    <>
                      <div className="digital-text large-digital text-danger mb-2">FAILED</div>
                      <div className="bento-pill light-pill mx-auto">Spoofing Detected</div>
                    </>
                  ) : (
                    <>
                      <div className="digital-text large-digital mb-2">PASSED</div>
                      <div className="bento-pill light-pill mx-auto">Sender Verified</div>
                    </>
                  )}
                </div>
              </div>

              {/* AUTHENTICATION PILLS WIDGET */}
              <div className="col-md-7">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3">Authentication Records</span>
                  
                  <div className="d-flex flex-column gap-3">
                    <div className="d-flex align-items-center justify-content-between">
                      <strong>SPF</strong>
                      <span className={`bento-pill ${auth.spf === 'PASS' ? 'dark-pill' : 'outline-pill'}`}>
                        {auth.spf || 'NONE'}
                      </span>
                    </div>
                    <div className="d-flex align-items-center justify-content-between">
                      <strong>DKIM</strong>
                      <span className={`bento-pill ${auth.dkim === 'PASS' ? 'dark-pill' : 'outline-pill'}`}>
                        {auth.dkim || 'NONE'}
                      </span>
                    </div>
                    <div className="d-flex align-items-center justify-content-between">
                      <strong>DMARC</strong>
                      <span className={`bento-pill ${auth.dmarc === 'PASS' ? 'dark-pill' : 'outline-pill'}`}>
                        {auth.dmarc || 'NONE'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* METADATA WIDGET */}
              <div className="col-md-12">
                <div className="bento-card p-4">
                  <div className="row">
                    <div className="col-md-6 mb-3 mb-md-0">
                      <span className="handwriting-text text-muted">Subject</span>
                      <div className="fw-bold text-truncate">{metadata.subject || 'N/A'}</div>
                    </div>
                    <div className="col-md-6">
                      <span className="handwriting-text text-muted">From</span>
                      <div className="fw-bold text-truncate">{metadata.from || 'N/A'}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* PROOF WIDGET */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3">Proof of Analysis</span>
                  {evidenceList.length > 0 ? (
                    <ul className="handwriting-list m-0 ps-3">
                      {evidenceList.map((item, idx) => (
                        <li key={idx} className="mb-2">{item}</li>
                      ))}
                    </ul>
                  ) : (
                    <div className="text-muted">No explicit evidence provided.</div>
                  )}
                </div>
              </div>

              {/* VIRUSTOTAL WIDGET */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3">Embedded Links</span>
                  {urlList.length === 0 ? (
                    <div className="text-muted text-center mt-4">No external links found.</div>
                  ) : (
                    <div className="d-flex flex-column gap-2">
                      {urlList.map((item, idx) => {
                        const vt = item?.vt_reputation || {};
                        return (
                          <div key={idx} className="bento-list-item d-flex justify-content-between align-items-center">
                            <span className="text-truncate" style={{ maxWidth: '60%' }}>{item?.domain || 'N/A'}</span>
                            <span className={`bento-pill ${vt.malicious > 0 ? 'dark-pill' : 'outline-pill'}`} style={{ fontSize: '0.7rem' }}>
                              {vt.status === 'scored' ? `${vt.malicious} MALICIOUS` : 'UNSCORED'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

            </div>
          </div>
        )}

        {/* INFO MODAL */}
        {showInfoModal && (
          <div className="bento-modal-backdrop" onClick={() => setShowInfoModal(false)}>
            <div className="bento-card p-4 modal-content-bento" onClick={(e) => e.stopPropagation()}>
              <div className="d-flex justify-content-between align-items-center mb-4">
                <h4 className="handwriting-text m-0 fs-3">Guide</h4>
                <button onClick={() => setShowInfoModal(false)} className="bento-btn bento-btn-icon">X</button>
              </div>
              <p className="mb-3"><strong>SPF:</strong> Authorized sending IPs.</p>
              <p className="mb-3"><strong>DKIM:</strong> Digital signature check.</p>
              <p className="mb-0"><strong>DMARC:</strong> Enforces domain alignment.</p>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

export default App;