import { useState, useEffect } from 'react';
import './index.css';

const EDUCATIONAL_CONTENT = {
  spf: { title: 'What is SPF?', body: 'Sender Policy Framework (SPF) acts like a guest list. It explicitly states which IP addresses or servers are allowed to send emails on behalf of that domain.' },
  dkim: { title: 'What is DKIM?', body: 'DomainKeys Identified Mail (DKIM) adds a digital cryptographic signature to emails. It proves that the email was genuinely sent by the domain owner and wasn’t tampered with in transit.' },
  dmarc: { title: 'What is DMARC?', body: 'DMARC ties SPF and DKIM together. It verifies that the domain in the "From" address actually matches the domains validated by SPF and DKIM, ensuring the sender’s identity isn’t spoofed.' },
  relay: { title: 'What are Email Relays?', body: 'When you send an email, it rarely goes directly to the recipient. It "hops" from one mail server (relay) to another across the internet. Attackers often route emails through suspicious relays to hide their origin.' },
  headers: { title: 'What are Email Headers?', body: 'Headers are hidden digital footprints attached to every email. They contain routing data, authentication results, and software details used by the sender.' }
};

const getAuthColor = (status) => {
  const s = status?.toUpperCase();
  if (s === 'PASS') return 'pass-pill';
  if (s === 'FAIL' || s === 'SOFTFAIL') return 'fail-pill';
  return 'neutral-pill';
};

const getAuthExplanation = (protocol, status) => {
  const s = status?.toUpperCase();
  if (protocol === 'SPF') {
    if (s === 'PASS') return 'The sending server IP is explicitly authorized by the domain owner.';
    if (s === 'FAIL' || s === 'SOFTFAIL') return 'The sending server is NOT authorized, highly indicative of spoofing.';
    return 'No valid SPF record found. The domain does not restrict who can send on its behalf.';
  }
  if (protocol === 'DKIM') {
    if (s === 'PASS') return 'The cryptographic signature is valid. The email was not tampered with.';
    if (s === 'FAIL') return 'The signature is invalid or missing, meaning the email may have been altered in transit.';
    return 'No DKIM signature found. The sender did not cryptographically sign this email.';
  }
  if (protocol === 'DMARC') {
    if (s === 'PASS') return 'The "From" domain matches the validated SPF/DKIM records. Sender identity is verified.';
    if (s === 'FAIL') return 'The "From" domain does NOT match the underlying sender data. This is likely a forged email.';
    return 'No DMARC policy enforced by the domain owner.';
  }
  return 'Status undetermined.';
};

function App() {
  const [viewState, setViewState] = useState('upload'); 
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [modalState, setModalState] = useState({ isOpen: false, title: '', body: null });

  const handleFileUpload = async (event) => {
    event.preventDefault();
    const file = event.target.fileInput.files[0];
    if (!file) return;

    setViewState('scanning');
    setError(null);
    setUploadProgress(0);

    // Simulate progress while fetching
    const progressInterval = setInterval(() => {
      setUploadProgress(prev => (prev >= 90 ? 90 : prev + 15));
    }, 400);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/index', { method: 'POST', body: formData });
      if (!response.ok) throw new Error('Failed to scan file');
      const data = await response.json();
      
      clearInterval(progressInterval);
      setUploadProgress(100);
      setReport(data);
      
      setTimeout(() => setViewState('ready'), 600); 
    } catch (err) {
      clearInterval(progressInterval);
      setError(err.message);
      setViewState('upload'); 
    }
  };

  const openEduModal = (key) => {
    setModalState({ isOpen: true, title: EDUCATIONAL_CONTENT[key].title, body: <p>{EDUCATIONAL_CONTENT[key].body}</p> });
  };

  const openAboutModal = () => {
    setModalState({
      isOpen: true,
      title: 'About Phizer',
      body: (
        <div className="d-flex flex-column gap-3">
          <div>
            <h5 className="handwriting-text fw-bold m-0"><i className="bi bi-info-circle"></i> What is Phizer?</h5>
            <p className="m-0 fs-6">Phizer is an educational forensic tool designed to analyze raw email files (.eml). It breaks down hidden routing data to verify if an email truly came from its claimed sender or if it contains hidden threats.</p>
          </div>
          <div>
            <h5 className="handwriting-text fw-bold m-0"><i className="bi bi-shield-exclamation"></i> What is Phishing?</h5>
            <p className="m-0 fs-6">Phishing is a cyberattack where scammers disguise themselves as trusted entities to trick you into clicking malicious links, downloading malware, or revealing sensitive data.</p>
          </div>
          <div>
            <h5 className="handwriting-text fw-bold m-0"><i className="bi bi-list-ol"></i> How to use this tool:</h5>
            <ol className="m-0 fs-6 ps-3">
              <li>Save a suspicious email as an <strong>.eml</strong> file from your mail client.</li>
              <li>Upload it into the Phizer scanner drop box.</li>
              <li>Wait for the automated forensic analysis to complete.</li>
              <li>Review the dashboard for spoofing alerts, malicious links, and unauthorized relays.</li>
            </ol>
          </div>
        </div>
      )
    });
  };

  const openLinkModal = (item) => {
    const vt = item?.vt_reputation || {};
    const isMalicious = vt.malicious > 0;
    
    setModalState({
      isOpen: true,
      title: 'Detailed Link Analysis',
      body: (
        <div className="d-flex flex-column gap-3">
          <div className="bento-list-item">
            <strong className="d-block mb-1">Full URL Scanned:</strong>
            <div className="pixel-mono text-break" style={{ wordBreak: 'break-all' }}>{item.url || item.domain || 'N/A'}</div>
          </div>
          <div className="bento-list-item">
            <strong className="d-block mb-1">Security Vendor Consensus:</strong>
            {vt.status === 'scored' ? (
              <span className={`badge ${isMalicious ? 'fail-pill' : 'pass-pill'} fs-6`}>
                {vt.malicious} / {vt.total || '0'} Vendors Flagged as Malicious
              </span>
            ) : (
              <span className="badge neutral-pill fs-6">Unscored / Unknown</span>
            )}
          </div>
          {vt.details && vt.details.length > 0 && (
            <div className="bento-list-item">
              <strong className="d-block mb-2">Vendor Flags:</strong>
              <ul className="handwriting-list m-0 ps-3">
                {vt.details.map((d, i) => (
                  <li key={i} className="mb-1"><strong>{d.vendor}:</strong> {d.result}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )
    });
  };

  const auth = report?.security_checks?.authentication || {};
  const evidenceList = report?.security_checks?.evidence || [];
  const urlList = report?.urls || [];
  const headersList = report?.headers || [];
  const relaysList = report?.relays || [];
  const isSpoofed = report?.security_checks?.spoofing_flagged;

  const importantKeys = ['Subject', 'From', 'To', 'Date'];
  const importantHeaders = importantKeys.map(key => {
    const found = headersList.find(h => h.name.toLowerCase() === key.toLowerCase());
    return { name: key, value: found ? found.value : 'N/A' };
  });
  const remainingHeaders = headersList.filter(
    h => !importantKeys.some(key => key.toLowerCase() === h.name.toLowerCase())
  );

  return (
    <div className={`app-wrapper ${viewState !== 'results' ? 'home-bg' : 'results-bg'}`}>
      
      {/* GLOBAL ABOUT BUTTON */}
      {viewState !== 'results' && (
        <button onClick={openAboutModal} className="bento-btn about-fab-btn">
          <i className="bi bi-info-circle-fill me-2"></i> About
        </button>
      )}

      <div className="container py-5 d-flex flex-column" style={{ maxWidth: '1000px', minHeight: '100vh' }}>
        
        {/* VIEW 1: UPLOAD SCREEN - PERFECTLY CENTERED */}
        {viewState !== 'results' && (
          <div className="d-flex flex-column align-items-center justify-content-center w-100" style={{ flexGrow: 1 }}>
            
            <div className="bento-card main-scanner-card p-5 text-center w-100" style={{ maxWidth: '600px' }}>
              <div className="bento-pill dark-pill mx-auto mb-3" style={{ width: 'fit-content' }}>PHIZER OS v2.0</div>
              <h1 className="bento-header mb-4">Email Scanner</h1>
              
              {viewState === 'upload' && (
                <form onSubmit={handleFileUpload}>
                  <div className="mb-4">
                    <input type="file" name="fileInput" className="bento-input form-control p-3" accept=".eml" required />
                  </div>
                  <button type="submit" className="bento-btn w-100 justify-content-center py-3 fs-4">
                    <i className="bi bi-play-fill btn-icon"></i> ANALYZE .EML
                  </button>
                </form>
              )}

              {viewState === 'scanning' && (
                <div className="py-4">
                  <div className="digital-text mb-2 fs-4">SCANNING... {uploadProgress}%</div>
                  <div className="bento-progress-bar">
                    <div className="bento-progress-fill" style={{ width: `${uploadProgress}%`, transition: 'width 0.4s ease' }}></div>
                  </div>
                </div>
              )}

              {viewState === 'ready' && (
                <div className="py-3">
                  <div className="bento-pill pass-pill mx-auto mb-4 px-4 py-2" style={{ fontSize: '1.2rem', width: 'fit-content' }}>
                    <i className="bi bi-check2-all"></i> SCAN COMPLETE
                  </div>
                  <button onClick={() => setViewState('results')} className="bento-btn w-100 justify-content-center py-3 fs-4">
                    VIEW REPORT <i className="bi bi-arrow-right-short btn-icon"></i>
                  </button>
                </div>
              )}
              {error && <div className="bento-card fail-card mt-3 p-3 text-white fw-bold"><i className="bi bi-exclamation-triangle"></i> {error}</div>}
            </div>
          </div>
        )}

        {/* VIEW 2: RESULTS DASHBOARD */}
        {viewState === 'results' && report && (
          <div className="results-dashboard w-100 py-3">
            <div className="d-flex justify-content-between align-items-center mb-4 gap-3">
              <button onClick={() => setViewState('upload')} className="bento-btn bento-btn-sm"><i className="bi bi-arrow-left"></i> Back</button>
              <div className="bento-card digital-clock-widget px-4 py-2 m-0 text-center flex-grow-1 border-2">
                <span className="digital-text large-digital m-0 p-0">ANALYSIS REPORT</span>
              </div>
            </div>

            <div className="row g-4">
              
              {/* SECTION 1: SECURITY STATUS & AUTHENTICATION */}
              <div className="col-md-5">
                <div className={`bento-card h-100 p-4 text-center d-flex flex-column justify-content-center ${!isSpoofed ? 'safe-card' : 'fail-card'}`}>
                  <div className="handwriting-text mb-2 text-white opacity-75">Security Status</div>
                  {isSpoofed ? (
                    <>
                      <div className="digital-text large-digital text-white mb-3">FAILED</div>
                      <div className="bento-pill mx-auto bg-white text-dark border-0"><i className="bi bi-shield-x text-danger"></i> Spoofing Detected</div>
                    </>
                  ) : (
                    <>
                      <div className="digital-text large-digital text-white mb-3">PASSED</div>
                      <div className="bento-pill mx-auto bg-white text-dark border-0"><i className="bi bi-shield-check text-success"></i> Sender Verified</div>
                    </>
                  )}
                </div>
              </div>

              <div className="col-md-7">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3">Authentication Records</span>
                  <div className="d-flex flex-column gap-3 mb-3">
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>SPF</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${getAuthColor(auth.spf)}`}>{auth.spf || 'NONE'}</span>
                      <button className="help-icon" onClick={() => openEduModal('spf')}><i className="bi bi-question-lg"></i></button>
                    </div>
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>DKIM</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${getAuthColor(auth.dkim)}`}>{auth.dkim || 'NONE'}</span>
                      <button className="help-icon" onClick={() => openEduModal('dkim')}><i className="bi bi-question-lg"></i></button>
                    </div>
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>DMARC</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${getAuthColor(auth.dmarc)}`}>{auth.dmarc || 'NONE'}</span>
                      <button className="help-icon" onClick={() => openEduModal('dmarc')}><i className="bi bi-question-lg"></i></button>
                    </div>
                  </div>
                </div>
              </div>

              {/* SECTION 1.5: IMPORTANT HEADERS */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-envelope-paper"></i> Important Email Details</span>
                  <div className="row g-3">
                    {importantHeaders.map((hdr, idx) => (
                      <div key={idx} className="col-md-6">
                        <div className="bento-list-item h-100 bg-white bg-opacity-50">
                          <strong className="d-block mb-1 text-muted small text-uppercase">{hdr.name}</strong>
                          <div className="pixel-mono fs-6 scroll-x">{hdr.value}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* SECTION 2: EMAIL RELAYS */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4"><i className="bi bi-router"></i> Email Relay Hops</span>
                    <button className="help-icon" onClick={() => openEduModal('relay')}><i className="bi bi-question-lg"></i></button>
                  </div>
                  
                  {relaysList.length === 0 ? (
                    <div className="text-muted">No relay information found.</div>
                  ) : (
                    <>
                      <div className="bento-list-item p-4 mb-4 bg-white bg-opacity-50 border-0">
                        {relaysList.map((relay, idx) => {
                          const delayNum = parseFloat(relay?.delay || relay?.Delay) || 0;
                          const maxScale = Math.max(...relaysList.map(r => parseFloat(r?.delay || r?.Delay) || 0), 1);
                          const widthPct = Math.max((delayNum / maxScale) * 100, 2); 
                          
                          // Broad fallbacks to ensure data is caught regardless of backend keys
                          const fromVal = relay?.from || relay?.From || relay?.sender || relay?.hostname || 'Unknown Origin';
                          const byVal = relay?.by || relay?.By || relay?.receiver || 'Unknown Destination';
                          const barHeight = relaysList.length > 5 ? '10px' : '16px';

                          return (
                            <div key={idx} className="d-flex flex-column mb-3">
                               <div className="d-flex justify-content-between align-items-end mb-1" style={{ fontSize: '0.9rem' }}>
                                  <strong className="text-truncate me-3" title={`${fromVal} → ${byVal}`}>
                                    Hop {relay?.hop || relay?.Hop || idx + 1}: <span className="text-muted fw-normal">{fromVal}</span> <i className="bi bi-arrow-right mx-1"></i> <span>{byVal}</span>
                                  </strong>
                                  <span className="pixel-mono fw-bold">{delayNum}s</span>
                               </div>
                               <div className="relay-bar-wrapper">
                                 <div className="relay-bar-fill" style={{ width: `${widthPct}%`, height: barHeight }}></div>
                               </div>
                            </div>
                          );
                        })}
                      </div>

                      <div className="table-responsive scroll-x">
                        <table className="bento-table" style={{ minWidth: '900px' }}>
                          <thead>
                            <tr>
                              <th>Hop</th>
                              <th>Delay</th>
                              <th>From</th>
                              <th>By</th>
                              <th>With</th>
                              <th>Time (UTC)</th>
                              <th>Blacklist</th>
                            </tr>
                          </thead>
                          <tbody>
                            {relaysList.map((relay, idx) => {
                              const rHop = relay?.hop || relay?.Hop || idx + 1;
                              const rDelay = relay?.delay ?? relay?.Delay ?? '-';
                              const rFrom = relay?.from || relay?.From || relay?.sender || '-';
                              const rBy = relay?.by || relay?.By || relay?.receiver || '-';
                              const rWith = relay?.with || relay?.With || relay?.protocol || '-';
                              const rTime = relay?.time || relay?.Time || relay?.date || '-';
                              const rBl = relay?.blacklist || relay?.Blacklist;

                              return (
                                <tr key={idx}>
                                  <td><strong>{rHop}</strong></td>
                                  <td className="pixel-mono">{rDelay}</td>
                                  <td className="pixel-mono scroll-x" style={{ maxWidth: '200px' }}>{rFrom}</td>
                                  <td className="pixel-mono scroll-x" style={{ maxWidth: '200px' }}>{rBy}</td>
                                  <td className="pixel-mono">{rWith}</td>
                                  <td className="pixel-mono text-nowrap">{rTime}</td>
                                  <td>
                                    {rBl ? (
                                      <span className="badge fail-pill border-0">Flagged</span>
                                    ) : (
                                      <span className="badge pass-pill border-0">Clean</span>
                                    )}
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* SECTION 3: SPLIT DASHBOARDS */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-card-checklist"></i> Analysis Breakdown</span>
                  <p className="small mb-3 text-muted">Why the email received its current security status:</p>
                  
                  <div className="d-flex flex-column gap-3">
                    {isSpoofed && evidenceList.map((e, idx) => (
                      <div key={idx} className="bento-list-item fail-pill text-white border-0 py-3">
                        <strong className="d-block mb-1"><i className="bi bi-exclamation-triangle-fill"></i> Spoofing Evidence</strong>
                        <span style={{ fontSize: '0.95rem' }}>{e}</span>
                      </div>
                    ))}

                    <div className="bento-list-item bg-white bg-opacity-50">
                      <strong className="d-block mb-1"><i className="bi bi-shield-check"></i> SPF Analysis ({auth.spf || 'NONE'})</strong>
                      <p className="mb-2 fs-6">{getAuthExplanation('SPF', auth.spf)}</p>
                      {auth.spf_basis && <div className="header-content-box pixel-mono scroll-x">{auth.spf_basis}</div>}
                    </div>

                    <div className="bento-list-item bg-white bg-opacity-50">
                      <strong className="d-block mb-1"><i className="bi bi-key"></i> DKIM Analysis ({auth.dkim || 'NONE'})</strong>
                      <p className="mb-2 fs-6">{getAuthExplanation('DKIM', auth.dkim)}</p>
                      {auth.dkim_basis && <div className="header-content-box pixel-mono scroll-x">{auth.dkim_basis}</div>}
                    </div>

                    <div className="bento-list-item bg-white bg-opacity-50">
                      <strong className="d-block mb-1"><i className="bi bi-diagram-3"></i> DMARC Analysis ({auth.dmarc || 'NONE'})</strong>
                      <p className="mb-2 fs-6">{getAuthExplanation('DMARC', auth.dmarc)}</p>
                      {auth.dmarc_basis && <div className="header-content-box pixel-mono scroll-x">{auth.dmarc_basis}</div>}
                    </div>
                  </div>
                </div>
              </div>

              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-link-45deg"></i> Embedded Links Analysis</span>
                  {urlList.length === 0 ? (
                    <div className="text-muted text-center mt-4 p-4 border border-secondary rounded-3 border-opacity-25">No external links found in the email body.</div>
                  ) : (
                    <div className="d-flex flex-column gap-2">
                      {urlList.map((item, idx) => {
                        const vt = item?.vt_reputation || {};
                        const isMalicious = vt.malicious > 0;
                        return (
                          <div key={idx} onClick={() => openLinkModal(item)} className="bento-list-item bg-white bg-opacity-50 scroll-x d-flex justify-content-between align-items-center gap-3 pointer-hover" title="Click for more details">
                            <span className="text-nowrap">{item?.domain || item?.url || 'N/A'}</span>
                            
                            {vt.status === 'scored' ? (
                              isMalicious ? (
                                <span className="bento-pill fail-pill text-nowrap border-0">
                                  {vt.malicious} MALICIOUS <i className="bi bi-arrows-angle-expand ms-1 opacity-50"></i>
                                </span>
                              ) : (
                                <span className="bento-pill safe-card text-nowrap text-white border-0">
                                  <i className="bi bi-check-circle"></i> SAFE <i className="bi bi-arrows-angle-expand ms-1 opacity-50"></i>
                                </span>
                              )
                            ) : (
                              <span className="bento-pill outline-pill text-nowrap">UNSCORED</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* SECTION 4: REMAINING RAW HEADERS */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4"><i className="bi bi-braces"></i> Technical Raw Headers</span>
                    <button className="help-icon" onClick={() => openEduModal('headers')}><i className="bi bi-question-lg"></i></button>
                  </div>
                  
                  <div className="row g-3">
                    {remainingHeaders.map((hdr, idx) => (
                      <div key={idx} className="col-md-6 col-lg-4">
                        <div className="bento-list-item h-100 bg-white bg-opacity-50">
                          <strong className="d-block mb-1 text-truncate" title={hdr.name}>{hdr.name}</strong>
                          <div className="header-content-box pixel-mono scroll-x">
                            {hdr.value}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* MODAL SYSTEM */}
        {modalState.isOpen && (
          <div className="bento-modal-backdrop" onClick={() => setModalState({ ...modalState, isOpen: false })}>
            <div className="bento-card p-4 modal-content-bento" onClick={(e) => e.stopPropagation()}>
              <div className="d-flex justify-content-between align-items-center mb-4 border-bottom border-dark border-opacity-10 pb-3">
                <h4 className="handwriting-text m-0 fs-3">{modalState.title}</h4>
                <button onClick={() => setModalState({ ...modalState, isOpen: false })} className="bento-btn bento-btn-icon"><i className="bi bi-x-lg"></i></button>
              </div>
              <div className="modal-body-content" style={{ fontSize: '1.1rem' }}>
                {modalState.body}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

export default App;