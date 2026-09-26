import { useState } from 'react';
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

const extractRelayField = (relay, keys) => {
  if (!relay) return '-';
  for (let key of keys) {
    let val = relay[key];
    if (val !== undefined && val !== null && val !== '') {
      if (typeof val === 'object') {
        try { return Array.isArray(val) ? val.join(', ') : JSON.stringify(val); } 
        catch (e) { return String(val); }
      }
      return String(val);
    }
  }
  return '-';
};

function App() {
  const [viewState, setViewState] = useState('upload'); 
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [modalState, setModalState] = useState({ isOpen: false, title: '', body: null });

  const MAX_CLIENT_FILE_SIZE = 10 * 1024 * 1024; // 10MB, mirrors backend limit

  const validateFile = (file) => {
    if (!file) return 'Please choose a file to scan.';

    const nameLower = file.name.toLowerCase();
    if (!nameLower.endsWith('.eml')) {
      return 'Invalid file type. Only .eml files are accepted.';
    }
    if (file.size === 0) {
      return 'The selected file is empty.';
    }
    if (file.size > MAX_CLIENT_FILE_SIZE) {
      return 'File size exceeds the 10MB limit.';
    }
    return null;
  };

  const handleFileUpload = async (event) => {
    event.preventDefault();
    const file = event.target.fileInput.files[0];

    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      return;
    }

    setViewState('scanning');
    setError(null);
    setUploadProgress(0);

    const progressInterval = setInterval(() => {
      setUploadProgress(prev => (prev >= 90 ? 90 : prev + 15));
    }, 400);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/index', { method: 'POST', body: formData });
      if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.detail || 'Failed to scan file');
      }
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
          <div className="bento-list-item bg-white bg-opacity-25">
            <h5 className="handwriting-text fw-bold m-0"><i className="bi bi-exclamation-diamond"></i> Disclaimer</h5>
            <p className="m-0 fs-6">Disclaimer: The information displayed in this system, including all outputs, results, analyses, and recommendations, may not always be complete, accurate, current, or free from errors. Users are encouraged to independently verify any information before relying on it for academic, professional, legal, financial, technical, or other important purposes. By using this information, you acknowledge that you do so at your own risk, and the provider assumes no responsibility or liability for any decisions, actions, losses, or damages resulting from its use.</p>
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
  const maliciousUrls = urlList.filter(item => (item?.vt_reputation?.malicious || 0) > 0);
  const hasMaliciousLinks = maliciousUrls.length > 0;
  const isCompromised = isSpoofed || hasMaliciousLinks;

  const authResultsHeader = headersList.find(h => h.name.toLowerCase() === 'authentication-results')?.value;
  const receivedSpfHeader = headersList.find(h => h.name.toLowerCase() === 'received-spf')?.value;
  const dkimSigHeader = headersList.find(h => h.name.toLowerCase() === 'dkim-signature')?.value;

  const importantKeys = ['Subject', 'From', 'To', 'Date'];
  const importantHeaders = importantKeys.map(key => {
    const found = headersList.find(h => h.name.toLowerCase() === key.toLowerCase());
    return { name: key, value: found ? found.value : 'N/A' };
  });
  const remainingHeaders = headersList.filter(
    h => !importantKeys.some(key => key.toLowerCase() === h.name.toLowerCase())
  );

  return (
    <div className="app-wrapper">
      
      {viewState !== 'results' && (
        <button onClick={openAboutModal} className="bento-btn about-fab-btn">
          <i className="bi bi-info-circle-fill me-2"></i> About
        </button>
      )}

      <div className="container py-5 d-flex flex-column" style={{ maxWidth: '1000px', minHeight: '100vh' }}>
        
        {/* VIEW 1: UPLOAD SCREEN */}
        {viewState !== 'results' && (
          <div className="d-flex flex-column align-items-center justify-content-center w-100" style={{ flexGrow: 1 }}>
            
            <div className="bento-card main-scanner-card p-5 text-center w-100" style={{ maxWidth: '600px' }}>
              <div className="bento-pill dark-pill mx-auto mb-3" style={{ width: 'fit-content' }}>PHIZER OS v2.0</div>
              <h1 className="bento-header mb-4">Email Scanner</h1>
              
              {viewState === 'upload' && (
                <form onSubmit={handleFileUpload}>
                  <div className="mb-4">
                    <input
                      type="file"
                      name="fileInput"
                      className="bento-input form-control p-3"
                      accept=".eml"
                      required
                      onChange={(e) => {
                        const file = e.target.files[0];
                        const validationError = validateFile(file);
                        if (validationError) {
                          setError(validationError);
                          e.target.value = '';
                        } else {
                          setError(null);
                        }
                      }}
                    />
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
              
              {/* Security Status Card */}
              <div className="col-md-5">
                <div className={`bento-card h-100 p-4 text-center d-flex flex-column justify-content-center ${!isCompromised ? 'safe-card' : 'fail-card'}`}>
                  <div className="handwriting-text mb-2 text-white opacity-75">Security Status</div>
                  {isCompromised ? (
                    <>
                      <div className="digital-text large-digital text-white mb-3">FAILED</div>
                      <div className="d-flex flex-column gap-2 align-items-center">
                        {isSpoofed && (
                          <div className="bento-pill bg-white text-dark border-0"><i className="bi bi-shield-x text-danger"></i> Spoofing Detected</div>
                        )}
                        {hasMaliciousLinks && (
                          <div className="bento-pill bg-white text-dark border-0"><i className="bi bi-bug-fill text-danger"></i> {maliciousUrls.length} Malicious Link{maliciousUrls.length > 1 ? 's' : ''} Found</div>
                        )}
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="digital-text large-digital text-white mb-3">PASSED</div>
                      <div className="bento-pill mx-auto bg-white text-dark border-0"><i className="bi bi-shield-check text-success"></i> Sender Verified</div>
                    </>
                  )}
                </div>
              </div>

              {/* Authentication Records Card */}
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

              {/* Email Details Card */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-envelope-paper"></i> Important Email Details</span>
                  <div className="row g-3">
                    {importantHeaders.map((hdr, idx) => (
                      <div key={idx} className="col-md-6">
                        <div className="bento-list-item h-100 bg-white bg-opacity-25">
                          <strong className="d-block mb-1 opacity-75 small text-uppercase">{hdr.name}</strong>
                          <div className="pixel-mono fs-6 scroll-x fw-bold">{hdr.value}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Email Relay Hops Card */}
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
                      <div className="bento-list-item p-4 mb-4 bg-white bg-opacity-25 border-0">
                        {relaysList.map((relay, idx) => {
                          let rDelay = 0;
                          let fromVal = 'Unknown Origin';
                          let byVal = 'Unknown Destination';

                          if (typeof relay === 'string') {
                            fromVal = 'Raw Header Extracted';
                            byVal = '...';
                          } else {
                            rDelay = extractRelayField(relay, ['delay', 'Delay', 'delay_in_seconds', 'duration']);
                            const rFrom = extractRelayField(relay, ['from', 'From', 'src', 'Src', 'sender', 'Sender', 'received_from', 'origin']);
                            const rBy = extractRelayField(relay, ['by', 'By', 'receiver', 'Receiver', 'dest', 'destination']);
                            fromVal = rFrom !== '-' ? rFrom : 'Unknown Origin';
                            byVal = rBy !== '-' ? rBy : 'Unknown Destination';
                          }

                          const delayNum = parseFloat(rDelay) || 0;
                          const maxScale = Math.max(...relaysList.map(r => parseFloat(extractRelayField(r, ['delay', 'Delay'])) || 0), 1);
                          const widthPct = Math.max((delayNum / maxScale) * 100, 2); 
                          const barHeight = relaysList.length > 5 ? '10px' : '16px';

                          return (
                            <div key={idx} className="d-flex flex-column mb-3">
                               <div className="d-flex justify-content-between align-items-end mb-1" style={{ fontSize: '0.9rem' }}>
                                  <strong className="text-truncate me-3" title={`${fromVal} → ${byVal}`}>
                                    Hop {idx + 1}: <span className="opacity-75 fw-normal">{fromVal}</span> <i className="bi bi-arrow-right mx-1"></i> <span>{byVal}</span>
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
                        <table className="bento-table" style={{ minWidth: '900px', tableLayout: 'fixed' }}>
                          <colgroup>
                            <col style={{ width: '6%' }} />
                            <col style={{ width: '30%' }} />
                            <col style={{ width: '30%' }} />
                            <col style={{ width: '19%' }} />
                            <col style={{ width: '15%' }} />
                          </colgroup>
                          <thead>
                            <tr>
                              <th>Hop</th>
                              <th>From (Source)</th>
                              <th>By (Destination)</th>
                              <th>With / Protocol</th>
                              <th>Time (UTC)</th>
                            </tr>
                          </thead>
                          <tbody>
                            {relaysList.map((relay, idx) => {
                              let rFrom, rBy, rWith, rTime;
                              
                              if (typeof relay === 'string') {
                                rFrom = relay; 
                                rBy = '-';
                                rWith = '-';
                                rTime = '-';
                              } else {
                                rFrom = extractRelayField(relay, ['from', 'From', 'src', 'Src', 'sender', 'Sender', 'received_from', 'raw', 'string', 'header']);
                                rBy = extractRelayField(relay, ['by', 'By', 'receiver', 'Receiver', 'dest', 'destination']);
                                rWith = extractRelayField(relay, ['with', 'With', 'protocol', 'Protocol', 'via']);
                                rTime = extractRelayField(relay, ['time', 'Time', 'date', 'Date', 'timestamp']);
                              }

                              return (
                                <tr key={idx}>
                                  <td><strong>{idx + 1}</strong></td>
                                  <td className="pixel-mono scroll-x fw-bold">{rFrom}</td>
                                  <td className="pixel-mono scroll-x fw-bold">{rBy}</td>
                                  <td className="pixel-mono scroll-x">{rWith}</td>
                                  <td className="pixel-mono scroll-x text-nowrap">{rTime}</td>
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

              {/* Analysis Breakdown with Dropdowns */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-card-checklist"></i> Analysis Breakdown</span>
                  <p className="small mb-3 opacity-75">Why the email received its current security status:</p>
                  
                  <div className="d-flex flex-column gap-3">
                    {isSpoofed && evidenceList.map((e, idx) => (
                      <div key={idx} className="bento-list-item fail-pill text-white border-0 py-3">
                        <strong className="d-block mb-1"><i className="bi bi-exclamation-triangle-fill"></i> Spoofing Evidence</strong>
                        <span style={{ fontSize: '0.95rem' }}>{e}</span>
                      </div>
                    ))}

                    {hasMaliciousLinks && (
                      <div className="bento-list-item fail-pill text-white border-0 py-3">
                        <strong className="d-block mb-1"><i className="bi bi-bug-fill"></i> Malicious Link Evidence</strong>
                        <span style={{ fontSize: '0.95rem' }}>
                          {maliciousUrls.length} embedded link{maliciousUrls.length > 1 ? 's were' : ' was'} flagged as malicious by VirusTotal (see Embedded Links Analysis below).
                        </span>
                      </div>
                    )}

                    <div className="bento-list-item bg-white bg-opacity-25">
                      <strong className="d-block mb-1"><i className="bi bi-shield-check"></i> SPF Analysis ({auth.spf || 'NONE'})</strong>
                      <p className="mb-2 fs-6">{getAuthExplanation('SPF', auth.spf)}</p>
                      <details className="mt-3 pt-2 border-top border-dark border-opacity-25">
                        <summary className="small opacity-75 fw-bold mb-1 pointer-hover text-decoration-underline"><i className="bi bi-search"></i> Show Header Evidence</summary>
                        <div className="header-content-box pixel-mono fw-bold">
                          {auth.spf_basis || receivedSpfHeader || authResultsHeader || 'No explicit SPF header evidence found.'}
                        </div>
                      </details>
                    </div>

                    <div className="bento-list-item bg-white bg-opacity-25">
                      <strong className="d-block mb-1"><i className="bi bi-key"></i> DKIM Analysis ({auth.dkim || 'NONE'})</strong>
                      <p className="mb-2 fs-6">{getAuthExplanation('DKIM', auth.dkim)}</p>
                      <details className="mt-3 pt-2 border-top border-dark border-opacity-25">
                        <summary className="small opacity-75 fw-bold mb-1 pointer-hover text-decoration-underline"><i className="bi bi-search"></i> Show Header Evidence</summary>
                        <div className="header-content-box pixel-mono fw-bold">
                          {auth.dkim_basis || dkimSigHeader || authResultsHeader || 'No explicit DKIM header evidence found.'}
                        </div>
                      </details>
                    </div>

                    <div className="bento-list-item bg-white bg-opacity-25">
                      <strong className="d-block mb-1"><i className="bi bi-diagram-3"></i> DMARC Analysis ({auth.dmarc || 'NONE'})</strong>
                      <p className="mb-2 fs-6">{getAuthExplanation('DMARC', auth.dmarc)}</p>
                      <details className="mt-3 pt-2 border-top border-dark border-opacity-25">
                        <summary className="small opacity-75 fw-bold mb-1 pointer-hover text-decoration-underline"><i className="bi bi-search"></i> Show Header Evidence</summary>
                        <div className="header-content-box pixel-mono fw-bold">
                          {auth.dmarc_basis || authResultsHeader || 'No explicit DMARC header evidence found.'}
                        </div>
                      </details>
                    </div>
                  </div>
                </div>
              </div>

              {/* Embedded Links Card */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-link-45deg"></i> Embedded Links Analysis</span>
                  {urlList.length === 0 ? (
                    <div className="text-center mt-4 p-4 border border-dark rounded-3 border-opacity-25 opacity-75">No external links found in the email body.</div>
                  ) : (
                    <div className="d-flex flex-column gap-2">
                      {urlList.map((item, idx) => {
                        const vt = item?.vt_reputation || {};
                        const isMalicious = vt.malicious > 0;
                        return (
                          <div key={idx} onClick={() => openLinkModal(item)} className="bento-list-item bg-white bg-opacity-25 scroll-x d-flex justify-content-between align-items-center gap-3 pointer-hover" title="Click for more details">
                            <span className="text-nowrap fw-bold">{item?.domain || item?.url || 'N/A'}</span>
                            
                            {vt.status === 'scored' ? (
                              isMalicious ? (
                                <span className="bento-pill fail-pill text-nowrap border-0 shadow-sm">
                                  {vt.malicious} MALICIOUS <i className="bi bi-arrows-angle-expand ms-1 opacity-50"></i>
                                </span>
                              ) : (
                                <span className="bento-pill safe-card text-nowrap text-white border-0 shadow-sm">
                                  <i className="bi bi-check-circle"></i> SAFE <i className="bi bi-arrows-angle-expand ms-1 opacity-50"></i>
                                </span>
                              )
                            ) : (
                              <span className="bento-pill outline-pill text-nowrap shadow-sm">UNSCORED</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* Raw Headers Card */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4"><i className="bi bi-braces"></i> Technical Raw Headers</span>
                    <button className="help-icon" onClick={() => openEduModal('headers')}><i className="bi bi-question-lg"></i></button>
                  </div>
                  
                  <div className="row g-3">
                    {remainingHeaders.map((hdr, idx) => (
                      <div key={idx} className="col-md-6 col-lg-4">
                        <div className="bento-list-item h-100 bg-white bg-opacity-25">
                          <strong className="d-block mb-1 text-truncate opacity-75" title={hdr.name}>{hdr.name}</strong>
                          <div className="header-content-box pixel-mono scroll-x fw-bold">
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

        {/* Dynamic Educational / Link Modal */}
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