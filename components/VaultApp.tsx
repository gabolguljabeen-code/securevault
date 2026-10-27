"use client";

import Link from "next/link";
import type { MouseEvent } from "react";
import { useRef, useState } from "react";
import { Activity, ArrowLeft, ArrowRight, BookOpen, Check, ChevronRight, CircleHelp, Clock3, FileArchive, FileKey2, FileLock2, Fingerprint, Info, KeyRound, LockKeyhole, Shield, ShieldCheck, Sparkles, Trash2, UnlockKeyhole, Upload, X } from "lucide-react";
import { decryptBytes, encryptBytes, FILE_SIZE_LIMIT, formatBytes, sanitizeFilename, VaultError } from "@/lib/crypto";

type Mode = "encrypt" | "decrypt";
type Operation = { id: string; filename: string; mode: Mode; at: string; size: number };

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.rel = "noopener";
  document.body.append(anchor); anchor.click(); anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function passwordRating(value: string) {
  if (!value) return { label: "No password", width: "0%", color: "transparent" };
  let score = 0;
  if (value.length >= 12) score++;
  if (value.length >= 16) score++;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
  if (/\d/.test(value)) score++;
  if (/[^a-zA-Z0-9]/.test(value)) score++;
  const levels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Strong"];
  const colors = ["#e77b6b", "#e77b6b", "#e8b35f", "#a7c57a", "#63c5b5", "#63c5b5"];
  return { label: levels[score], width: `${Math.max(15, score * 20)}%`, color: colors[score] };
}

export default function VaultApp() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [history, setHistory] = useState<Operation[]>([]);
  const [tab, setTab] = useState<"vault" | "learn">("vault");
  const inputRef = useRef<HTMLInputElement>(null);
  const rating = passwordRating(password);

  function chooseMode(next: Mode) {
    if (busy) return;
    setMode(next); setFile(null); setPassword(""); setConfirm(""); setError(""); setSuccess("");
    if (inputRef.current) inputRef.current.value = "";
  }
  function chooseFile(next: File | undefined) {
    setError(""); setSuccess("");
    if (!next) return;
    if (next.size > FILE_SIZE_LIMIT) { setFile(null); setError(`This file is ${formatBytes(next.size)}. The current limit is ${formatBytes(FILE_SIZE_LIMIT)}.`); return; }
    if (next.size === 0 && mode === "decrypt") { setFile(null); setError("This file is empty and cannot be a valid encrypted vault file."); return; }
    if (mode === "decrypt" && !next.name.toLowerCase().endsWith(".svault")) { setFile(null); setError("Choose a SecureVault file ending in .svault."); return; }
    setFile(next);
  }
  async function processFile() {
    setError(""); setSuccess("");
    if (!file) { setError("Choose a file to continue."); return; }
    if (password.length < 12 && mode === "encrypt") { setError("Use a password with at least 12 characters. A longer unique passphrase is better."); return; }
    if (mode === "encrypt" && password !== confirm) { setError("The passwords do not match."); return; }
    if (!password) { setError("Enter your password to continue."); return; }
    setBusy(true);
    let bytes: Uint8Array | null = null;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      if (mode === "encrypt") {
        const vault = await encryptBytes(bytes, file.name, file.type, password);
        const vaultName = `${sanitizeFilename(file.name.replace(/\.svault$/i, "file"))}.svault`;
        try { download(new Blob([vault.buffer.slice(vault.byteOffset, vault.byteOffset + vault.byteLength) as ArrayBuffer], { type: "application/octet-stream" }), vaultName); }
        finally { vault.fill(0); }
        setSuccess(`Encrypted ${file.name} with AES-256-GCM. Your .svault download is ready.`);
        setHistory((items) => [{ id: crypto.randomUUID(), filename: file.name, mode, at: new Date().toLocaleString(), size: file.size }, ...items]);
      } else {
        const result = await decryptBytes(bytes, password);
        try { download(new Blob([result.data.buffer.slice(result.data.byteOffset, result.data.byteOffset + result.data.byteLength) as ArrayBuffer], { type: result.mimeType }), result.filename); }
        finally { result.data.fill(0); }
        setSuccess(`Authentication succeeded. ${result.filename} has been downloaded.`);
        setHistory((items) => [{ id: crypto.randomUUID(), filename: result.filename, mode, at: new Date().toLocaleString(), size: file.size }, ...items]);
      }
      setPassword(""); setConfirm("");
    } catch (reason) {
      setError(reason instanceof VaultError ? reason.message : "Processing failed. Your file may be too large for the available browser memory.");
    } finally {
      bytes?.fill(0); bytes = null; setFile(null); if (inputRef.current) inputRef.current.value = ""; setPassword(""); setConfirm(""); setShowPassword(false); setBusy(false);
    }
  }

  return <div className="shell">
    <aside className="sidebar">
      <Link href="/" className="brand" onClick={(event: MouseEvent<HTMLAnchorElement>) => { event.preventDefault(); setTab("vault"); }}><span className="brand-icon"><ShieldCheck size={21} /></span><span>secure<span className="brand-light">vault</span></span></Link>
      <div className="side-label">WORKSPACE</div>
      <button className={`nav-link ${tab === "vault" ? "active" : ""}`} onClick={() => setTab("vault")}><Activity size={17} /> Overview</button>
      <button className="nav-link" onClick={() => { setTab("vault"); document.getElementById("workspace")?.scrollIntoView({ behavior: "smooth" }); }}><FileLock2 size={17} /> File encryption</button>
      <button className={`nav-link ${tab === "learn" ? "active" : ""}`} onClick={() => setTab("learn")}><BookOpen size={17} /> Learn security</button>
      <div className="side-spacer" />
      <div className="local-card"><span className="local-dot" /><div><strong>Local processing</strong><small>Your files stay on this device</small></div></div>
      <div className="sidebar-bottom"><Shield size={15} /> Built for privacy by design</div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="mobile-brand"><span className="brand-icon"><ShieldCheck size={19} /></span> SecureVault</div><div className="breadcrumb">Workspace <ChevronRight size={14} /> <span>{tab === "vault" ? "Overview" : "Security guide"}</span></div><div className="top-status"><span className="status-pip" /> Browser protected <span className="top-divider" /><span className="version-tag">V 1.0</span></div></header>
      {tab === "vault" ? <>
        <div className="content">
          <section className="welcome-row"><div><div className="eyebrow"><span className="eyebrow-line" /> PRIVATE BY DESIGN</div><h1>Your files.<br /><span>Your key.</span></h1><p className="intro">A calm, secure space to protect sensitive files. Encryption happens right here in your browser, so your data never leaves your device.</p></div><div className="hero-art" aria-hidden="true"><div className="art-ring ring-one"/><div className="art-ring ring-two"/><div className="art-orbit"><span /><span /><span /></div><div className="art-shield"><ShieldCheck size={44} strokeWidth={1.4} /></div><div className="art-caption"><span className="status-pip"/> AES-256 ACTIVE</div></div></section>
          <section className="action-grid" aria-label="Choose an action"><button className={`action-card ${mode === "encrypt" ? "selected" : ""}`} onClick={() => chooseMode("encrypt")}><span className="action-icon amber"><LockKeyhole size={20}/></span><span className="action-copy"><strong>Encrypt a file</strong><small>Lock a file with your password</small></span><ArrowRight size={17} className="action-arrow"/></button><button className={`action-card ${mode === "decrypt" ? "selected" : ""}`} onClick={() => chooseMode("decrypt")}><span className="action-icon teal"><UnlockKeyhole size={20}/></span><span className="action-copy"><strong>Decrypt a file</strong><small>Restore a SecureVault file</small></span><ArrowRight size={17} className="action-arrow"/></button></section>
          <section className="workspace" id="workspace"><div className="section-heading"><div><div className="section-kicker">FILE WORKSPACE</div><h2>{mode === "encrypt" ? "Create an encrypted file" : "Unlock an encrypted file"}</h2><p>{mode === "encrypt" ? "Choose a file and create a private, authenticated copy." : "Select a .svault file and enter the original password."}</p></div><span className="secure-badge"><Fingerprint size={14}/> END-TO-END LOCAL</span></div>
            <div className="workspace-grid"><div className="form-column"><div className={`drop-zone ${dragging ? "dragging" : ""} ${file ? "has-file" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); chooseFile(e.dataTransfer.files[0]); }} onClick={() => inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") inputRef.current?.click(); }} aria-label="Choose or drop a file">
              <input ref={inputRef} type="file" hidden onChange={(e) => chooseFile(e.target.files?.[0])} />
              {file ? <><span className="drop-icon ready"><FileArchive size={22}/></span><div className="file-info"><strong>{file.name}</strong><small>{formatBytes(file.size)} <span>·</span> {file.type || "Unknown type"}</small></div><button className="remove-file" aria-label="Remove file" onClick={(e) => { e.stopPropagation(); setFile(null); if (inputRef.current) inputRef.current.value = ""; }}><X size={16}/></button></> : <><span className="drop-icon"><Upload size={21}/></span><strong>Drop your file here</strong><span className="drop-sub">or <span className="browse">browse your device</span></span><small className="file-limit">Up to {formatBytes(FILE_SIZE_LIMIT)} · {mode === "decrypt" ? ".svault files" : "Any file type"}</small></>}
            </div>
            <div className="password-block"><label htmlFor="password">{mode === "encrypt" ? "Create a password" : "Vault password"}</label><div className="input-wrap"><KeyRound size={16}/><input id="password" type={showPassword ? "text" : "password"} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder={mode === "encrypt" ? "At least 12 characters" : "Enter the original password"} /><button className="show-toggle" type="button" onClick={() => setShowPassword((value) => !value)}>{showPassword ? "Hide" : "Show"}</button></div>
              {mode === "encrypt" && <><div className="strength-row"><span>Password guidance</span><span style={{ color: rating.color }}>{rating.label}</span></div><div className="strength-track"><span style={{ width: rating.width, background: rating.color }}/></div><div className="hint"><Info size={13}/> Use a long, unique passphrase. This guidance is not a security guarantee.</div><label htmlFor="confirm" className="confirm-label">Confirm password</label><div className="input-wrap"><KeyRound size={16}/><input id="confirm" type={showPassword ? "text" : "password"} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Enter it again" /></div></>}
            </div>
            {error && <div className="message error" role="alert"><CircleHelp size={16}/><span>{error}</span></div>}{success && <div className="message success" role="status"><Check size={16}/><span>{success}</span></div>}
            <button className="primary-button" onClick={processFile} disabled={busy || !file}>{busy ? <><span className="spinner"/> {mode === "encrypt" ? "Encrypting locally…" : "Authenticating & decrypting…"}</> : mode === "encrypt" ? <><LockKeyhole size={17}/> Encrypt file <ArrowRight size={16}/></> : <><UnlockKeyhole size={17}/> Decrypt file <ArrowRight size={16}/></>}</button>
            <p className="processing-note"><ShieldCheck size={14}/> Your file and password are processed in this browser only.</p>
          </div>
          <aside className="method-column"><div className="method-title"><span className="mini-shield"><Shield size={15}/></span><div><strong>Protection details</strong><small>Cryptography in use</small></div></div><div className="method-row"><span className="method-symbol">01</span><div><strong>AES-256-GCM</strong><small>Authenticated file encryption</small></div><Check size={15} className="check-teal"/></div><div className="method-row"><span className="method-symbol">02</span><div><strong>PBKDF2 · SHA-256</strong><small>600,000 password iterations</small></div><Check size={15} className="check-teal"/></div><div className="method-row"><span className="method-symbol">03</span><div><strong>Fresh salt + nonce</strong><small>Randomly generated per file</small></div><Check size={15} className="check-teal"/></div><div className="method-note"><Info size={14}/><span>Keep your password safe. There is no password reset; a lost password means the file cannot be recovered.</span></div></aside></div>
          </section>
          <section className="explain-grid"><article className="explain-card"><span className="explain-icon"><FileKey2 size={18}/></span><div><h3>Confidentiality</h3><p>Encryption scrambles readable data so only someone with the right key can read it.</p></div></article><article className="explain-card"><span className="explain-icon"><ShieldCheck size={18}/></span><div><h3>Integrity</h3><p>Authentication detects changes. A wrong password or altered file will fail to open.</p></div></article><article className="explain-card"><span className="explain-icon"><Sparkles size={18}/></span><div><h3>Your key, your control</h3><p>Your password derives a unique key. SecureVault never stores or transmits it.</p></div></article></section>
          <section className="history-section"><div className="history-heading"><div><div className="section-kicker">THIS PAGE SESSION ONLY</div><h2>Recent activity</h2></div>{history.length > 0 && <button className="clear-button" onClick={() => setHistory([])}><Trash2 size={14}/> Clear history</button>}</div>{history.length === 0 ? <div className="empty-history"><span className="empty-icon"><Clock3 size={18}/></span><div><strong>No activity yet</strong><small>Completed operations will appear here until this page session ends.</small></div></div> : <div className="history-list">{history.map((item) => <div className="history-item" key={item.id}><span className={`history-icon ${item.mode}`} >{item.mode === "encrypt" ? <LockKeyhole size={15}/> : <UnlockKeyhole size={15}/>}</span><span className="history-name"><strong>{item.filename}</strong><small>{item.mode === "encrypt" ? "Encrypted" : "Decrypted"} · AES-256-GCM</small></span><span className="history-time">{item.at}</span><span className="history-size">{formatBytes(item.size)}</span></div>)}</div>}</section>
          <section className="security-callout"><span className="callout-icon"><Shield size={19}/></span><div><strong>Built for local privacy. Browser limits still apply.</strong><p>Local encryption cannot protect against malware, compromised devices, malicious extensions, or a compromised website deployment. Use a trusted, updated device and keep a separate backup of important files.</p></div><button onClick={() => setTab("learn")} aria-label="Read security limitations"><ArrowRight size={17}/></button></section>
        </div>
      </> : <LearnPage onBack={() => setTab("vault")} />}
      <footer className="footer"><span>© 2026 SecureVault <span className="footer-dot">·</span> Information Security project</span><span><ShieldCheck size={13}/> Files stay in your browser</span></footer>
    </main>
  </div>;
}

function LearnPage({ onBack }: { onBack: () => void }) {
  return <div className="content learn-content"><button className="back-link" onClick={onBack}><ArrowLeft size={15}/> Back to workspace</button><div className="eyebrow"><span className="eyebrow-line"/> SECURITY, MADE CLEAR</div><h1 className="learn-title">A little more about<br/><span>staying secure.</span></h1><p className="learn-intro">A student-friendly guide to the ideas behind SecureVault and the limits of browser-based protection.</p>
    <section className="learn-section"><div className="section-kicker">THE FOUNDATIONS</div><h2>What is information security?</h2><p>Information security is the practice of protecting information and the systems that handle it from unauthorized access, changes, or disruption. The CIA triad is a useful way to remember its three goals:</p><div className="cia-grid"><article><span>C</span><h3>Confidentiality</h3><p>Only authorized people can see the information. Encryption helps protect confidentiality.</p></article><article><span>I</span><h3>Integrity</h3><p>Information stays accurate and changes can be detected. AES-GCM provides authentication checks.</p></article><article><span>A</span><h3>Availability</h3><p>Authorized people can access information when they need it. Backups and reliable systems help.</p></article></div></section>
    <section className="learn-section"><div className="section-kicker">THE CRYPTOGRAPHY</div><h2>How SecureVault protects a file</h2><div className="learn-steps"><article><span className="step-no">01</span><div><h3>Your password becomes a key</h3><p>PBKDF2 repeatedly combines your password with a random salt using SHA-256. 600,000 iterations make password guessing more expensive. The salt is stored with the encrypted file; it is not a secret.</p></div></article><article><span className="step-no">02</span><div><h3>AES-GCM encrypts and authenticates</h3><p>AES with a 256-bit key transforms the file bytes into ciphertext. GCM adds an authentication tag, so the app can detect a wrong key or changed data before releasing plaintext.</p></div></article><article><span className="step-no">03</span><div><h3>A fresh nonce protects each operation</h3><p>The 96-bit nonce is a unique random value used once with the key. Reusing a nonce with AES-GCM can seriously weaken security, so SecureVault generates a fresh one for every encryption.</p></div></article><article><span className="step-no">04</span><div><h3>Authenticated data is released</h3><p>On decryption, the same password and stored salt derive the same key. If the password is wrong, or ciphertext or header data changed, AES-GCM authentication fails and the app does not offer a decrypted download.</p></div></article></div></section>
    <section className="learn-section"><div className="section-kicker">USE IT RESPONSIBLY</div><h2>Encryption and hashing are different</h2><p>Encryption is reversible with the correct key, so it can protect files that you need to open later. Hashing is designed as a one-way fingerprint: it helps compare or verify data, but it is not a way to recover the original. Passwords should be hashed for login systems; file encryption uses a key so the owner can decrypt later.</p><div className="real-world"><div><FileLock2 size={19}/><h3>Where file encryption is used</h3><p>Protecting laptop backups, confidential documents, archived records, and files moved between people or systems. Encryption helps reduce exposure if storage or transport is accessed by someone else.</p></div><div><CircleHelp size={19}/><h3>What it cannot do</h3><p>It cannot make an infected device safe, protect files after you decrypt them, recover a forgotten password, or guarantee that a website delivering code has not been compromised.</p></div></div></section>
    <div className="learn-notice"><Info size={17}/><p><strong>Keep an independent backup.</strong> SecureVault has no recovery service and a lost password cannot be reset. Browser memory use can also limit the size of files your device can process.</p></div>
    <button className="primary-button learn-cta" onClick={onBack}><ArrowLeft size={16}/> Return to your workspace</button>
  </div>;
}
