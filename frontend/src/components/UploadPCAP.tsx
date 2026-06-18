import React, { useState, useRef } from 'react';
import { Upload, File, AlertCircle, CheckCircle2 } from 'lucide-react';
import { packetService } from '../services/api';

interface UploadPCAPProps {
  onUploadSuccess: (session: any) => void;
}

const UploadPCAP: React.FC<UploadPCAPProps> = ({ onUploadSuccess }) => {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const processFile = async (selectedFile: File) => {
    const name = selectedFile.name.toLowerCase();
    if (!name.endsWith('.pcap') && !name.endsWith('.pcapng') && !name.endsWith('.cap')) {
      setStatus('error');
      setErrorMessage('Unsupported file format. Please upload .pcap, .pcapng, or .cap files.');
      return;
    }

    setFile(selectedFile);
    setStatus('uploading');
    setErrorMessage('');

    try {
      const session = await packetService.uploadPcap(selectedFile);
      setStatus('success');
      onUploadSuccess(session);
      setTimeout(() => {
        setStatus('idle');
        setFile(null);
      }, 3000);
    } catch (err: any) {
      console.error(err);
      setStatus('error');
      setErrorMessage(err.response?.data?.detail || 'Failed to upload PCAP file. Please try again.');
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const onButtonClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="glass-card p-6 w-full">
      <h3 className="text-lg font-semibold mb-4 text-white">Ingest Packet Capture</h3>
      
      <div 
        className={`relative border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center transition-all duration-300 ${
          dragActive 
            ? 'border-blue-500 bg-blue-500/5' 
            : status === 'uploading'
              ? 'border-indigo-500 bg-indigo-500/5'
              : 'border-slate-800 hover:border-slate-700 bg-slate-900/20'
        }`}
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept=".pcap,.pcapng,.cap"
          onChange={handleChange}
          disabled={status === 'uploading'}
        />

        {status === 'idle' && (
          <>
            <div className="w-12 h-12 rounded-lg bg-blue-600/10 text-blue-500 flex items-center justify-center mb-4 border border-blue-500/20">
              <Upload size={22} />
            </div>
            <p className="text-sm font-medium text-slate-200 text-center">
              Drag & drop PCAP file here, or{' '}
              <button 
                type="button" 
                onClick={onButtonClick}
                className="text-blue-400 hover:text-blue-300 underline font-semibold focus:outline-none"
              >
                browse local files
              </button>
            </p>
            <p className="text-xs text-slate-500 mt-2">
              Supports standard PCAP, PCAPNG, and CAP formats
            </p>
          </>
        )}

        {status === 'uploading' && (
          <div className="flex flex-col items-center py-4">
            <div className="relative w-12 h-12 flex items-center justify-center mb-4">
              <div className="absolute inset-0 border-4 border-indigo-500/20 rounded-full"></div>
              <div className="absolute inset-0 border-4 border-t-indigo-500 rounded-full animate-spin"></div>
              <File size={18} className="text-indigo-400" />
            </div>
            <p className="text-sm font-medium text-slate-200">
              Uploading {file?.name}...
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Parsing packet structures and metadata...
            </p>
          </div>
        )}

        {status === 'success' && (
          <div className="flex flex-col items-center py-4 text-center">
            <div className="w-12 h-12 rounded-full bg-emerald-500/10 text-emerald-500 flex items-center justify-center mb-4 border border-emerald-500/20">
              <CheckCircle2 size={24} className="animate-bounce" />
            </div>
            <p className="text-sm font-semibold text-emerald-400">
              Upload Successful!
            </p>
            <p className="text-xs text-slate-400 mt-1 max-w-[250px] truncate">
              {file?.name}
            </p>
            <p className="text-[10px] text-slate-500 mt-2">
              Analysis session created. Packet processing is running in the background.
            </p>
          </div>
        )}

        {status === 'error' && (
          <div className="flex flex-col items-center py-4 text-center">
            <div className="w-12 h-12 rounded-full bg-rose-500/10 text-rose-500 flex items-center justify-center mb-4 border border-rose-500/20">
              <AlertCircle size={24} />
            </div>
            <p className="text-sm font-semibold text-rose-400">
              Processing Error
            </p>
            <p className="text-xs text-slate-400 mt-2 px-6">
              {errorMessage}
            </p>
            <button 
              onClick={() => setStatus('idle')}
              className="text-xs text-blue-400 hover:text-blue-300 font-semibold underline mt-4"
            >
              Try another file
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default UploadPCAP;
