import React, { useState } from 'react';
import { Share2, Twitter, Facebook, Linkedin, Mail, Copy, Check } from 'lucide-react';

interface ShareData {
  url: string;
  title: string;
  description?: string;
}

interface ShareButtonsProps {
  shareData: ShareData;
  platforms?: ('twitter' | 'facebook' | 'linkedin' | 'email' | 'copy')[];
  variant?: 'default' | 'compact' | 'dropdown';
  onShare?: (platform: string) => void;
}

const ShareButtons: React.FC<ShareButtonsProps> = ({
  shareData,
  platforms = ['twitter', 'facebook', 'linkedin', 'email', 'copy'],
  variant = 'default',
  onShare
}) => {
  const [copied, setCopied] = useState(false);
  const [isOpen, setIsOpen] = useState(false);

  const shareUrls = {
    twitter: `https://twitter.com/intent/tweet?url=${encodeURIComponent(shareData.url)}&text=${encodeURIComponent(shareData.title)}`,
    facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareData.url)}`,
    linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareData.url)}`,
    email: `mailto:?subject=${encodeURIComponent(shareData.title)}&body=${encodeURIComponent(`${shareData.description || shareData.title}\n\n${shareData.url}`)}`
  };

  const platformConfig = {
    twitter: { icon: Twitter, label: 'Twitter', color: 'hover:bg-blue-50 hover:text-blue-600' },
    facebook: { icon: Facebook, label: 'Facebook', color: 'hover:bg-blue-50 hover:text-blue-800' },
    linkedin: { icon: Linkedin, label: 'LinkedIn', color: 'hover:bg-blue-50 hover:text-blue-700' },
    email: { icon: Mail, label: 'Email', color: 'hover:bg-gray-50 hover:text-gray-700' },
    copy: { icon: copied ? Check : Copy, label: copied ? 'Copied!' : 'Copy Link', color: 'hover:bg-green-50 hover:text-green-600' }
  };

  const handleShare = async (platform: string) => {
    if (platform === 'copy') {
      try {
        await navigator.clipboard.writeText(shareData.url);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = shareData.url;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } else {
      window.open(shareUrls[platform as keyof typeof shareUrls], '_blank', 'width=550,height=420');
    }
    
    if (onShare) {
      onShare(platform);
    }
    if (variant === 'dropdown') {
      setIsOpen(false);
    }
  };

  const handleNativeShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: shareData.title,
          text: shareData.description,
          url: shareData.url
        });
        if (onShare) {
          onShare('native');
        }
      } catch (err) {
        // User cancelled or error occurred
      }
    }
  };

  if (variant === 'dropdown') {
    return (
      <div className="relative">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors"
        >
          <Share2 className="w-4 h-4" />
          Share
        </button>

        {isOpen && (
          <>
            <div 
              className="fixed inset-0 z-10" 
              onClick={() => setIsOpen(false)}
            />
            <div className="absolute top-full right-0 mt-2 w-48 bg-background border border-border rounded-lg shadow-lg z-20">
              <div className="p-2">
                {typeof navigator !== 'undefined' && 'share' in navigator && (
                  <button
                    onClick={handleNativeShare}
                    className="w-full flex items-center gap-3 px-3 py-2 text-sm rounded-lg hover:bg-accent transition-colors"
                  >
                    <Share2 className="w-4 h-4" />
                    Share via...
                  </button>
                )}
                
                {platforms.map((platform) => {
                  const config = platformConfig[platform];
                  const Icon = config.icon;
                  
                  return (
                    <button
                      key={platform}
                      onClick={() => handleShare(platform)}
                      className={`w-full flex items-center gap-3 px-3 py-2 text-sm rounded-lg transition-colors ${config.color}`}
                    >
                      <Icon className="w-4 h-4" />
                      {config.label}
                    </button>
                  );
                })}
              </div>
            </div>
          </>
        )}
      </div>
    );
  }

  if (variant === 'compact') {
    return (
      <div className="flex items-center gap-2">
        <Share2 className="w-4 h-4 text-muted-foreground" />
        <div className="flex gap-1">
          {platforms.map((platform) => {
            const config = platformConfig[platform];
            const Icon = config.icon;
            
            return (
              <button
                key={platform}
                onClick={() => handleShare(platform)}
                className="p-1.5 rounded hover:bg-accent transition-colors"
                title={config.label}
              >
                <Icon className="w-4 h-4 text-muted-foreground hover:text-foreground" />
              </button>
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg p-4 border border-border">
      <h4 className="font-medium text-foreground mb-3 flex items-center gap-2">
        <Share2 className="w-4 h-4" />
        Share this post
      </h4>
      
      <div className="grid grid-cols-2 gap-2">
        {typeof navigator !== 'undefined' && 'share' in navigator && (
          <button
            onClick={handleNativeShare}
            className="flex items-center gap-2 px-3 py-2 text-sm border border-border rounded-lg hover:bg-accent transition-colors"
          >
            <Share2 className="w-4 h-4" />
            Share
          </button>
        )}
        
        {platforms.map((platform) => {
          const config = platformConfig[platform];
          const Icon = config.icon;
          
          return (
            <button
              key={platform}
              onClick={() => handleShare(platform)}
              className={`flex items-center gap-2 px-3 py-2 text-sm border border-border rounded-lg transition-colors ${config.color}`}
              disabled={platform === 'copy' && copied}
            >
              <Icon className="w-4 h-4" />
              {config.label}
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default ShareButtons;