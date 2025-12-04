import React from "react";
import { Github, Twitter, Linkedin } from "lucide-react"; // example icons

interface AuthorCardProps {
  name: string;
  bio: string;
  avatar: string;
  socials?: { platform: string; url: string }[];
}

const platformIcons: Record<string, JSX.Element> = {
  github: <Github className="w-4 h-4" />,
  twitter: <Twitter className="w-4 h-4" />,
  linkedin: <Linkedin className="w-4 h-4" />,
};

const AuthorCard: React.FC<AuthorCardProps> = ({ name, bio, avatar, socials = [] }) => {
  return (
    <div className="bg-card rounded-lg shadow-sm border border-border p-6 text-center">
      <img
        src={avatar}
        alt={name}
        className="w-20 h-20 rounded-full mx-auto mb-4 border border-border"
      />
      <h3 className="text-lg font-semibold text-foreground">{name}</h3>
      <p className="text-sm text-muted-foreground mb-4">{bio}</p>

      {socials.length > 0 && (
        <div className="flex justify-center gap-4">
          {socials.map(({ platform, url }) => {
            const icon = platformIcons[platform.toLowerCase()];
            if (!icon) return null; // safely skip unknown platforms

            return (
              <a
                key={platform}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-primary transition-colors"
              >
                {icon}
              </a>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default AuthorCard;
