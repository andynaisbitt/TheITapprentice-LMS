import React from 'react';
import { Link } from 'react-router-dom';
import { Clock, ArrowRight, Sparkles } from 'lucide-react';

interface BlogPost {
  id: string;
  title: string;
  excerpt: string;
  date: string;
  readTime: string;
  image: string;
  author: { name: string; avatar: string };
  slug: string;
  tags: string[];
}

interface RelatedPostsProps {
  currentPostId: string;
  currentTags: string[];
  allPosts: BlogPost[];
  maxPosts?: number;
}

const RelatedPosts: React.FC<RelatedPostsProps> = ({ 
  currentPostId, 
  currentTags, 
  allPosts, 
  maxPosts = 3 
}) => {
  const relatedPosts = React.useMemo(() => {
    return allPosts
      .filter(post => post.id !== currentPostId)
      .map(post => ({
        ...post,
        similarity: post.tags.filter(tag => currentTags.includes(tag)).length
      }))
      .filter(post => post.similarity > 0)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, maxPosts);
  }, [currentPostId, currentTags, allPosts, maxPosts]);

  if (relatedPosts.length === 0) return null;

  return (
    <section className="bg-card rounded-lg p-6 border border-border">
      <div className="flex items-center gap-2 mb-4">
        <Sparkles className="w-5 h-5 text-primary" />
        <h3 className="text-lg font-semibold text-foreground">Related Posts</h3>
      </div>
      
      <div className="grid gap-4">
        {relatedPosts.map((post) => (
          <Link
            key={post.id}
            to={`/blog/${post.slug}`}
            className="group flex gap-4 p-4 rounded-lg hover:bg-accent transition-colors"
          >
            <img
              src={post.image}
              alt={post.title}
              className="w-20 h-20 object-cover rounded-lg flex-shrink-0"
            />
            <div className="flex-1 min-w-0">
              <h4 className="font-medium text-foreground group-hover:text-primary transition-colors line-clamp-2 mb-1">
                {post.title}
              </h4>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <span>{post.author.name}</span>
                <div className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {post.readTime}
                </div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors flex-shrink-0" />
          </Link>
        ))}
      </div>
    </section>
  );
};

export default RelatedPosts;