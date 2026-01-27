# WordPress to BlogCMS Import Guide

Reference document for building a WordPress XML (WXR) exporter/importer tool for the BlogCMS system.

---

## 1. BlogCMS Post Data Model

### `blog_posts` Table

| Column | Type | Max Length | Required | Notes |
|---|---|---|---|---|
| `title` | String | 200 | Yes | Min 3 chars |
| `slug` | String | 250 | Auto | Lowercase, hyphens, numbers only. Auto-generated from title if omitted. De-duplicated with `-2`, `-3` suffix. |
| `excerpt` | Text | 500 | No | Short description, shown in listing cards |
| `content` | Text | 5MB | Yes | **Markdown format** (rendered via `react-markdown` on frontend) |
| `meta_title` | String | 60 | Auto | SEO `<title>`. Auto-filled from `title[:60]` if blank |
| `meta_description` | String | 160 | Auto | SEO meta description. Auto-filled from `excerpt[:160]` or `content[:160]` |
| `meta_keywords` | String | 255 | No | Comma-separated keywords |
| `canonical_url` | String | 500 | No | Must be full `https://` URL. For cross-posted content |
| `featured_image` | String | 500 | No | URL or relative path to image |
| `featured_image_alt` | String | 125 | No | Alt text for accessibility/SEO |
| `featured_image_caption` | String | 255 | No | Visible caption below image |
| `published` | Boolean | - | No | Default `false` (draft) |
| `published_at` | DateTime | - | Auto | Set automatically when `published=true` |
| `scheduled_for` | DateTime | - | No | Future publish date |
| `is_featured` | Boolean | - | No | Pins to homepage featured section |
| `allow_comments` | Boolean | - | No | Default `true` |
| `read_time_minutes` | Integer | - | Auto | Calculated: `word_count / 200`, minimum 1 |
| `author_id` | Integer | - | Yes | FK to `users.id` |
| `tag_ids` | List[int] | - | No | FK references to `blog_tags.id` (many-to-many) |
| `category_ids` | List[int] | - | No | FK references to `blog_categories.id` (many-to-many) |

### `blog_categories` Table

| Column | Type | Max Length | Notes |
|---|---|---|---|
| `name` | String | 100 | Unique |
| `slug` | String | 100 | Auto-generated, unique |
| `description` | Text | - | Optional |
| `parent_id` | Integer | - | FK self-reference for subcategories |
| `color` | String | 7 | Hex color, default `#3B82F6` |
| `icon` | String | 50 | Icon name or emoji |
| `meta_title` | String | 60 | Category page SEO title |
| `meta_description` | String | 160 | Category page SEO description |
| `display_order` | Integer | - | Custom sort order |

### `blog_tags` Table

| Column | Type | Max Length | Notes |
|---|---|---|---|
| `name` | String | 50 | Unique |
| `slug` | String | 50 | Auto-generated, unique |
| `description` | String | 255 | Optional |
| `color` | String | 7 | Hex color, default `#6B7280` |

### `blog_media` Table

| Column | Type | Notes |
|---|---|---|
| `filename` | String(255) | Server filename |
| `original_filename` | String(255) | Original upload name |
| `file_path` | String(500) | Relative path on disk |
| `file_url` | String(500) | Public URL |
| `file_size` | Integer | Bytes |
| `mime_type` | String(100) | e.g. `image/jpeg` |
| `width` / `height` | Integer | Image dimensions |
| `alt_text` | String(125) | SEO alt text |
| `caption` | String(255) | Visible caption |

---

## 2. Content Format: Markdown

**BlogCMS stores and renders content as Markdown**, not HTML.

The frontend uses `react-markdown` to render post content inside a Tailwind CSS `prose` container with full dark mode support. The prose classes provide automatic styling for:

- Headings (h2, h3) with proper sizing and spacing
- Paragraphs with relaxed leading
- Links styled blue with hover underline
- Inline code with background highlight
- Code blocks with border and shadow
- Blockquotes with blue left border and background
- Ordered/unordered lists with proper indentation
- Images with rounded corners and shadow

### WordPress HTML to Markdown Conversion

WordPress exports content as HTML. The importer **must convert HTML to Markdown**. Key mappings:

| WordPress HTML | BlogCMS Markdown |
|---|---|
| `<h2>Title</h2>` | `## Title` |
| `<h3>Title</h3>` | `### Title` |
| `<p>Text</p>` | `Text\n\n` |
| `<strong>bold</strong>` | `**bold**` |
| `<em>italic</em>` | `*italic*` |
| `<a href="url">text</a>` | `[text](url)` |
| `<img src="url" alt="x">` | `![x](url)` |
| `<blockquote>text</blockquote>` | `> text` |
| `<ul><li>item</li></ul>` | `- item` |
| `<ol><li>item</li></ol>` | `1. item` |
| `<code>inline</code>` | `` `inline` `` |
| `<pre><code>block</code></pre>` | ```` ```\nblock\n``` ```` |
| `<!-- wp:image -->` blocks | Extract `src`/`alt`, convert to `![alt](src)` |
| `<!-- wp:gallery -->` blocks | Convert each image to `![](src)` |
| `<!-- wp:embed -->` blocks | Extract URL, output as plain link or embed syntax |
| WordPress shortcodes `[shortcode]` | Strip or convert to equivalent Markdown |
| `&nbsp;` / HTML entities | Convert to plain characters |

### Gutenberg Block Handling

WordPress 5.0+ uses Gutenberg blocks stored as HTML comments. The importer should:

1. Parse `<!-- wp:paragraph -->` - extract inner `<p>` content
2. Parse `<!-- wp:heading -->` - extract heading level and text
3. Parse `<!-- wp:image -->` - extract `src`, `alt`, `caption`
4. Parse `<!-- wp:list -->` - extract list items
5. Parse `<!-- wp:code -->` / `<!-- wp:preformatted -->` - extract code blocks
6. Parse `<!-- wp:quote -->` - convert to blockquote
7. Parse `<!-- wp:separator -->` - convert to `---`
8. **Strip** unsupported blocks: `<!-- wp:columns -->`, `<!-- wp:buttons -->`, etc.

---

## 3. SEO System

### Auto-Generated Fields

When creating a post, BlogCMS auto-generates SEO fields if not provided:

```
meta_title     = title[:60]              (if blank)
meta_description = excerpt[:160]          (if blank, falls back to content[:160])
read_time_minutes = ceil(word_count / 200) (always calculated)
slug           = slugify(title)           (if blank)
```

### SSR Meta Tag Injection

BlogCMS runs an Express.js SSR server (`server.js`) that detects crawlers (Googlebot, Facebookbot, LinkedInBot, Twitterbot, etc.) and injects meta tags into the HTML `<head>` before serving:

- `<title>` - from `meta_title` or `title`
- `<meta name="description">` - from `meta_description`
- `<meta name="keywords">` - from `meta_keywords`
- `<link rel="canonical">` - from `canonical_url`
- `<meta property="og:title">` - Open Graph title
- `<meta property="og:description">` - Open Graph description
- `<meta property="og:image">` - from `featured_image`
- `<meta name="twitter:card">` - Twitter card
- `<meta name="twitter:title">` / `twitter:description` / `twitter:image`

Regular users get the standard SPA with client-side `react-helmet-async` managing the `<head>`.

### SEO Constraints (Validation)

| Field | Limit | Notes |
|---|---|---|
| `meta_title` | Max 60 chars | Enforced by Pydantic validator |
| `meta_description` | Max 160 chars | Enforced by Pydantic validator |
| `slug` | Max 250 chars | Only `[a-z0-9-]` allowed |
| `featured_image_alt` | Max 125 chars | Accessibility requirement |
| `canonical_url` | Must be `https?://` | Validated by regex |

---

## 4. WordPress WXR XML Structure

WordPress exports use the WXR (WordPress eXtended RSS) format. Key elements the importer needs to extract:

```xml
<channel>
  <!-- Site metadata -->
  <title>Site Name</title>
  <link>https://example.com</link>

  <!-- Categories -->
  <wp:category>
    <wp:term_id>3</wp:term_id>
    <wp:category_nicename>tech</wp:category_nicename>
    <wp:cat_name><![CDATA[Technology]]></wp:cat_name>
    <wp:category_parent></wp:category_parent>
    <wp:category_description><![CDATA[Tech posts]]></wp:category_description>
  </wp:category>

  <!-- Tags -->
  <wp:tag>
    <wp:term_id>5</wp:term_id>
    <wp:tag_slug>python</wp:tag_slug>
    <wp:tag_name><![CDATA[Python]]></wp:tag_name>
    <wp:tag_description><![CDATA[Python programming]]></wp:tag_description>
  </wp:tag>

  <!-- Posts -->
  <item>
    <title>Post Title</title>
    <link>https://example.com/2024/01/post-slug/</link>
    <wp:post_name>post-slug</wp:post_name>
    <wp:post_type>post</wp:post_type>
    <wp:status>publish</wp:status>
    <wp:post_date>2024-01-15 10:30:00</wp:post_date>
    <dc:creator>authorname</dc:creator>
    <content:encoded><![CDATA[HTML content here]]></content:encoded>
    <excerpt:encoded><![CDATA[Excerpt text]]></excerpt:encoded>

    <!-- Post categories/tags -->
    <category domain="category" nicename="tech"><![CDATA[Technology]]></category>
    <category domain="post_tag" nicename="python"><![CDATA[Python]]></category>

    <!-- Featured image (in postmeta) -->
    <wp:postmeta>
      <wp:meta_key>_thumbnail_id</wp:meta_key>
      <wp:meta_value>123</wp:meta_value>
    </wp:postmeta>

    <!-- SEO plugin meta (Yoast / RankMath / AIOSEO) -->
    <wp:postmeta>
      <wp:meta_key>_yoast_wpseo_title</wp:meta_key>
      <wp:meta_value>Custom SEO Title</wp:meta_value>
    </wp:postmeta>
    <wp:postmeta>
      <wp:meta_key>_yoast_wpseo_metadesc</wp:meta_key>
      <wp:meta_value>Custom meta description</wp:meta_value>
    </wp:postmeta>
    <wp:postmeta>
      <wp:meta_key>_yoast_wpseo_focuskw</wp:meta_key>
      <wp:meta_value>focus,keywords</wp:meta_value>
    </wp:postmeta>
  </item>

  <!-- Attachments (images) -->
  <item>
    <wp:post_type>attachment</wp:post_type>
    <wp:post_id>123</wp:post_id>
    <wp:attachment_url>https://example.com/wp-content/uploads/2024/01/image.jpg</wp:attachment_url>
    <title>Image Title</title>
    <wp:postmeta>
      <wp:meta_key>_wp_attachment_image_alt</wp:meta_key>
      <wp:meta_value>Alt text for SEO</wp:meta_value>
    </wp:postmeta>
  </item>
</channel>
```

---

## 5. Field Mapping: WordPress to BlogCMS

### Posts

| WordPress (WXR) | BlogCMS Field | Transform |
|---|---|---|
| `<title>` | `title` | Truncate to 200 chars |
| `<wp:post_name>` | `slug` | Already lowercase-hyphenated. Validate `[a-z0-9-]`, truncate to 250 |
| `<excerpt:encoded>` | `excerpt` | Strip HTML, truncate to 500 chars |
| `<content:encoded>` | `content` | **Convert HTML to Markdown** (main conversion step) |
| `_yoast_wpseo_title` or `_rank_math_title` | `meta_title` | Truncate to 60 chars. Strip Yoast `%%` variables. |
| `_yoast_wpseo_metadesc` or `_rank_math_description` | `meta_description` | Truncate to 160 chars |
| `_yoast_wpseo_focuskw` or `_rank_math_focus_keyword` | `meta_keywords` | Truncate to 255 chars |
| `<link>` (original permalink) | `canonical_url` | Set if you want to preserve the original URL for SEO migration |
| `_thumbnail_id` -> attachment URL | `featured_image` | Resolve attachment ID to URL from attachment items |
| `_wp_attachment_image_alt` (on attachment) | `featured_image_alt` | Truncate to 125 chars |
| `<wp:status>` = `publish` | `published` = `true` | Map: `publish` -> `true`, `draft`/`pending`/`private` -> `false` |
| `<wp:post_date>` | `published_at` | Parse `YYYY-MM-DD HH:MM:SS`, only set if status=publish |
| `<wp:post_date>` (if future) | `scheduled_for` | If date is in the future and status=future |
| `<category domain="category">` | `category_ids` | Create-or-match by slug, collect IDs |
| `<category domain="post_tag">` | `tag_ids` | Create-or-match by slug, collect IDs |
| `<dc:creator>` | `author_id` | Map WP username to BlogCMS user ID (fallback: admin user) |
| (computed) | `read_time_minutes` | Auto-calculated by BlogCMS from content word count |
| (sticky flag) | `is_featured` | Map `<wp:is_sticky>1</wp:is_sticky>` to `true` |

### Categories

| WordPress | BlogCMS | Notes |
|---|---|---|
| `<wp:cat_name>` | `name` | Truncate to 100 |
| `<wp:category_nicename>` | `slug` | Validate format |
| `<wp:category_description>` | `description` | |
| `<wp:category_parent>` | `parent_id` | Resolve parent slug to ID after all categories created |

### Tags

| WordPress | BlogCMS | Notes |
|---|---|---|
| `<wp:tag_name>` | `name` | Truncate to 50 |
| `<wp:tag_slug>` | `slug` | Validate format |
| `<wp:tag_description>` | `description` | Truncate to 255 |

---

## 6. API Endpoints for Import

The importer should use the admin API endpoints:

```
POST /api/v1/blog/admin/categories     -> Create category (returns id)
POST /api/v1/blog/admin/tags           -> Create tag (returns id)
POST /api/v1/blog/admin/posts          -> Create post (with tag_ids, category_ids)
```

Request body for creating a post:

```json
{
  "title": "Post Title",
  "slug": "post-title",
  "excerpt": "Short description of the post",
  "content": "# Heading\n\nMarkdown content here...",
  "meta_title": "SEO Title (max 60 chars)",
  "meta_description": "SEO description (max 160 chars)",
  "meta_keywords": "keyword1, keyword2",
  "canonical_url": "https://old-site.com/original-post/",
  "featured_image": "https://example.com/image.jpg",
  "featured_image_alt": "Descriptive alt text",
  "featured_image_caption": "Photo credit caption",
  "published": true,
  "scheduled_for": null,
  "is_featured": false,
  "allow_comments": true,
  "tag_ids": [1, 3, 5],
  "category_ids": [2]
}
```

All requests require an admin JWT token in the `Authorization: Bearer <token>` header.

---

## 7. Import Tool Optimisations

### Content Cleaning

1. **Strip WordPress shortcodes**: Remove `[caption]`, `[gallery]`, `[embed]`, `[contact-form]`, etc.
2. **Clean Gutenberg comments**: Remove `<!-- wp:* -->` wrapper comments after extracting content
3. **Fix internal links**: Replace `https://old-site.com/` URLs with relative `/blog/` paths
4. **Normalise whitespace**: Collapse multiple blank lines to double-newline (Markdown paragraph break)
5. **Fix image URLs**: Either download and re-upload images, or rewrite `wp-content/uploads/` paths

### SEO Preservation

1. **Keep Yoast/RankMath meta**: Extract `_yoast_wpseo_title`, `_yoast_wpseo_metadesc`, `_rank_math_title`, `_rank_math_description`, `_aioseo_title`, `_aioseo_description`
2. **Set canonical URLs**: Point back to original WordPress URLs during migration to prevent duplicate content penalties. Remove them once the old site is taken down and redirects are in place.
3. **Preserve slugs**: Use original `<wp:post_name>` as slug to maintain URL structure
4. **Map publish dates**: Preserve original `published_at` for post ordering and sitemap accuracy

### Image Handling Strategy

Two options:

**Option A - URL Rewriting (Simple)**
- Keep original WordPress image URLs in Markdown
- Works immediately, depends on old server staying online
- Good for testing/staging

**Option B - Download & Re-upload (Recommended for production)**
- Parse all attachment items from WXR for URL-to-metadata mapping
- Download each image from `<wp:attachment_url>`
- Upload to BlogCMS media library via `POST /api/v1/blog/admin/media`
- Rewrite content image URLs to new BlogCMS URLs
- Set `alt_text` from `_wp_attachment_image_alt` postmeta
- Set `featured_image` from resolved `_thumbnail_id`

### Import Order

Must be done in this sequence due to foreign key relationships:

1. **Categories** (create all, build `wp_slug -> blogcms_id` map)
2. **Tags** (create all, build `wp_slug -> blogcms_id` map)
3. **Media/Attachments** (if using Option B, download and upload all images)
4. **Posts** (convert content, resolve category/tag IDs, resolve featured image)

### Duplicate Prevention

- Before creating categories/tags, check if slug already exists
- Before creating posts, check if slug already exists
- Use `GET /api/v1/blog/admin/categories` and `GET /api/v1/blog/admin/tags` to pre-fetch existing items
- Skip or update-in-place for duplicates

### Post-Import Checklist

- [ ] Verify post count matches expected
- [ ] Spot-check 5 posts for correct Markdown rendering
- [ ] Verify images load correctly
- [ ] Check featured images appear on blog listing
- [ ] Verify categories and tags are correctly assigned
- [ ] Test SEO meta tags render for crawlers (use SSR server)
- [ ] Check that slugs match original URLs for redirect mapping
- [ ] Set up 301 redirects from old WordPress URL structure to new BlogCMS URLs

---

## 8. WordPress URL Structure to BlogCMS Redirects

| WordPress Pattern | BlogCMS Route |
|---|---|
| `/2024/01/post-slug/` | `/blog/post-slug` |
| `/category/tech/` | `/blog?category=tech` |
| `/tag/python/` | `/blog?tag=python` |
| `/author/username/` | No equivalent (ignore or redirect to homepage) |
| `/page/2/` | `/blog?page=2` |

The nginx config should include 301 redirects for the old WordPress permalink patterns.
