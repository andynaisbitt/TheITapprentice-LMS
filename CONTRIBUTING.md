# Contributing to FastReactCMS

Thank you for your interest in contributing to FastReactCMS! We welcome contributions from the community to help make this project even better.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. We expect all contributors to:

- Be respectful and considerate in communications
- Accept constructive criticism gracefully
- Focus on what's best for the community and project
- Show empathy towards other community members

## How to Contribute

There are many ways to contribute to FastReactCMS:

### 1. Report Bugs

If you find a bug, please create an issue on GitHub with:

- **Clear title** - Descriptive summary of the issue
- **Steps to reproduce** - Detailed steps to reproduce the bug
- **Expected behavior** - What you expected to happen
- **Actual behavior** - What actually happened
- **Environment** - OS, Python version, Node version, browser
- **Screenshots** - If applicable
- **Error logs** - Any relevant error messages

**Security vulnerabilities** should be reported privately (see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)).

### 2. Suggest Features

We love feature requests! Please create an issue with:

- **Use case** - Why is this feature needed?
- **Proposed solution** - How should it work?
- **Alternatives** - What other approaches did you consider?
- **Additional context** - Any mockups, examples, or references

### 3. Submit Code Changes

#### Development Setup

1. **Fork the repository** on GitHub

2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/fastreactcms.git
   cd fastreactcms
   ```

3. **Set up the backend**:
   ```bash
   cd Backend
   python -m venv venv
   venv\Scripts\activate  # Windows
   # source venv/bin/activate  # macOS/Linux
   pip install -r requirements.txt
   alembic upgrade head
   python scripts/create_admin.py
   ```

4. **Set up the frontend**:
   ```bash
   cd Frontend
   npm install
   ```

5. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

#### Making Changes

1. **Write clean code**:
   - Follow existing code style and patterns
   - Add comments for complex logic
   - Keep functions small and focused
   - Use meaningful variable names

2. **Frontend code style**:
   - Run ESLint: `npm run lint`
   - Use TypeScript strict mode
   - Follow React best practices
   - Use Tailwind CSS for styling

3. **Backend code style**:
   - Format with Black: `black .`
   - Sort imports with isort: `isort .`
   - Follow PEP 8 guidelines
   - Use type hints

4. **Test your changes**:
   - Manually test in the browser
   - Verify backend API with `/docs`
   - Test in both light and dark mode
   - Check mobile responsiveness
   - Ensure no console errors

5. **Update documentation**:
   - Update README.md if needed
   - Add docstrings to new functions
   - Update API documentation
   - Include code comments

#### Commit Guidelines

Use conventional commit format:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```bash
git commit -m "feat(blog): add comment system to blog posts"
git commit -m "fix(auth): resolve CSRF token refresh issue"
git commit -m "docs(readme): update installation instructions"
```

#### Submitting a Pull Request

1. **Push your branch** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** on GitHub with:
   - Clear title following conventional commit format
   - Description of changes made
   - Why the changes are needed
   - Screenshots (for UI changes)
   - Reference to related issues (Fixes #123)

3. **Respond to feedback**:
   - Address reviewer comments
   - Make requested changes
   - Keep the PR up to date with main branch

4. **Wait for approval**:
   - At least one maintainer must approve
   - All CI checks must pass
   - No merge conflicts

## Development Workflow

### Backend Development

**Run the server**:
```bash
cd Backend
venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8100
```

**Create a database migration**:
```bash
alembic revision --autogenerate -m "Description of changes"
alembic upgrade head
```

**Access API documentation**:
- Swagger UI: http://localhost:8100/docs
- ReDoc: http://localhost:8100/redoc

### Frontend Development

**Run the dev server**:
```bash
cd Frontend
npm run dev
```

**Lint code**:
```bash
npm run lint
```

**Build for production**:
```bash
npm run build
```

## Project Structure

### Backend (`Backend/`)
```
app/
├── api/v1/           # API endpoints and services
│   ├── endpoints/    # Route handlers
│   ├── schemas/      # Pydantic schemas
│   └── services/     # Business logic
├── auth/             # Authentication
├── core/             # Core utilities
├── pages/            # Dynamic pages
└── users/            # User management
```

### Frontend (`Frontend/src/`)
```
src/
├── components/       # React components
│   ├── Admin/        # Admin panel
│   ├── Blog/         # Blog components
│   ├── Layout/       # Layout components
│   └── Pages/        # Dynamic pages
├── pages/            # Page-level components
├── services/         # API clients
├── state/            # Context providers
├── hooks/            # Custom hooks
└── utils/            # Utility functions
```

## Coding Standards

### TypeScript/React

- Use functional components with hooks
- Prefer composition over inheritance
- Extract reusable logic into custom hooks
- Use TypeScript strict mode
- Avoid `any` types
- Use proper prop typing
- Handle loading and error states
- Clean up side effects in useEffect

**Example**:
```typescript
interface BlogPostCardProps {
  post: BlogPost;
  onClick?: () => void;
}

export const BlogPostCard: React.FC<BlogPostCardProps> = ({ post, onClick }) => {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div
      className="card"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={onClick}
    >
      {/* Component content */}
    </div>
  );
};
```

### Python/FastAPI

- Use type hints everywhere
- Follow PEP 8 style guide
- Write descriptive docstrings
- Use Pydantic for validation
- Handle errors gracefully
- Use dependency injection
- Keep route handlers thin

**Example**:
```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.v1.schemas.blog import BlogPostCreate, BlogPostResponse

router = APIRouter()

@router.post("/posts", response_model=BlogPostResponse)
def create_blog_post(
    post: BlogPostCreate,
    db: Session = Depends(get_db)
) -> BlogPostResponse:
    """
    Create a new blog post.

    Args:
        post: Blog post data
        db: Database session

    Returns:
        Created blog post

    Raises:
        HTTPException: If post creation fails
    """
    # Implementation
    pass
```

## Testing

While we don't currently have automated tests, please manually test:

1. **Functionality**:
   - Feature works as intended
   - Edge cases are handled
   - Error messages are clear

2. **UI/UX**:
   - Responsive design (mobile, tablet, desktop)
   - Dark mode support
   - Accessibility (keyboard navigation, screen readers)
   - Loading states
   - Error states

3. **Security**:
   - No XSS vulnerabilities
   - CSRF protection in place
   - No sensitive data in localStorage
   - Proper authentication checks

## Getting Help

If you need help:

1. Check the [README.md](README.md) documentation
2. Browse existing [GitHub Issues](https://github.com/yourusername/fastreactcms/issues)
3. Ask in [GitHub Discussions](https://github.com/yourusername/fastreactcms/discussions)
4. Review the [Security Audit Report](SECURITY_AUDIT_REPORT.md) for security questions

## Recognition

Contributors will be:
- Listed in the project's contributors page
- Mentioned in release notes (for significant contributions)
- Credited in the README acknowledgments

## License

By contributing to FastReactCMS, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for contributing to FastReactCMS! Your efforts help make this project better for everyone.
