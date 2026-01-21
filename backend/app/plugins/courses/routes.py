# backend/app/plugins/courses/routes.py
"""
Course Routes - Public & Admin Endpoints
Adapted from ITAppBetaV1 for BlogCMS plugin architecture
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional

from app.core.database import get_db
from app.auth.dependencies import get_current_user, get_current_admin_user
from app.users.models import User
from app.plugins.courses import models, schemas, crud

router = APIRouter()


# ============================================================================
# PUBLIC ENDPOINTS (No auth required for browsing)
# ============================================================================

@router.get("/", response_model=schemas.PaginatedCoursesResponse)
async def list_courses(
    level: Optional[str] = None,
    category: Optional[str] = None,
    is_free: Optional[bool] = None,
    is_featured: Optional[bool] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(12, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Get all published courses with optional filtering (main endpoint)

    - **level**: Filter by difficulty (beginner, intermediate, advanced)
    - **category**: Filter by category
    - **is_free**: Filter free/premium courses
    - **is_featured**: Filter featured courses
    - **status**: Filter by status (default: published)
    - **search**: Search in title and description
    - **page**: Page number (default: 1)
    - **page_size**: Items per page (default: 12, max: 100)
    """
    from sqlalchemy import text

    # Default to published if no status specified
    target_status = status or 'published'

    query = db.query(models.Course).filter(
        models.Course.status == text(f"'{target_status}'::coursestatus")
    )

    # Apply filters
    if level:
        try:
            query = query.filter(models.Course.level == models.CourseLevel(level))
        except ValueError:
            pass  # Invalid level, ignore filter

    if category:
        query = query.filter(models.Course.category == category)

    if is_free is not None:
        query = query.filter(models.Course.is_premium == (not is_free))

    if is_featured is not None:
        query = query.filter(models.Course.is_featured == is_featured)

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                models.Course.title.ilike(search_term),
                models.Course.description.ilike(search_term),
                models.Course.short_description.ilike(search_term)
            )
        )

    # Get total count
    total = query.count()

    # Calculate offset
    skip = (page - 1) * page_size

    # Get paginated courses
    courses = query.order_by(models.Course.created_at.desc()).offset(skip).limit(page_size).all()

    # Fix None values
    for course in courses:
        if course.related_skills is None:
            course.related_skills = ["problem-solving"]

    return {
        "courses": courses,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/public", response_model=schemas.PaginatedCoursesResponse)
async def list_published_courses(
    level: Optional[str] = None,
    category: Optional[str] = None,
    is_free: Optional[bool] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(12, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Get all published courses with optional filtering

    - **level**: Filter by difficulty (beginner, intermediate, advanced)
    - **category**: Filter by category
    - **is_free**: Filter free/premium courses
    - **search**: Search in title and description
    - **page**: Page number (default: 1)
    - **page_size**: Items per page (default: 12, max: 100)
    """
    query = db.query(models.Course).filter(
        models.Course.status == models.CourseStatus.published
    )

    # Apply filters
    if level:
        try:
            query = query.filter(models.Course.level == models.CourseLevel(level))
        except ValueError:
            pass  # Invalid level, ignore filter

    if category:
        query = query.filter(models.Course.category == category)

    if is_free is not None:
        query = query.filter(models.Course.is_premium == (not is_free))

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                models.Course.title.ilike(search_term),
                models.Course.description.ilike(search_term),
                models.Course.short_description.ilike(search_term)
            )
        )

    # Get total count
    total = query.count()

    # Calculate offset
    skip = (page - 1) * page_size

    # Get paginated courses
    courses = query.order_by(models.Course.created_at.desc()).offset(skip).limit(page_size).all()

    # Fix None values
    for course in courses:
        if course.related_skills is None:
            course.related_skills = ["problem-solving"]

    return {
        "courses": courses,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/featured", response_model=List[schemas.CourseListResponse])
async def get_featured_courses(
    limit: int = Query(6, ge=1, le=20),
    db: Session = Depends(get_db)
):
    """Get featured courses for homepage"""
    courses = db.query(models.Course).filter(
        models.Course.status == models.CourseStatus.published,
        models.Course.is_featured == True
    ).limit(limit).all()

    for course in courses:
        if course.related_skills is None:
            course.related_skills = ["problem-solving"]

    return courses


@router.get("/categories")
async def get_course_categories(db: Session = Depends(get_db)):
    """Get list of all course categories"""
    categories = db.query(models.Course.category).filter(
        models.Course.status == models.CourseStatus.published,
        models.Course.category.isnot(None)
    ).distinct().all()

    return [cat[0] for cat in categories if cat[0]]


@router.get("/{course_id}", response_model=schemas.CourseDetailResponse)
async def get_course(
    course_id: str,
    db: Session = Depends(get_db)
):
    """Get single course by ID with all modules and sections"""
    course = crud.get_course(db, course_id)

    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    # Only allow published courses for public access
    if course.status != models.CourseStatus.published:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    # Fix None values
    if course.related_skills is None:
        course.related_skills = ["problem-solving"]

    return course


# ============================================================================
# USER ENDPOINTS (Authentication required)
# ============================================================================

@router.post("/enroll", response_model=schemas.CourseDetailResponse)
async def enroll_in_course(
    enrollment: schemas.EnrollmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enroll current user in a course"""
    db_enrollment = crud.enroll_user(db, enrollment, current_user.id)

    # Return course details
    course = crud.get_course(db, enrollment.course_id)
    return course


@router.get("/my-courses", response_model=List[schemas.CourseDetailResponse])
async def get_my_courses(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all courses the current user is enrolled in"""
    enrollments = crud.get_user_enrollments(db, current_user.id)

    courses = []
    for enrollment in enrollments:
        course = crud.get_course(db, enrollment.course_id)
        if course:
            courses.append(course)

    return courses


@router.get("/progress/{course_id}")
async def get_my_course_progress(
    course_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current user's progress in a course"""
    progress = crud.get_course_progress(db, current_user.id, course_id)

    if not progress.get("enrolled"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not enrolled in this course"
        )

    return progress


@router.put("/progress/{course_id}/module/{module_id}")
async def update_my_module_progress(
    course_id: str,
    module_id: str,
    progress_update: schemas.ModuleProgressUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update progress for a module"""
    # Get enrollment
    enrollment = crud.get_user_course_enrollment(db, current_user.id, course_id)
    if not enrollment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not enrolled in this course"
        )

    # Store previous completion state to detect if module/course was just completed
    was_module_complete = False
    existing_progress = crud.get_user_module_progress(db, enrollment.id, module_id)
    if existing_progress:
        was_module_complete = existing_progress.completed

    was_course_complete = enrollment.is_complete

    # Update progress
    progress = crud.update_module_progress(
        db,
        enrollment.id,
        module_id,
        progress_update
    )

    # Refresh enrollment to get updated state
    db.refresh(enrollment)

    # Build response
    response = {
        "message": "Progress updated",
        "completed": progress.completed,
        "completed_sections": progress.completed_sections,
        "time_spent": progress.time_spent,
        "module_completed": progress.completed and not was_module_complete,
        "course_complete": enrollment.is_complete and not was_course_complete,
        "progress": enrollment.progress
    }

    # Include certificate if course was just completed
    if enrollment.is_complete and not was_course_complete:
        # Get certificate (it was created in update_module_progress)
        certificate = crud.get_user_course_certificate(db, current_user.id, course_id)
        if certificate:
            response["certificate"] = {
                "title": certificate.title,
                "description": certificate.description,
                "verification_code": certificate.verification_code,
                "skills_acquired": certificate.skills_acquired or []
            }
            response["certificate_id"] = certificate.id

    return response


# ============================================================================
# ADMIN ENDPOINTS (Admin authentication required)
# ============================================================================

@router.get("/admin/courses", response_model=schemas.PaginatedCoursesResponse)
async def admin_list_courses(
    status: Optional[str] = None,
    level: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get all courses (including drafts) for admin"""
    course_status = models.CourseStatus(status) if status else None
    course_level = models.CourseLevel(level) if level else None

    skip = (page - 1) * page_size

    courses = crud.get_courses(
        db,
        skip=skip,
        limit=page_size,
        status=course_status,
        level=course_level
    )

    total = crud.get_courses_count(db, status=course_status, level=course_level)

    return {
        "courses": courses,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/admin/courses/{course_id}", response_model=schemas.CourseDetailResponse)
async def admin_get_course(
    course_id: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get single course (any status) for admin"""
    course = crud.get_course(db, course_id)

    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    return course


@router.post("/admin/courses", response_model=schemas.CourseDetailResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_course(
    course: schemas.CourseCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create a new course"""
    return crud.create_course(db, course)


@router.put("/admin/courses/{course_id}", response_model=schemas.CourseDetailResponse)
async def admin_update_course(
    course_id: str,
    course_update: schemas.CourseUpdate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Update a course"""
    course = crud.update_course(db, course_id, course_update)

    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    return course


@router.delete("/admin/courses/{course_id}")
async def admin_delete_course(
    course_id: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Delete (archive) a course"""
    success = crud.delete_course(db, course_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    return {"success": True, "message": "Course archived"}


@router.post("/admin/courses/{course_id}/publish", response_model=schemas.CourseDetailResponse)
async def admin_publish_course(
    course_id: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Publish a course"""
    course = crud.publish_course(db, course_id)

    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    return course


# ============================================================================
# ADMIN MODULE ENDPOINTS
# ============================================================================

@router.post("/admin/courses/{course_id}/modules", response_model=schemas.CourseModuleResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_module(
    course_id: str,
    module: schemas.CourseModuleCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create a new module in a course"""
    return crud.create_module(db, module, course_id)


@router.put("/admin/courses/{course_id}/modules/{module_id}", response_model=schemas.CourseModuleResponse)
async def admin_update_module(
    course_id: str,
    module_id: str,
    module_update: schemas.CourseModuleUpdate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Update a module"""
    module = crud.update_module(db, module_id, module_update)

    if not module:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Module not found"
        )

    return module


@router.delete("/admin/courses/{course_id}/modules/{module_id}")
async def admin_delete_module(
    course_id: str,
    module_id: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Delete a module"""
    success = crud.delete_module(db, module_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Module not found"
        )

    return {"success": True, "message": "Module deleted"}


# ============================================================================
# ADMIN SECTION ENDPOINTS (Content Blocks)
# ============================================================================

@router.post("/admin/courses/{course_id}/modules/{module_id}/sections", response_model=schemas.ModuleSectionResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_section(
    course_id: str,
    module_id: str,
    section: schemas.ModuleSectionCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create a new section with content blocks"""
    return crud.create_section(db, section, module_id)


@router.put("/admin/courses/{course_id}/modules/{module_id}/sections/{section_id}", response_model=schemas.ModuleSectionResponse)
async def admin_update_section(
    course_id: str,
    module_id: str,
    section_id: str,
    section_update: schemas.ModuleSectionUpdate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Update a section (including content blocks)"""
    section = crud.update_section(db, section_id, section_update)

    if not section:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Section not found"
        )

    return section


@router.delete("/admin/courses/{course_id}/modules/{module_id}/sections/{section_id}")
async def admin_delete_section(
    course_id: str,
    module_id: str,
    section_id: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Delete a section"""
    success = crud.delete_section(db, section_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Section not found"
        )

    return {"success": True, "message": "Section deleted"}


# ============================================================================
# ADMIN ANALYTICS
# ============================================================================

@router.get("/admin/enrollments")
async def admin_get_all_enrollments(
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    course_id: str = None,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get all enrollments across all courses with filtering"""
    query = db.query(models.CourseEnrollment)

    if status:
        query = query.filter(models.CourseEnrollment.status == status)
    if course_id:
        query = query.filter(models.CourseEnrollment.course_id == course_id)

    total = query.count()
    enrollments = query.order_by(models.CourseEnrollment.enrolled_at.desc()).offset(skip).limit(limit).all()

    # Get course and user info for each enrollment
    result = []
    for enrollment in enrollments:
        course = db.query(models.Course).filter(models.Course.id == enrollment.course_id).first()
        user = db.query(User).filter(User.id == enrollment.user_id).first()

        result.append({
            "id": enrollment.id,
            "user": {
                "id": user.id if user else None,
                "username": user.username if user else "Unknown",
                "email": user.email if user else "",
            } if user else None,
            "course": {
                "id": course.id if course else None,
                "title": course.title if course else "Unknown Course",
                "level": course.level if course else "beginner",
            } if course else None,
            "enrolled_at": enrollment.enrolled_at.isoformat() if enrollment.enrolled_at else None,
            "progress_percent": enrollment.progress_percent or 0,
            "last_activity": enrollment.last_activity_at.isoformat() if enrollment.last_activity_at else None,
            "status": enrollment.status.value if enrollment.status else "active",
        })

    # Get course stats
    course_stats = []
    courses = db.query(models.Course).all()
    for course in courses:
        course_enrollments = db.query(models.CourseEnrollment).filter(
            models.CourseEnrollment.course_id == course.id
        ).all()

        completed = len([e for e in course_enrollments if e.status == models.EnrollmentStatus.COMPLETED])
        total_enrolled = len(course_enrollments)

        course_stats.append({
            "course_id": course.id,
            "course_title": course.title,
            "total_enrollments": total_enrolled,
            "active_students": len([e for e in course_enrollments if e.status == models.EnrollmentStatus.ACTIVE]),
            "completion_rate": int((completed / total_enrolled * 100) if total_enrolled > 0 else 0),
        })

    return {
        "total": total,
        "enrollments": result,
        "course_stats": course_stats,
        "summary": {
            "total_enrollments": total,
            "active": db.query(models.CourseEnrollment).filter(
                models.CourseEnrollment.status == models.EnrollmentStatus.ACTIVE
            ).count(),
            "completed": db.query(models.CourseEnrollment).filter(
                models.CourseEnrollment.status == models.EnrollmentStatus.COMPLETED
            ).count(),
        }
    }


@router.get("/admin/courses/{course_id}/enrollments")
async def admin_get_course_enrollments(
    course_id: str,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Get all enrollments for a course"""
    enrollments = crud.get_course_enrollments(db, course_id)

    return {
        "total_enrollments": len(enrollments),
        "active": len([e for e in enrollments if e.status == models.EnrollmentStatus.ACTIVE]),
        "completed": len([e for e in enrollments if e.status == models.EnrollmentStatus.COMPLETED]),
        "dropped": len([e for e in enrollments if e.status == models.EnrollmentStatus.DROPPED]),
        "enrollments": enrollments
    }


# ============================================================================
# CERTIFICATE ENDPOINTS
# ============================================================================

@router.get("/certificates/me", response_model=List[schemas.CertificateResponse])
async def get_my_certificates(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all certificates for the current user"""
    certificates = crud.get_user_certificates(db, current_user.id)
    return certificates


@router.get("/certificates/verify/{verification_code}")
async def verify_certificate(
    verification_code: str,
    db: Session = Depends(get_db)
):
    """
    Verify a certificate by its verification code.
    Public endpoint - no authentication required.
    """
    certificate = crud.get_certificate_by_verification_code(db, verification_code)

    if not certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found or invalid verification code"
        )

    return {
        "valid": True,
        "certificate": {
            "title": certificate.title,
            "description": certificate.description,
            "verification_code": certificate.verification_code,
            "recipient_name": certificate.recipient_name,
            "course_title": certificate.course_title,
            "course_level": certificate.course_level,
            "skills_acquired": certificate.skills_acquired or [],
            "total_modules": certificate.total_modules,
            "total_sections": certificate.total_sections,
            "issued_at": certificate.issued_at.isoformat() if certificate.issued_at else None,
            "instructor_name": certificate.instructor_name
        }
    }


@router.get("/certificates/{course_id}")
async def get_certificate_for_course(
    course_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get certificate for a specific course (if completed)"""
    certificate = crud.get_user_course_certificate(db, current_user.id, course_id)

    if not certificate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found. Complete the course to earn a certificate."
        )

    return certificate
