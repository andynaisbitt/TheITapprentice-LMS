# backend/app/plugins/courses/crud.py
"""
CRUD operations for Course System
Handles all database operations for courses, modules, sections, and enrollments
Adapted from ITAppBetaV1 for BlogCMS plugin architecture
"""
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
from datetime import datetime

from app.plugins.courses.models import (
    Course, CourseModule, ModuleSection,
    CourseEnrollment, ModuleProgress,
    CourseLevel, CourseStatus, SectionType,
    SectionStatus, EnrollmentStatus
)
from app.plugins.courses.schemas import (
    CourseCreate, CourseUpdate,
    CourseModuleCreate, CourseModuleUpdate,
    ModuleSectionCreate, ModuleSectionUpdate,
    EnrollmentCreate, ModuleProgressUpdate
)


# ==================== COURSE CRUD ====================

def get_course(db: Session, course_id: str) -> Optional[Course]:
    """Get a single course by ID with all relationships loaded"""
    return db.query(Course)\
        .options(
            joinedload(Course.modules).joinedload(CourseModule.sections),
            joinedload(Course.enrollments)
        )\
        .filter(Course.id == course_id)\
        .first()


def get_courses(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[CourseStatus] = None,
    level: Optional[CourseLevel] = None,
    is_featured: Optional[bool] = None
) -> List[Course]:
    """Get all courses with optional filtering"""
    query = db.query(Course).options(joinedload(Course.modules))

    if status:
        query = query.filter(Course.status == status)
    if level:
        query = query.filter(Course.level == level)
    if is_featured is not None:
        query = query.filter(Course.is_featured == is_featured)

    return query.order_by(Course.created_at.desc()).offset(skip).limit(limit).all()


def get_courses_count(
    db: Session,
    status: Optional[CourseStatus] = None,
    level: Optional[CourseLevel] = None
) -> int:
    """Get total count of courses with filtering"""
    query = db.query(Course)

    if status:
        query = query.filter(Course.status == status)
    if level:
        query = query.filter(Course.level == level)

    return query.count()


def create_course(db: Session, course: CourseCreate) -> Course:
    """Create a new course"""
    try:
        db_course = Course(
            id=course.id,
            title=course.title,
            description=course.description,
            short_description=course.short_description,
            image=course.image,
            level=course.level,
            duration=course.duration,
            skills=course.skills or [],
            category=course.category,
            tags=course.tags or [],
            requirements=course.requirements or [],
            objectives=course.objectives or [],
            instructor_id=course.instructor_id,
            is_premium=course.is_premium,
            price=course.price,
            related_skills=course.related_skills or ["problem-solving"],
            xp_reward=course.xp_reward,
            status=CourseStatus.DRAFT,
        )
        db.add(db_course)
        db.commit()
        db.refresh(db_course)
        return db_course
    except IntegrityError as e:
        db.rollback()
        if "PRIMARY KEY" in str(e) or "courses_pkey" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Course with id '{course.id}' already exists"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to create course"
        )


def update_course(
    db: Session,
    course_id: str,
    course_update: CourseUpdate
) -> Optional[Course]:
    """Update an existing course"""
    db_course = get_course(db, course_id)
    if not db_course:
        return None

    update_data = course_update.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(db_course, field, value)

    try:
        db.commit()
        db.refresh(db_course)
        return db_course
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update course"
        )


def delete_course(db: Session, course_id: str) -> bool:
    """Delete a course (soft delete by setting status to archived)"""
    db_course = get_course(db, course_id)
    if not db_course:
        return False

    # Soft delete - just change status
    db_course.status = CourseStatus.ARCHIVED
    db.commit()
    return True


def publish_course(db: Session, course_id: str) -> Optional[Course]:
    """Publish a course"""
    db_course = get_course(db, course_id)
    if not db_course:
        return None

    db_course.status = CourseStatus.PUBLISHED
    db_course.published_at = datetime.utcnow()
    db.commit()
    db.refresh(db_course)
    return db_course


# ==================== MODULE CRUD ====================

def get_module(db: Session, module_id: str) -> Optional[CourseModule]:
    """Get a single module with sections loaded"""
    return db.query(CourseModule)\
        .options(joinedload(CourseModule.sections))\
        .filter(CourseModule.id == module_id)\
        .first()


def get_course_modules(db: Session, course_id: str) -> List[CourseModule]:
    """Get all modules for a course"""
    return db.query(CourseModule)\
        .options(joinedload(CourseModule.sections))\
        .filter(CourseModule.course_id == course_id)\
        .order_by(CourseModule.order_index)\
        .all()


def create_module(
    db: Session,
    module: CourseModuleCreate,
    course_id: str
) -> CourseModule:
    """Create a new module"""
    # Verify course exists
    course = get_course(db, course_id)
    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Course {course_id} not found"
        )

    # Check for duplicate module ID
    existing = db.query(CourseModule).filter(CourseModule.id == module.id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Module with id '{module.id}' already exists"
        )

    db_module = CourseModule(
        id=module.id,
        course_id=course_id,
        title=module.title,
        description=module.description,
        duration=module.duration,
        order_index=module.order_index,
        estimated_minutes=module.estimated_minutes,
        prerequisites=module.prerequisites or [],
        component=module.component,
        difficulty_level=module.difficulty_level,
    )

    db.add(db_module)
    db.commit()
    db.refresh(db_module)
    return db_module


def update_module(
    db: Session,
    module_id: str,
    module_update: CourseModuleUpdate
) -> Optional[CourseModule]:
    """Update an existing module"""
    db_module = get_module(db, module_id)
    if not db_module:
        return None

    update_data = module_update.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(db_module, field, value)

    db.commit()
    db.refresh(db_module)
    return db_module


def delete_module(db: Session, module_id: str) -> bool:
    """Delete a module and all its sections (CASCADE handles sections)"""
    db_module = get_module(db, module_id)
    if not db_module:
        return False

    db.delete(db_module)
    db.commit()
    return True


# ==================== SECTION CRUD ====================

def get_section(db: Session, section_id: str) -> Optional[ModuleSection]:
    """Get a single section"""
    return db.query(ModuleSection)\
        .filter(ModuleSection.id == section_id)\
        .first()


def get_module_sections(db: Session, module_id: str) -> List[ModuleSection]:
    """Get all sections for a module"""
    return db.query(ModuleSection)\
        .filter(ModuleSection.module_id == module_id)\
        .order_by(ModuleSection.order_index)\
        .all()


def create_section(
    db: Session,
    section: ModuleSectionCreate,
    module_id: str
) -> ModuleSection:
    """Create a new section with content blocks"""
    # Verify module exists
    module = get_module(db, module_id)
    if not module:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Module {module_id} not found"
        )

    # Check for duplicate section ID
    existing = db.query(ModuleSection).filter(ModuleSection.id == section.id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Section with id '{section.id}' already exists"
        )

    db_section = ModuleSection(
        id=section.id,
        module_id=module_id,
        title=section.title,
        description=section.description,
        time_estimate=section.time_estimate,
        type=section.type,
        content_blocks=section.content_blocks or [],
        order_index=section.order_index,
        points=section.points,
    )

    db.add(db_section)
    db.commit()
    db.refresh(db_section)
    return db_section


def update_section(
    db: Session,
    section_id: str,
    section_update: ModuleSectionUpdate
) -> Optional[ModuleSection]:
    """Update an existing section"""
    db_section = get_section(db, section_id)
    if not db_section:
        return None

    update_data = section_update.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        setattr(db_section, field, value)

    db.commit()
    db.refresh(db_section)
    return db_section


def delete_section(db: Session, section_id: str) -> bool:
    """Delete a section"""
    db_section = get_section(db, section_id)
    if not db_section:
        return False

    db.delete(db_section)
    db.commit()
    return True


# ==================== ENROLLMENT CRUD ====================

def get_user_enrollments(
    db: Session,
    user_id: int,
    status: Optional[EnrollmentStatus] = None
) -> List[CourseEnrollment]:
    """Get all enrollments for a user"""
    query = db.query(CourseEnrollment)\
        .options(joinedload(CourseEnrollment.course))\
        .filter(CourseEnrollment.user_id == user_id)

    if status:
        query = query.filter(CourseEnrollment.status == status)

    return query.order_by(CourseEnrollment.enrolled_at.desc()).all()


def get_course_enrollments(
    db: Session,
    course_id: str
) -> List[CourseEnrollment]:
    """Get all enrollments for a course"""
    return db.query(CourseEnrollment)\
        .filter(CourseEnrollment.course_id == course_id)\
        .all()


def get_user_course_enrollment(
    db: Session,
    user_id: int,
    course_id: str
) -> Optional[CourseEnrollment]:
    """Get user's enrollment in a specific course"""
    return db.query(CourseEnrollment)\
        .filter(
            CourseEnrollment.user_id == user_id,
            CourseEnrollment.course_id == course_id
        )\
        .first()


def enroll_user(
    db: Session,
    enrollment: EnrollmentCreate,
    user_id: int
) -> CourseEnrollment:
    """Enroll a user in a course"""
    # Check if already enrolled
    existing = get_user_course_enrollment(db, user_id, enrollment.course_id)

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already enrolled in this course"
        )

    # Verify course exists and is published
    course = get_course(db, enrollment.course_id)
    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )
    if course.status != CourseStatus.PUBLISHED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot enroll in unpublished course"
        )

    db_enrollment = CourseEnrollment(
        user_id=user_id,
        course_id=enrollment.course_id,
        status=EnrollmentStatus.ACTIVE,
    )

    db.add(db_enrollment)

    # Increment enrollment count on course
    course.enrollment_count += 1

    db.commit()
    db.refresh(db_enrollment)
    return db_enrollment


def update_enrollment_status(
    db: Session,
    enrollment_id: int,
    new_status: EnrollmentStatus
) -> Optional[CourseEnrollment]:
    """Update enrollment status"""
    enrollment = db.query(CourseEnrollment)\
        .filter(CourseEnrollment.id == enrollment_id)\
        .first()

    if not enrollment:
        return None

    enrollment.status = new_status

    if new_status == EnrollmentStatus.COMPLETED:
        enrollment.completed_at = datetime.utcnow()
        enrollment.is_complete = True

        # Increment completion count on course
        course = get_course(db, enrollment.course_id)
        if course:
            course.completion_count += 1

    db.commit()
    db.refresh(enrollment)
    return enrollment


# ==================== PROGRESS TRACKING ====================

def get_user_module_progress(
    db: Session,
    enrollment_id: int,
    module_id: str
) -> Optional[ModuleProgress]:
    """Get user's progress for a specific module"""
    return db.query(ModuleProgress)\
        .filter(
            ModuleProgress.enrollment_id == enrollment_id,
            ModuleProgress.module_id == module_id
        )\
        .first()


def update_module_progress(
    db: Session,
    enrollment_id: int,
    module_id: str,
    progress_update: ModuleProgressUpdate
) -> ModuleProgress:
    """Update user's progress in a module"""
    # Get or create progress record
    progress = get_user_module_progress(db, enrollment_id, module_id)

    if not progress:
        progress = ModuleProgress(
            enrollment_id=enrollment_id,
            module_id=module_id,
            completed_sections=progress_update.completed_sections or [],
            quiz_scores=progress_update.quiz_scores or {},
        )
        db.add(progress)
    else:
        # Update fields from request
        if progress_update.completed_sections is not None:
            progress.completed_sections = progress_update.completed_sections
        if progress_update.quiz_scores:
            progress.quiz_scores.update(progress_update.quiz_scores)
        if progress_update.last_position:
            progress.last_position = progress_update.last_position
        if progress_update.notes:
            progress.notes = progress_update.notes

        progress.time_spent += progress_update.time_spent

    # Get total sections count for this module
    total_sections = db.query(ModuleSection)\
        .filter(ModuleSection.module_id == module_id)\
        .count()

    # Check if module is completed
    if len(progress.completed_sections) >= total_sections and total_sections > 0:
        if not progress.completed:
            progress.completed = True
            progress.completed_at = datetime.utcnow()

            # Update enrollment progress
            enrollment = db.query(CourseEnrollment).filter(
                CourseEnrollment.id == enrollment_id
            ).first()

            if enrollment and module_id not in enrollment.completed_modules:
                enrollment.completed_modules.append(module_id)

                # Calculate overall course progress
                total_modules = db.query(CourseModule)\
                    .filter(CourseModule.course_id == enrollment.course_id)\
                    .count()

                enrollment.progress = int(
                    (len(enrollment.completed_modules) / total_modules * 100)
                    if total_modules > 0 else 0
                )

                # Check if course is completed
                if enrollment.progress >= 100:
                    enrollment.is_complete = True
                    enrollment.completed_at = datetime.utcnow()
                    enrollment.status = EnrollmentStatus.COMPLETED

    db.commit()
    db.refresh(progress)
    return progress


def get_course_progress(
    db: Session,
    user_id: int,
    course_id: str
) -> dict:
    """Get overall course progress for a user"""
    # Get enrollment
    enrollment = get_user_course_enrollment(db, user_id, course_id)
    if not enrollment:
        return {
            "course_id": course_id,
            "enrolled": False,
            "progress": 0,
            "completed_modules": [],
            "is_complete": False
        }

    # Get all modules for the course
    modules = get_course_modules(db, course_id)

    module_progress_data = {}
    for module in modules:
        progress = get_user_module_progress(db, enrollment.id, module.id)
        module_progress_data[module.id] = {
            "completed": progress.completed if progress else False,
            "completed_sections": progress.completed_sections if progress else [],
            "time_spent": progress.time_spent if progress else 0,
            "quiz_scores": progress.quiz_scores if progress else {},
            "last_position": progress.last_position if progress else None,
        }

    return {
        "course_id": course_id,
        "enrolled": True,
        "enrollment_id": enrollment.id,
        "progress": enrollment.progress,
        "completed_modules": enrollment.completed_modules,
        "current_module": enrollment.current_module_id,
        "is_complete": enrollment.is_complete,
        "total_modules": len(modules),
        "time_spent": enrollment.time_spent,
        "module_progress": module_progress_data,
        "last_accessed": enrollment.last_accessed,
    }
