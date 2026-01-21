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
    CourseEnrollment, ModuleProgress, Certificate,
    CourseLevel, CourseStatus, SectionType,
    SectionStatus, EnrollmentStatus
)
import secrets
import string
from app.plugins.courses.schemas import (
    CourseCreate, CourseUpdate,
    CourseModuleCreate, CourseModuleUpdate,
    ModuleSectionCreate, ModuleSectionUpdate,
    EnrollmentCreate, ModuleProgressUpdate
)
from app.plugins.shared.xp_service import xp_service
from app.plugins.shared.achievement_service import achievement_service
from app.plugins.shared.models import ActivityType, ChallengeType
from app.plugins.shared.challenge_service import challenge_service
from app.users.models import User
import logging

logger = logging.getLogger(__name__)


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
        # Convert schema enum to model enum using value
        level_value = course.level.value if hasattr(course.level, 'value') else course.level
        db_level = CourseLevel(level_value)

        db_course = Course(
            id=course.id,
            title=course.title,
            description=course.description,
            short_description=course.short_description,
            image=course.image,
            level=db_level,
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
            status=CourseStatus.draft,
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
    db_course.status = CourseStatus.archived
    db.commit()
    return True


def publish_course(db: Session, course_id: str) -> Optional[Course]:
    """Publish a course"""
    db_course = get_course(db, course_id)
    if not db_course:
        return None

    db_course.status = CourseStatus.published
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
    if course.status != CourseStatus.published:
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

    # Log enrollment activity
    achievement_service.log_activity(
        db=db,
        user_id=user_id,
        activity_type=ActivityType.COURSE_ENROLL,
        title=f"Enrolled in course: {course.title}",
        reference_type="course",
        reference_id=enrollment.course_id,
        activity_data={
            "level": course.level.value,
            "total_modules": len(course.modules) if course.modules else 0
        }
    )

    logger.info(f"User {user_id} enrolled in course {enrollment.course_id}")

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

                # Get module details for XP award
                module = get_module(db, module_id)
                module_title = module.title if module else module_id

                # Award XP for module completion
                xp_result = xp_service.award_xp(
                    db=db,
                    user_id=enrollment.user_id,
                    action="module_complete",
                    reason=f"Completed module: {module_title}"
                )

                logger.info(f"User {enrollment.user_id} completed module {module_id}, awarded {xp_result.get('xp_awarded', 0)} XP")

                # Log module completion activity
                achievement_service.log_activity(
                    db=db,
                    user_id=enrollment.user_id,
                    activity_type=ActivityType.MODULE_COMPLETE,
                    title=f"Completed module: {module_title}",
                    reference_type="module",
                    reference_id=module_id,
                    activity_data={
                        "course_id": enrollment.course_id,
                        "time_spent": progress.time_spent,
                        "sections_completed": len(progress.completed_sections)
                    },
                    xp_earned=xp_result.get("xp_awarded", 0)
                )

                # Check for level up
                if xp_result.get("level_up"):
                    logger.info(f"User {enrollment.user_id} leveled up to {xp_result.get('new_level')}!")
                    achievement_service.log_activity(
                        db=db,
                        user_id=enrollment.user_id,
                        activity_type=ActivityType.LEVEL_UP,
                        title=f"Reached level {xp_result.get('new_level')}!",
                        activity_data={
                            "old_level": xp_result.get("old_level"),
                            "new_level": xp_result.get("new_level"),
                            "trigger": "module_complete"
                        }
                    )

                # Check and unlock achievements for module completion
                achievement_service.check_and_unlock_achievements(
                    db=db,
                    user_id=enrollment.user_id,
                    action="module_complete",
                    context={
                        "module_id": module_id,
                        "course_id": enrollment.course_id
                    }
                )

                # Track challenge progress for module/course section completion
                challenge_service.increment_progress(
                    db=db,
                    user_id=enrollment.user_id,
                    challenge_type=ChallengeType.COURSE_SECTION,
                    amount=1
                )

                # Track XP earned for XP challenges
                if xp_result.get("xp_awarded", 0) > 0:
                    challenge_service.increment_progress(
                        db=db,
                        user_id=enrollment.user_id,
                        challenge_type=ChallengeType.XP_EARN,
                        amount=xp_result.get("xp_awarded", 0)
                    )

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

                    # Get course details for XP award
                    course = get_course(db, enrollment.course_id)
                    course_title = course.title if course else enrollment.course_id

                    # Increment course completion count
                    if course:
                        course.completion_count += 1

                    # Award XP for course completion
                    # Use course's custom xp_reward if set, otherwise use default
                    if course and course.xp_reward and course.xp_reward > 0:
                        base_xp = xp_service.config.REWARDS.get("course_complete", 250)
                        multiplier = course.xp_reward / base_xp if base_xp > 0 else 1.0
                        course_xp_result = xp_service.award_xp(
                            db=db,
                            user_id=enrollment.user_id,
                            action="course_complete",
                            multiplier=multiplier,
                            reason=f"Completed course: {course_title}"
                        )
                    else:
                        course_xp_result = xp_service.award_xp(
                            db=db,
                            user_id=enrollment.user_id,
                            action="course_complete",
                            reason=f"Completed course: {course_title}"
                        )

                    logger.info(f"User {enrollment.user_id} completed course {enrollment.course_id}, awarded {course_xp_result.get('xp_awarded', 0)} XP")

                    # Create certificate for course completion
                    try:
                        certificate = create_certificate(
                            db=db,
                            user_id=enrollment.user_id,
                            course_id=enrollment.course_id,
                            enrollment_id=enrollment.id
                        )
                        # Store certificate info on progress for return
                        progress.certificate_info = {
                            "id": certificate.id,
                            "title": certificate.title,
                            "description": certificate.description,
                            "verification_code": certificate.verification_code,
                            "skills_acquired": certificate.skills_acquired
                        }
                        logger.info(f"Certificate created: {certificate.verification_code}")
                    except Exception as cert_err:
                        logger.error(f"Failed to create certificate: {cert_err}")
                        # Don't fail the whole operation if certificate creation fails
                        progress.certificate_info = None

                    # Log course completion activity
                    achievement_service.log_activity(
                        db=db,
                        user_id=enrollment.user_id,
                        activity_type=ActivityType.COURSE_COMPLETE,
                        title=f"Completed course: {course_title}",
                        reference_type="course",
                        reference_id=enrollment.course_id,
                        activity_data={
                            "total_modules": total_modules,
                            "total_time_spent": enrollment.time_spent,
                            "level": course.level.value if course else None
                        },
                        xp_earned=course_xp_result.get("xp_awarded", 0)
                    )

                    # Check for level up from course completion
                    if course_xp_result.get("level_up"):
                        logger.info(f"User {enrollment.user_id} leveled up to {course_xp_result.get('new_level')}!")
                        achievement_service.log_activity(
                            db=db,
                            user_id=enrollment.user_id,
                            activity_type=ActivityType.LEVEL_UP,
                            title=f"Reached level {course_xp_result.get('new_level')}!",
                            activity_data={
                                "old_level": course_xp_result.get("old_level"),
                                "new_level": course_xp_result.get("new_level"),
                                "trigger": "course_complete"
                            }
                        )

                    # Update user's courses_completed count
                    user = db.query(User).filter(User.id == enrollment.user_id).first()
                    if user:
                        user.courses_completed = (user.courses_completed or 0) + 1

                    # Check and unlock achievements for course completion
                    unlocked = achievement_service.check_and_unlock_achievements(
                        db=db,
                        user_id=enrollment.user_id,
                        action="course_complete",
                        context={
                            "course_id": enrollment.course_id,
                            "level": course.level.value if course else None,
                            "total_modules": total_modules
                        }
                    )

                    if unlocked:
                        logger.info(f"User {enrollment.user_id} unlocked {len(unlocked)} achievement(s) from course completion")

                    # Track XP earned for XP challenges (course completion)
                    if course_xp_result.get("xp_awarded", 0) > 0:
                        challenge_service.increment_progress(
                            db=db,
                            user_id=enrollment.user_id,
                            challenge_type=ChallengeType.XP_EARN,
                            amount=course_xp_result.get("xp_awarded", 0)
                        )

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


# ==================== CERTIFICATE CRUD ====================

def generate_verification_code() -> str:
    """Generate a unique verification code for certificates"""
    # Format: CERT-XXXX-XXXX-XXXX (where X is alphanumeric)
    chars = string.ascii_uppercase + string.digits
    segments = [
        ''.join(secrets.choice(chars) for _ in range(4))
        for _ in range(3)
    ]
    return f"CERT-{'-'.join(segments)}"


def get_certificate_by_verification_code(
    db: Session,
    verification_code: str
) -> Optional[Certificate]:
    """Get certificate by verification code"""
    return db.query(Certificate)\
        .filter(Certificate.verification_code == verification_code)\
        .first()


def get_user_certificates(
    db: Session,
    user_id: int
) -> List[Certificate]:
    """Get all certificates for a user"""
    return db.query(Certificate)\
        .filter(Certificate.user_id == user_id)\
        .order_by(Certificate.issued_at.desc())\
        .all()


def get_user_course_certificate(
    db: Session,
    user_id: int,
    course_id: str
) -> Optional[Certificate]:
    """Get certificate for a specific course and user"""
    return db.query(Certificate)\
        .filter(
            Certificate.user_id == user_id,
            Certificate.course_id == course_id
        )\
        .first()


def create_certificate(
    db: Session,
    user_id: int,
    course_id: str,
    enrollment_id: int
) -> Certificate:
    """
    Create a certificate for course completion.
    Returns existing certificate if one already exists.
    """
    # Check for existing certificate
    existing = get_user_course_certificate(db, user_id, course_id)
    if existing:
        logger.info(f"Certificate already exists for user {user_id}, course {course_id}")
        return existing

    # Get course details
    course = get_course(db, course_id)
    if not course:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Course not found"
        )

    # Get user details
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Calculate total sections
    total_sections = sum(
        len(module.sections) if module.sections else 0
        for module in (course.modules or [])
    )

    # Generate unique verification code
    verification_code = generate_verification_code()
    # Ensure uniqueness
    while get_certificate_by_verification_code(db, verification_code):
        verification_code = generate_verification_code()

    # Build certificate description
    description = (
        f"This certifies that {user.username or user.email} has successfully completed "
        f"all {len(course.modules or [])} modules and {total_sections} sections of the "
        f"{course.title} course."
    )

    # Create certificate
    certificate = Certificate(
        user_id=user_id,
        course_id=course_id,
        enrollment_id=enrollment_id,
        title=f"Certificate of Completion: {course.title}",
        description=description,
        verification_code=verification_code,
        skills_acquired=course.skills or [],
        recipient_name=user.username or user.email,
        instructor_name=course.instructor_name,
        course_title=course.title,
        course_level=course.level.value if course.level else None,
        total_modules=len(course.modules or []),
        total_sections=total_sections
    )

    db.add(certificate)
    db.commit()
    db.refresh(certificate)

    logger.info(f"Created certificate {verification_code} for user {user_id}, course {course_id}")

    return certificate
