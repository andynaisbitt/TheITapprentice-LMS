// src/pages/admin/RolesAdmin.tsx
/**
 * User Roles & Permissions Management
 * Manage user roles and their permissions
 */

import { useState, useEffect } from 'react';
import {
  Shield,
  Plus,
  Edit2,
  Trash2,
  Users,
  Check,
  X,
  Loader2,
  Info,
} from 'lucide-react';

interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  user_count: number;
  is_system: boolean; // System roles can't be deleted
}

interface Permission {
  id: string;
  name: string;
  description: string;
  category: string;
}

const AVAILABLE_PERMISSIONS: Permission[] = [
  // Content
  { id: 'blog.create', name: 'Create Posts', description: 'Create blog posts', category: 'Content' },
  { id: 'blog.edit', name: 'Edit Posts', description: 'Edit own blog posts', category: 'Content' },
  { id: 'blog.edit_all', name: 'Edit All Posts', description: 'Edit any blog post', category: 'Content' },
  { id: 'blog.delete', name: 'Delete Posts', description: 'Delete blog posts', category: 'Content' },
  { id: 'blog.publish', name: 'Publish Posts', description: 'Publish/unpublish posts', category: 'Content' },
  { id: 'pages.manage', name: 'Manage Pages', description: 'Create, edit, delete pages', category: 'Content' },
  // Users
  { id: 'users.view', name: 'View Users', description: 'View user list', category: 'Users' },
  { id: 'users.edit', name: 'Edit Users', description: 'Edit user profiles', category: 'Users' },
  { id: 'users.delete', name: 'Delete Users', description: 'Delete user accounts', category: 'Users' },
  { id: 'users.roles', name: 'Manage Roles', description: 'Assign roles to users', category: 'Users' },
  // LMS
  { id: 'tutorials.manage', name: 'Manage Tutorials', description: 'CRUD tutorials', category: 'LMS' },
  { id: 'courses.manage', name: 'Manage Courses', description: 'CRUD courses', category: 'LMS' },
  { id: 'games.manage', name: 'Manage Games', description: 'Manage typing games', category: 'LMS' },
  // System
  { id: 'settings.view', name: 'View Settings', description: 'View site settings', category: 'System' },
  { id: 'settings.edit', name: 'Edit Settings', description: 'Modify site settings', category: 'System' },
  { id: 'plugins.manage', name: 'Manage Plugins', description: 'Enable/disable plugins', category: 'System' },
];

const DEFAULT_ROLES: Role[] = [
  {
    id: 'admin',
    name: 'Administrator',
    description: 'Full system access',
    permissions: AVAILABLE_PERMISSIONS.map(p => p.id),
    user_count: 1,
    is_system: true,
  },
  {
    id: 'editor',
    name: 'Editor',
    description: 'Can manage content but not users or settings',
    permissions: ['blog.create', 'blog.edit', 'blog.edit_all', 'blog.delete', 'blog.publish', 'pages.manage', 'tutorials.manage', 'courses.manage'],
    user_count: 3,
    is_system: true,
  },
  {
    id: 'author',
    name: 'Author',
    description: 'Can create and edit own content',
    permissions: ['blog.create', 'blog.edit'],
    user_count: 5,
    is_system: true,
  },
  {
    id: 'subscriber',
    name: 'Subscriber',
    description: 'Basic user with learning access',
    permissions: [],
    user_count: 150,
    is_system: true,
  },
];

export const RolesAdmin: React.FC = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    permissions: [] as string[],
  });

  useEffect(() => {
    loadRoles();
  }, []);

  const loadRoles = async () => {
    setLoading(true);
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/admin/roles');
      // const data = await response.json();
      // setRoles(data);

      // Use mock data for now
      setRoles(DEFAULT_ROLES);
    } catch (error) {
      console.error('Failed to load roles:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (role: Role) => {
    setEditingRole(role);
    setFormData({
      name: role.name,
      description: role.description,
      permissions: [...role.permissions],
    });
    setShowForm(true);
  };

  const handleDelete = async (roleId: string) => {
    const role = roles.find(r => r.id === roleId);
    if (role?.is_system) {
      alert('System roles cannot be deleted');
      return;
    }
    if (!confirm('Are you sure you want to delete this role?')) return;

    // TODO: Implement delete API call
    setRoles(roles.filter(r => r.id !== roleId));
  };

  const togglePermission = (permissionId: string) => {
    setFormData(prev => ({
      ...prev,
      permissions: prev.permissions.includes(permissionId)
        ? prev.permissions.filter(p => p !== permissionId)
        : [...prev.permissions, permissionId]
    }));
  };

  const handleSave = async () => {
    // TODO: Implement save API call
    if (editingRole) {
      setRoles(roles.map(r =>
        r.id === editingRole.id
          ? { ...r, name: formData.name, description: formData.description, permissions: formData.permissions }
          : r
      ));
    } else {
      const newRole: Role = {
        id: formData.name.toLowerCase().replace(/\s+/g, '_'),
        name: formData.name,
        description: formData.description,
        permissions: formData.permissions,
        user_count: 0,
        is_system: false,
      };
      setRoles([...roles, newRole]);
    }
    setShowForm(false);
    setEditingRole(null);
    setFormData({ name: '', description: '', permissions: [] });
  };

  const permissionsByCategory = AVAILABLE_PERMISSIONS.reduce((acc, perm) => {
    if (!acc[perm.category]) acc[perm.category] = [];
    acc[perm.category].push(perm);
    return acc;
  }, {} as Record<string, Permission[]>);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Roles & Permissions
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Manage user roles and their access permissions
          </p>
        </div>
        <button
          onClick={() => {
            setEditingRole(null);
            setFormData({ name: '', description: '', permissions: [] });
            setShowForm(true);
          }}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Role
        </button>
      </div>

      {/* Info Banner */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-blue-800 dark:text-blue-200">
              Roles define what actions users can perform. System roles (Administrator, Editor, Author, Subscriber) cannot be deleted but their permissions can be modified.
            </p>
          </div>
        </div>
      </div>

      {/* Roles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {roles.map((role) => (
          <div
            key={role.id}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 border border-gray-200 dark:border-gray-700"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${
                  role.id === 'admin'
                    ? 'bg-red-100 dark:bg-red-900/30'
                    : role.id === 'editor'
                    ? 'bg-blue-100 dark:bg-blue-900/30'
                    : role.id === 'author'
                    ? 'bg-green-100 dark:bg-green-900/30'
                    : 'bg-gray-100 dark:bg-gray-700'
                }`}>
                  <Shield className={`w-5 h-5 ${
                    role.id === 'admin'
                      ? 'text-red-600 dark:text-red-400'
                      : role.id === 'editor'
                      ? 'text-blue-600 dark:text-blue-400'
                      : role.id === 'author'
                      ? 'text-green-600 dark:text-green-400'
                      : 'text-gray-600 dark:text-gray-400'
                  }`} />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    {role.name}
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    {role.description}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleEdit(role)}
                  className="p-2 text-gray-400 hover:text-primary transition-colors"
                >
                  <Edit2 className="w-4 h-4" />
                </button>
                {!role.is_system && (
                  <button
                    onClick={() => handleDelete(role.id)}
                    className="p-2 text-gray-400 hover:text-red-500 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            <div className="mt-4 flex items-center gap-4 text-sm">
              <span className="flex items-center gap-1 text-gray-500 dark:text-gray-400">
                <Users className="w-4 h-4" />
                {role.user_count} users
              </span>
              <span className="text-gray-500 dark:text-gray-400">
                {role.permissions.length} permissions
              </span>
            </div>

            {/* Permission Tags */}
            {role.permissions.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1">
                {role.permissions.slice(0, 5).map((permId) => {
                  const perm = AVAILABLE_PERMISSIONS.find(p => p.id === permId);
                  return (
                    <span
                      key={permId}
                      className="px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300"
                    >
                      {perm?.name || permId}
                    </span>
                  );
                })}
                {role.permissions.length > 5 && (
                  <span className="px-2 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500">
                    +{role.permissions.length - 5} more
                  </span>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Edit/Create Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {editingRole ? 'Edit Role' : 'Create New Role'}
              </h2>
            </div>

            <div className="p-6 overflow-y-auto flex-1">
              {/* Role Info */}
              <div className="space-y-4 mb-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Role Name
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    disabled={editingRole?.is_system}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white disabled:opacity-50"
                    placeholder="e.g., Moderator"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description
                  </label>
                  <input
                    type="text"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    placeholder="Brief description of this role"
                  />
                </div>
              </div>

              {/* Permissions */}
              <div>
                <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                  Permissions
                </h3>
                <div className="space-y-4">
                  {Object.entries(permissionsByCategory).map(([category, perms]) => (
                    <div key={category}>
                      <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">
                        {category}
                      </h4>
                      <div className="space-y-2">
                        {perms.map((perm) => (
                          <label
                            key={perm.id}
                            className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                          >
                            <button
                              type="button"
                              onClick={() => togglePermission(perm.id)}
                              className={`w-5 h-5 rounded flex items-center justify-center transition-colors ${
                                formData.permissions.includes(perm.id)
                                  ? 'bg-primary text-white'
                                  : 'border-2 border-gray-300 dark:border-gray-600'
                              }`}
                            >
                              {formData.permissions.includes(perm.id) && (
                                <Check className="w-3 h-3" />
                              )}
                            </button>
                            <div>
                              <p className="text-sm font-medium text-gray-900 dark:text-white">
                                {perm.name}
                              </p>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                {perm.description}
                              </p>
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowForm(false);
                  setEditingRole(null);
                }}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!formData.name}
                className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors disabled:opacity-50"
              >
                {editingRole ? 'Save Changes' : 'Create Role'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RolesAdmin;
